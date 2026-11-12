// Package gate asks the user before a local caller may use the proxy's client certificates for a domain. The design
// is modeled in models/gate.als; comments name the assertion a piece of code enforces
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Caller is who opened a connection, as far as the OS can tell
type Caller struct {
	// What rules are keyed on: the same for every connection from the same principal, different across principals
	ID string
	// What the user is shown
	Description string
}

type Answer int

const (
	// Closed unanswered, withdrawn or failed: refused, no rule
	Dismissed Answer = iota
	Deny
	AllowTemp
	AllowAlways
)

const (
	// How long "Allow for 1 hour" and "Deny" last
	TempDuration = time.Hour
	// How long a request waits for an answer
	MaxWait = 2 * time.Minute
)

// Identify finds the caller of a connection from its local and remote address
type Identify func(local, remote string) (Caller, error)

// Ask asks the user whether caller may use the client certificates for domains. It returns Dismissed when ctx ends
type Ask func(ctx context.Context, caller Caller, domains []string) (Answer, error)

type rule struct {
	Caller string `json:"caller"`
	Domain string `json:"domain"`
}

type Gate struct {
	path     string
	identify Identify
	ask      Ask
	now      func() time.Time

	mu      sync.Mutex
	always  map[rule]bool
	allowed map[rule]time.Time
	denied  map[rule]time.Time
	callers map[string]*callerState
}

type callerState struct {
	caller  Caller
	waiting map[*waiter]bool
	// The open prompt, nil when there is none
	open *prompt
}

type waiter struct {
	domain string
	result chan bool
}

type prompt struct {
	shown  map[string]bool
	cancel context.CancelFunc
}

// New loads the "Always allow" rules from path, which needn't exist yet
func New(path string, identify Identify, ask Ask) (*Gate, error) {
	g := &Gate{
		path: path, identify: identify, ask: ask, now: time.Now,
		always: map[rule]bool{}, allowed: map[rule]time.Time{}, denied: map[rule]time.Time{},
		callers: map[string]*callerState{},
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return g, nil
	} else if err != nil {
		return nil, fmt.Errorf("Read the allowed callers: %w", err)
	}
	var rules []rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("Parse the allowed callers in %s: %w", path, err)
	}
	for _, r := range rules {
		g.always[r] = true
	}
	return g, nil
}

// Check says whether the caller of conn may reach domain, asking the user when no rule decides. It returns early with
// false when the client hangs up or MaxWait passes
func (g *Gate) Check(ctx context.Context, conn *PeekConn, domain string) bool {
	caller, err := g.identify(conn.LocalAddr().String(), conn.RemoteAddr().String())
	if err != nil {
		slog.Warn("Refused an unidentified caller", "client", conn.RemoteAddr(), "domain", domain, "error", err)
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	log := slog.With("caller", caller.ID, "domain", domain)
	r := rule{caller.ID, domain}

	g.mu.Lock()
	// arrive: a rule decides at once
	if allowed, decided := g.decide(r); decided {
		g.mu.Unlock()
		if !allowed {
			log.Info("Refused by a Deny answer")
		}
		return allowed
	}
	cs := g.callers[caller.ID]
	if cs == nil {
		cs = &callerState{caller: caller, waiting: map[*waiter]bool{}}
		g.callers[caller.ID] = cs
	}
	w := &waiter{domain: domain, result: make(chan bool, 1)}
	cs.waiting[w] = true
	// onePromptPerCaller: a domain the open prompt doesn't show waits for the next one
	if cs.open == nil {
		g.show(cs)
	}
	g.mu.Unlock()

	waitCtx, cancel := context.WithTimeout(ctx, MaxWait)
	defer cancel()
	peekCtx, stopPeek := context.WithCancel(waitCtx)
	defer stopPeek()
	peeked := make(chan struct{})
	go func() {
		defer close(peeked)
		if conn.WaitClosed(peekCtx) {
			log.Info("Client hung up waiting for an answer")
		}
	}()
	select {
	case allowed := <-w.result:
		stopPeek()
		<-peeked
		return allowed
	case <-peeked:
		g.leave(cs, w)
		select {
		case allowed := <-w.result:
			return allowed && ctx.Err() == nil
		default:
			return false
		}
	}
}

// decide applies a live rule to r. Allow rules come first, as an answer replaces the opposite rule
func (g *Gate) decide(r rule) (allowed, decided bool) {
	now := g.now()
	if g.always[r] || now.Before(g.allowed[r]) {
		return true, true
	}
	if now.Before(g.denied[r]) {
		return false, true
	}
	return false, false
}

// show opens a prompt for every domain cs waits on (show). Called with g.mu held
func (g *Gate) show(cs *callerState) {
	shown := map[string]bool{}
	for w := range cs.waiting {
		shown[w.domain] = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &prompt{shown: shown, cancel: cancel}
	cs.open = p
	domains := slices.Sorted(maps.Keys(shown))
	slog.Info("Asking the user", "caller", cs.caller.ID, "domains", domains)
	go func() {
		defer cancel()
		answer, err := g.ask(ctx, cs.caller, domains)
		if err != nil {
			slog.Error("Asking the user failed", "caller", cs.caller.ID, "error", err)
			answer = Dismissed
		}
		g.answer(cs, p, answer)
	}()
}

// answer records the user's answer for the domains p showed (allow, deny, dismiss) and, while p is still the open
// prompt, settles the requests waiting on them. An answer to a withdrawn prompt only adds rules: the user saw it
func (g *Gate) answer(cs *callerState, p *prompt, answer Answer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	persist := false
	// consentShown: rules only for the domains the prompt showed
	for domain := range p.shown {
		r := rule{cs.caller.ID, domain}
		switch answer {
		case AllowAlways:
			g.always[r], persist = true, true
			delete(g.denied, r)
		case AllowTemp:
			g.allowed[r] = now.Add(TempDuration)
			delete(g.denied, r)
		case Deny:
			persist = persist || g.always[r]
			delete(g.always, r)
			delete(g.allowed, r)
			g.denied[r] = now.Add(TempDuration)
		}
	}
	slog.Info("The user answered", "caller", cs.caller.ID, "domains", slices.Sorted(maps.Keys(p.shown)),
		"answer", answer)
	if persist {
		if err := g.save(); err != nil {
			slog.Error("Saving the allowed callers failed", "error", err)
		}
	}
	if cs.open == p {
		// forwardedWithConsent: settle only the waiters for shown domains; the rest wait for the next prompt
		allowed := answer == AllowTemp || answer == AllowAlways
		for w := range cs.waiting {
			if p.shown[w.domain] {
				w.result <- allowed
				delete(cs.waiting, w)
			}
		}
		cs.open = nil
	}
	g.settle(cs)
	if live := g.callers[cs.caller.ID]; live != nil && live != cs {
		g.settle(live)
	}
}

// leave drops a waiter whose client hung up or timed out (leave)
func (g *Gate) leave(cs *callerState, w *waiter) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cs.waiting[w] {
		delete(cs.waiting, w)
		g.settle(cs)
	}
}

// settle lets rules decide what they can, takes the open prompt down once nobody waits on what it shows (withdraw),
// and shows a prompt for what's left (show). Called with g.mu held
func (g *Gate) settle(cs *callerState) {
	for w := range cs.waiting {
		if allowed, decided := g.decide(rule{cs.caller.ID, w.domain}); decided {
			w.result <- allowed
			delete(cs.waiting, w)
		}
	}
	if cs.open != nil && !slices.ContainsFunc(slices.Collect(maps.Keys(cs.waiting)),
		func(w *waiter) bool { return cs.open.shown[w.domain] }) {
		cs.open.cancel()
		cs.open = nil
	}
	if cs.open != nil {
		return
	}
	if len(cs.waiting) > 0 {
		g.show(cs)
	} else if g.callers[cs.caller.ID] == cs {
		delete(g.callers, cs.caller.ID)
	}
}

// save writes the "Always allow" rules. Called with g.mu held
func (g *Gate) save() error {
	rules := slices.SortedFunc(maps.Keys(g.always), func(a, b rule) int {
		return strings.Compare(a.Caller+"\x00"+a.Domain, b.Caller+"\x00"+b.Domain)
	})
	raw, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(g.path), ".allowed-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), g.path)
}

func (a Answer) String() string {
	return [...]string{"dismissed", "deny", "allow for 1 hour", "always allow"}[a]
}
