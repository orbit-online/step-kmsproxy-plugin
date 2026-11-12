package gate

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// A prompt the fake Ask received
type asked struct {
	ctx     context.Context
	caller  string
	domains []string
	reply   chan Answer
}

type harness struct {
	t       *testing.T
	gate    *Gate
	path    string
	prompts chan *asked
	ln      net.Listener
	mu      sync.Mutex
	callers map[string]string // remote address -> caller ID
	clock   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, path: filepath.Join(t.TempDir(), "allowed.json"), prompts: make(chan *asked, 16),
		callers: map[string]string{}, clock: time.Unix(1_000_000, 0)}
	h.gate = h.reopen()
	var err error
	if h.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.ln.Close() })
	return h
}

func (h *harness) reopen() *Gate {
	g, err := New(h.path, func(local, remote string) (Caller, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		id, ok := h.callers[remote]
		if !ok {
			return Caller{}, errors.New("unknown")
		}
		return Caller{ID: id, Description: id}, nil
	}, func(ctx context.Context, caller Caller, domains []string) (Answer, error) {
		a := &asked{ctx: ctx, caller: caller.ID, domains: domains, reply: make(chan Answer, 1)}
		h.prompts <- a
		select {
		case answer := <-a.reply:
			return answer, nil
		case <-ctx.Done():
			return Dismissed, nil
		}
	})
	if err != nil {
		h.t.Fatal(err)
	}
	g.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	return g
}

func (h *harness) advance(d time.Duration) { h.mu.Lock(); h.clock = h.clock.Add(d); h.mu.Unlock() }

// A pending Check: done delivers its result, hangUp closes the client side
type request struct {
	done   chan bool
	client net.Conn
}

func (h *harness) check(caller, domain string) *request {
	h.t.Helper()
	client, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	server, err := h.ln.Accept()
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { client.Close(); server.Close() })
	h.mu.Lock()
	h.callers[server.RemoteAddr().String()] = caller
	h.mu.Unlock()
	r := &request{done: make(chan bool, 1), client: client}
	before := h.waiting(caller)
	go func() { r.done <- h.gate.Check(context.Background(), NewPeekConn(server, nil), domain) }()
	// Return once the gate settled the request or has it waiting, as the model's arrive does
	for deadline := time.Now().Add(5 * time.Second); len(r.done) == 0 && h.waiting(caller) == before; {
		if time.Now().After(deadline) {
			h.t.Fatalf("%s for %s neither settled nor waits", caller, domain)
		}
		time.Sleep(time.Millisecond)
	}
	return r
}

// waiting counts the requests of caller waiting in the gate
func (h *harness) waiting(caller string) int {
	h.gate.mu.Lock()
	defer h.gate.mu.Unlock()
	if cs := h.gate.callers[caller]; cs != nil {
		return len(cs.waiting)
	}
	return 0
}

func (h *harness) prompt() *asked {
	h.t.Helper()
	select {
	case a := <-h.prompts:
		return a
	case <-time.After(5 * time.Second):
		h.t.Fatal("no prompt")
		return nil
	}
}

func (h *harness) noPrompt() {
	h.t.Helper()
	select {
	case a := <-h.prompts:
		h.t.Fatalf("unexpected prompt for %s %v", a.caller, a.domains)
	case <-time.After(100 * time.Millisecond):
	}
}

func (r *request) result(t *testing.T) bool {
	t.Helper()
	select {
	case ok := <-r.done:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
		return false
	}
}

func (r *request) pending(t *testing.T) {
	t.Helper()
	select {
	case ok := <-r.done:
		t.Fatalf("settled early with %v", ok)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAlwaysAllowPersists(t *testing.T) {
	h := newHarness(t)
	r := h.check("curl", "a.example")
	p := h.prompt()
	if p.caller != "curl" || !slices.Equal(p.domains, []string{"a.example"}) {
		t.Fatalf("prompt for %s %v", p.caller, p.domains)
	}
	p.reply <- AllowAlways
	if !r.result(t) {
		t.Fatal("refused after Always allow")
	}
	if !h.check("curl", "A.Example.").result(t) {
		t.Fatal("rule didn't decide the same domain")
	}
	h.noPrompt()
	h.gate = h.reopen()
	if !h.check("curl", "a.example").result(t) {
		t.Fatal("rule didn't survive a restart")
	}
	h.noPrompt()
	// Another caller, or another domain, is asked about
	h.check("wget", "a.example")
	if p := h.prompt(); p.caller != "wget" {
		t.Fatalf("prompt for %s", p.caller)
	}
}

func TestQueuedDomainsGroupIntoTheNextPrompt(t *testing.T) {
	h := newHarness(t)
	a := h.check("curl", "a.example")
	first := h.prompt()
	b := h.check("curl", "b.example")
	c := h.check("curl", "c.example")
	a2 := h.check("curl", "a.example")
	h.noPrompt()
	first.reply <- AllowTemp
	if !a.result(t) || !a2.result(t) {
		t.Fatal("the shown domain wasn't allowed for every waiting request")
	}
	b.pending(t)
	c.pending(t)
	second := h.prompt()
	if !slices.Equal(second.domains, []string{"b.example", "c.example"}) {
		t.Fatalf("second prompt shows %v", second.domains)
	}
	second.reply <- Deny
	if b.result(t) || c.result(t) {
		t.Fatal("allowed after Deny")
	}
}

func TestTemporaryRulesExpire(t *testing.T) {
	h := newHarness(t)
	r := h.check("curl", "a.example")
	h.prompt().reply <- Deny
	if r.result(t) {
		t.Fatal("allowed after Deny")
	}
	if h.check("curl", "a.example").result(t) {
		t.Fatal("Deny not remembered")
	}
	h.noPrompt()
	h.advance(TempDuration)
	r = h.check("curl", "a.example")
	h.prompt().reply <- AllowTemp
	if !r.result(t) {
		t.Fatal("refused after Allow for 1 hour")
	}
	h.advance(TempDuration)
	h.check("curl", "a.example")
	h.prompt()
}

func TestCallersAreAskedSeparately(t *testing.T) {
	h := newHarness(t)
	curl := h.check("curl", "a.example")
	wget := h.check("wget", "a.example")
	prompts := map[string]*asked{}
	for range 2 {
		p := h.prompt()
		prompts[p.caller] = p
	}
	prompts["wget"].reply <- Deny
	if wget.result(t) {
		t.Fatal("wget allowed after Deny")
	}
	curl.pending(t)
	prompts["curl"].reply <- AllowTemp
	if !curl.result(t) {
		t.Fatal("curl refused after Allow")
	}
}

func TestHangUpWithdrawsThePrompt(t *testing.T) {
	h := newHarness(t)
	r := h.check("curl", "a.example")
	p := h.prompt()
	r.client.Close()
	if r.result(t) {
		t.Fatal("allowed after hanging up")
	}
	select {
	case <-p.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("prompt not withdrawn")
	}
}

func TestHangUpKeepsAPromptOthersWaitOn(t *testing.T) {
	h := newHarness(t)
	r1 := h.check("curl", "a.example")
	p := h.prompt()
	r2 := h.check("curl", "a.example")
	r1.client.Close()
	r1.result(t)
	if p.ctx.Err() != nil {
		t.Fatal("withdrawn while a request still waits on it")
	}
	p.reply <- AllowTemp
	if !r2.result(t) {
		t.Fatal("refused after Allow")
	}
}

// The user answers a withdrawn prompt: the rule applies to a request waiting on the next one
func TestLateAnswerAppliesItsRule(t *testing.T) {
	h := newHarness(t)
	g, err := New(h.path, h.gate.identify, func(ctx context.Context, caller Caller, domains []string) (Answer, error) {
		a := &asked{ctx: ctx, caller: caller.ID, domains: domains, reply: make(chan Answer, 1)}
		h.prompts <- a
		return <-a.reply, nil // ignores ctx, as a click in flight would
	})
	if err != nil {
		t.Fatal(err)
	}
	h.gate = g
	r1 := h.check("curl", "a.example")
	stale := h.prompt()
	r1.client.Close()
	r1.result(t)
	r2 := h.check("curl", "a.example")
	fresh := h.prompt()
	stale.reply <- AllowTemp
	if !r2.result(t) {
		t.Fatal("the late Allow didn't apply")
	}
	fresh.reply <- Dismissed
	h.noPrompt()
}

func TestUnidentifiedCallerIsRefused(t *testing.T) {
	h := newHarness(t)
	client, _ := net.Dial("tcp", h.ln.Addr().String())
	defer client.Close()
	server, _ := h.ln.Accept()
	defer server.Close()
	if h.gate.Check(context.Background(), NewPeekConn(server, nil), "a.example") {
		t.Fatal("allowed an unidentified caller")
	}
	h.noPrompt()
}

func TestPeekKeepsBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	c := NewPeekConn(server, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() { done <- c.WaitClosed(ctx) }()
	client.Write([]byte("early"))
	cancel()
	if <-done {
		t.Fatal("counted as closed")
	}
	go client.Write([]byte(" late"))
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	if string(buf[:n]) != "early" {
		t.Fatalf("read %q first", buf[:n])
	}
	n, _ = c.Read(buf)
	if string(buf[:n]) != " late" {
		t.Fatalf("read %q second", buf[:n])
	}
}

func TestPeekNoticesHangUp(t *testing.T) {
	client, server := net.Pipe()
	c := NewPeekConn(server, nil)
	done := make(chan bool)
	go func() { done <- c.WaitClosed(context.Background()) }()
	client.Close()
	select {
	case closed := <-done:
		if !closed {
			t.Fatal("hang-up not noticed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitClosed didn't return")
	}
}
