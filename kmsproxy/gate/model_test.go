package gate

import (
	"context"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestModel runs the actions of models/gate.als against the gate (arrive, leave, allow, deny, dismiss, expire; show
// and withdraw follow from them) and checks its assertions after every step
func TestModel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dir := t.TempDir()
	runs := 0
	rapid.Check(t, func(rt *rapid.T) {
		runs++
		m := newModelRun(rt, ln, filepath.Join(dir, fmt.Sprintf("allowed-%d.json", runs)))
		defer m.close()
		rt.Repeat(map[string]func(*rapid.T){
			"arrive": func(rt *rapid.T) {
				m.arrive(rapid.SampledFrom([]string{"a", "b"}).Draw(rt, "caller"),
					rapid.SampledFrom([]string{"x", "y", "z"}).Draw(rt, "domain"))
			},
			"leave": func(rt *rapid.T) {
				pending := m.pendingRequests()
				if len(pending) == 0 {
					rt.Skip("nothing waits")
				}
				m.leave(rapid.SampledFrom(pending).Draw(rt, "request"))
			},
			"answer": func(rt *rapid.T) {
				callers := m.prompted()
				if len(callers) == 0 {
					rt.Skip("no prompt")
				}
				m.answer(rapid.SampledFrom(callers).Draw(rt, "caller"),
					rapid.SampledFrom([]Answer{Dismissed, Deny, AllowTemp, AllowAlways}).Draw(rt, "answer"))
			},
			"expire": func(rt *rapid.T) { m.advance(TempDuration) },
			"":       func(rt *rapid.T) { m.check() },
		})
	})
}

type modelRequest struct {
	caller, domain string
	client, server net.Conn
	result         chan bool
	settled        *bool
}

type modelRun struct {
	t       *rapid.T
	ln      net.Listener
	gate    *Gate
	mu      sync.Mutex
	clock   time.Time
	callers map[string]string // remote address -> caller
	// Prompts asked and not answered or withdrawn, by caller; more than one is a failure
	open     map[string][]*asked
	requests []*modelRequest
	// The model's ghosts: what the user allowed (consent), per caller and domain
	consent map[[2]string]bool
}

func newModelRun(t *rapid.T, ln net.Listener, path string) *modelRun {
	m := &modelRun{t: t, ln: ln, clock: time.Unix(1_000_000, 0), callers: map[string]string{},
		open: map[string][]*asked{}, consent: map[[2]string]bool{}}
	g, err := New(path, func(local, remote string) (Caller, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return Caller{ID: m.callers[remote]}, nil
	}, func(ctx context.Context, caller Caller, domains []string) (Answer, error) {
		a := &asked{ctx: ctx, caller: caller.ID, domains: domains, reply: make(chan Answer, 1)}
		m.mu.Lock()
		m.open[caller.ID] = append(m.open[caller.ID], a)
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			m.open[caller.ID] = slices.DeleteFunc(m.open[caller.ID], func(o *asked) bool { return o == a })
			m.mu.Unlock()
		}()
		select {
		case answer := <-a.reply:
			return answer, nil
		case <-ctx.Done():
			return Dismissed, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { m.mu.Lock(); defer m.mu.Unlock(); return m.clock }
	m.gate = g
	return m
}

func (m *modelRun) close() {
	for _, r := range m.requests {
		r.client.Close()
		r.server.Close()
	}
}

func (m *modelRun) arrive(caller, domain string) {
	client, err := net.Dial("tcp", m.ln.Addr().String())
	if err != nil {
		m.t.Fatal(err)
	}
	server, err := m.ln.Accept()
	if err != nil {
		m.t.Fatal(err)
	}
	m.mu.Lock()
	m.callers[server.RemoteAddr().String()] = caller
	m.mu.Unlock()
	settled := false
	r := &modelRequest{caller: caller, domain: domain, client: client, server: server, result: make(chan bool, 1),
		settled: &settled}
	m.requests = append(m.requests, r)
	before := m.waiters(caller, domain)
	go func() { r.result <- m.gate.Check(context.Background(), NewPeekConn(server, nil), domain) }()
	// arrive is one step in the model: wait until a rule settled it or it waits in the gate
	for deadline := time.Now().Add(5 * time.Second); len(r.result) == 0 && m.waiters(caller, domain) == before; {
		if time.Now().After(deadline) {
			m.t.Fatalf("%s for %s neither settled nor waits", caller, domain)
		}
		time.Sleep(time.Millisecond)
	}
	m.quiesce()
}

// waiters counts the requests of caller for domain waiting in the gate
func (m *modelRun) waiters(caller, domain string) int {
	m.gate.mu.Lock()
	defer m.gate.mu.Unlock()
	n := 0
	if cs := m.gate.callers[caller]; cs != nil {
		for w := range cs.waiting {
			if w.domain == domain {
				n++
			}
		}
	}
	return n
}

func (m *modelRun) leave(i int) {
	r := m.requests[i]
	r.client.Close()
	m.await(r)
	m.quiesce()
}

func (m *modelRun) answer(caller string, answer Answer) {
	m.mu.Lock()
	a := m.live(caller)[0]
	m.open[caller] = slices.DeleteFunc(m.open[caller], func(o *asked) bool { return o == a })
	m.mu.Unlock()
	if answer == AllowTemp || answer == AllowAlways {
		for _, d := range a.domains {
			m.consent[[2]string{caller, d}] = true
		}
	}
	a.reply <- answer
	// The requests it answers settle, and a prompt for what else the caller waits on follows
	for _, r := range m.requests {
		if !*r.settled && r.caller == caller && slices.Contains(a.domains, r.domain) {
			m.await(r)
		}
	}
	m.quiesce()
}

func (m *modelRun) advance(d time.Duration) {
	m.mu.Lock()
	m.clock = m.clock.Add(d)
	m.mu.Unlock()
}

// pendingRequests are the indexes of requests still waiting
func (m *modelRun) pendingRequests() []int {
	var pending []int
	for i, r := range m.requests {
		if !*r.settled {
			pending = append(pending, i)
		}
	}
	return pending
}

func (m *modelRun) prompted() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var callers []string
	for c := range m.open {
		if len(m.live(c)) > 0 {
			callers = append(callers, c)
		}
	}
	slices.Sort(callers)
	return callers
}

func (m *modelRun) await(r *modelRequest) {
	select {
	case ok := <-r.result:
		*r.settled = true
		// forwardedWithConsent
		if ok && !m.consent[[2]string{r.caller, r.domain}] {
			m.t.Fatalf("%s reached %s without the user allowing it", r.caller, r.domain)
		}
	case <-time.After(5 * time.Second):
		m.t.Fatalf("%s for %s didn't settle; gate: %s", r.caller, r.domain, m.dump())
	}
}

// quiesce collects what settled and waits until every caller with waiting requests has a prompt, which shows every
// domain it waits on unless the domain arrived after it opened
func (m *modelRun) quiesce() {
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, r := range m.requests {
			if !*r.settled && len(r.result) > 0 {
				m.await(r)
			}
		}
		waiting := map[string]bool{}
		for _, r := range m.requests {
			if !*r.settled {
				waiting[r.caller] = true
			}
		}
		m.mu.Lock()
		ready := true
		for c := range waiting {
			if len(m.live(c)) == 0 {
				ready = false
			}
		}
		for c := range m.open {
			if len(m.live(c)) > 0 && !waiting[c] {
				ready = false // a prompt nobody waits on yet to be withdrawn
			}
		}
		m.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			m.t.Fatalf("no prompt for the waiting callers %v", waiting)
		}
		time.Sleep(time.Millisecond)
	}
}

func (m *modelRun) check() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// onePromptPerCaller
	for c := range m.open {
		if open := m.live(c); len(open) > 1 {
			m.t.Fatalf("%d prompts open for %s", len(open), c)
		}
	}
}

// live are the prompts open for caller: a withdrawn one is closed before its Ask returns. Called with m.mu held
func (m *modelRun) live(caller string) []*asked {
	return slices.DeleteFunc(slices.Clone(m.open[caller]), func(a *asked) bool { return a.ctx.Err() != nil })
}

func (m *modelRun) dump() string {
	m.gate.mu.Lock()
	defer m.gate.mu.Unlock()
	out := ""
	for id, cs := range m.gate.callers {
		var ws []string
		for w := range cs.waiting {
			ws = append(ws, w.domain)
		}
		open := "none"
		if cs.open != nil {
			open = fmt.Sprint(slices.Sorted(maps.Keys(cs.open.shown)))
		}
		out += fmt.Sprintf("[%s waiting=%v open=%s] ", id, ws, open)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for c, open := range m.open {
		for _, a := range open {
			out += fmt.Sprintf("{ask %s %v done=%v} ", c, a.domains, a.ctx.Err() != nil)
		}
	}
	return out
}
