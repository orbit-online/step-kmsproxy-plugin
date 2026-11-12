package gate

// The fake server follows orbit-online/agent-sandbox cmd/permissions-broker/internal/notify/notify_test.go

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeNotifications is a notification server on a bus of its own. Like Plasma's, it replaces a notification by its id
// whoever asks, and emits ActionInvoked for the key of the button clicked. Its name in GetServerInformation is name
type fakeNotifications struct {
	conn   *dbus.Conn
	name   string
	mu     sync.Mutex
	last   uint32
	shown  map[uint32][]string // id: the actions, key then label
	bodies map[uint32]string
	sums   map[uint32]string
	closed map[uint32]bool
	posted chan uint32
}

func (f *fakeNotifications) GetServerInformation() (string, string, string, string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.name, "test", "1", "1.3", nil
}

func (f *fakeNotifications) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, expire int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := replaces
	if id == 0 {
		f.last++
		id = f.last
	}
	f.shown[id], f.bodies[id], f.sums[id] = actions, body, summary
	select {
	case f.posted <- id:
	default:
	}
	return id, nil
}

func (f *fakeNotifications) CloseNotification(id uint32) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed[id] = true
	return nil
}

// click clicks the button labelled label on notification id
func (f *fakeNotifications) click(t *testing.T, id uint32, label string) {
	t.Helper()
	if err := f.conn.Emit(notifyPath, notifyIface+".ActionInvoked", id, f.key(id, label)); err != nil {
		t.Fatal(err)
	}
}

// key is the action key of the button labelled label on notification id
func (f *fakeNotifications) key(id uint32, label string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	actions := f.shown[id]
	for i := 0; i+1 < len(actions); i += 2 {
		if actions[i+1] == label {
			return actions[i]
		}
	}
	return ""
}

// testBus starts a dbus-daemon of its own with a fake notification server on it, and returns its address
func testBus(t *testing.T) (string, *fakeNotifications) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(`<busconfig><type>session</type><listen>unix:path=`+dir+`/bus</listen>
<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>`),
		0o600); err != nil {
		t.Fatal(err)
	}
	// --print-address writes the address only once the bus listens
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	daemon := exec.Command("dbus-daemon", "--nofork", "--config-file="+conf, "--print-address=3")
	daemon.ExtraFiles = []*os.File{w}
	err = daemon.Start()
	w.Close()
	if err != nil {
		t.Skip("No dbus-daemon:", err)
	}
	t.Cleanup(func() { daemon.Process.Kill(); daemon.Wait() })
	r.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := bufio.NewReader(r).ReadString('\n'); err != nil {
		t.Fatalf("dbus-daemon's address: %v", err)
	}
	addr := "unix:path=" + dir + "/bus"
	f := &fakeNotifications{conn: busConn(t, addr), name: "fake", shown: map[uint32][]string{},
		bodies: map[uint32]string{}, sums: map[uint32]string{}, closed: map[uint32]bool{}, posted: make(chan uint32, 8)}
	if err := f.conn.Export(f, notifyPath, notifyIface); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.conn.RequestName(notifyName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return addr, f
}

func busConn(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

var testCaller = Caller{ID: "linux uid=1000 cgroup=/app ns=host", Description: "curl in app"}

type asking struct {
	id      uint32
	answer  chan Answer
	dialogs chan string
	cancel  context.CancelFunc
}

// ask asks on a connection of its own to the test bus
func ask(t *testing.T, addr string, f *fakeNotifications, domains ...string) *asking {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	a := &asking{answer: make(chan Answer, 1), dialogs: make(chan string, 1), cancel: cancel}
	go func() {
		answer, err := askOn(ctx, busConn(t, addr), testCaller, domains, func(ctx context.Context, summary, body string, labels []string) (Answer, error) {
			a.dialogs <- body
			return AllowTemp, nil
		})
		if err != nil {
			t.Error(err)
		}
		a.answer <- answer
	}()
	select {
	case a.id = <-f.posted:
	case <-time.After(5 * time.Second):
		t.Fatal("No notification posted")
	}
	return a
}

func (a *asking) result(t *testing.T) Answer {
	t.Helper()
	select {
	case answer := <-a.answer:
		return answer
	case <-time.After(5 * time.Second):
		t.Fatal("No answer")
		return Dismissed
	}
}

func immature(t *testing.T) {
	notifyMature = 0
	t.Cleanup(func() { notifyMature = time.Second })
}

func TestNotificationButtons(t *testing.T) {
	immature(t)
	addr, f := testBus(t)
	for label, want := range map[string]Answer{labelAlways: AllowAlways, labelTemp: AllowTemp, labelDeny: Deny} {
		a := ask(t, addr, f, "a.example")
		f.click(t, a.id, label)
		if got := a.result(t); got != want {
			t.Errorf("%s answered %s", label, got)
		}
	}
}

// A caller on the session bus replaces the notification by its id with a button whose key is "allow", or sends
// ActionInvoked with the real key itself. Neither allows
func TestNotificationNoAlwaysForHidden(t *testing.T) {
	addr, f := testBus(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go askOn(ctx, busConn(t, addr), Caller{ID: "linux uid=1000 cgroup=/app exe=unknown ns=unknown"}, []string{"a.example"}, nil)
	id := <-f.posted
	if f.key(id, labelAlways) != "" || f.key(id, labelTemp) == "" || f.key(id, labelDeny) == "" {
		f.mu.Lock()
		defer f.mu.Unlock()
		t.Errorf("buttons %q", f.shown[id])
	}
}

func TestNotificationForged(t *testing.T) {
	immature(t)
	addr, f := testBus(t)
	caller := busConn(t, addr)

	a := ask(t, addr, f, "a.example")
	if err := caller.Object(notifyName, notifyPath).Call(notifyIface+".Notify", 0, "kmsproxy", a.id, "security-medium",
		"Allow?", "", []string{"allow", labelAlways}, map[string]dbus.Variant{}, int32(0)).Err; err != nil {
		t.Fatal(err)
	}
	<-f.posted
	f.click(t, a.id, labelAlways)
	if got := a.result(t); got != Dismissed {
		t.Errorf("A click on the replacement answered %s", got)
	}

	a = ask(t, addr, f, "a.example")
	if err := caller.Emit(notifyPath, notifyIface+".ActionInvoked", a.id, f.key(a.id, labelAlways)); err != nil {
		t.Fatal(err)
	}
	f.click(t, a.id, labelDeny)
	if got := a.result(t); got != Deny {
		t.Errorf("The forged ActionInvoked answered %s", got)
	}
}

// A click on the body dismisses, and on COSMIC, which draws no buttons, opens the dialog
func TestNotificationBodyClick(t *testing.T) {
	immature(t)
	addr, f := testBus(t)
	for server, want := range map[string]Answer{"fake": Dismissed, cosmicServer: AllowTemp} {
		f.mu.Lock()
		f.name = server
		f.mu.Unlock()
		a := ask(t, addr, f, "a.example")
		f.mu.Lock()
		first := f.shown[a.id][0]
		f.mu.Unlock()
		if first != "default" {
			t.Errorf("%s: the first action is %q", server, first)
		}
		f.conn.Emit(notifyPath, notifyIface+".ActionInvoked", a.id, "default")
		if got := a.result(t); got != want {
			t.Errorf("%s: a click on the body answered %s", server, got)
		}
		if server == cosmicServer && !strings.Contains(<-a.dialogs, `"a.example"`) {
			t.Error("the dialog doesn't show the domain")
		}
	}
}

func TestNotificationTooEarly(t *testing.T) {
	notifyMature = 300 * time.Millisecond
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	a := ask(t, addr, f, "a.example")
	f.click(t, a.id, labelAlways)
	select {
	case again := <-f.posted:
		time.Sleep(2 * notifyMature)
		f.click(t, again, labelDeny)
	case got := <-a.answer:
		t.Fatalf("A click at once answered %s", got)
	case <-time.After(5 * time.Second):
		t.Fatal("Not asked again")
	}
	if got := a.result(t); got != Deny {
		t.Errorf("A later click answered %s", got)
	}
}

func TestNotificationWithdrawn(t *testing.T) {
	addr, f := testBus(t)
	a := ask(t, addr, f, "a.example")
	time.Sleep(100 * time.Millisecond) // Notify has returned
	a.cancel()
	if got := a.result(t); got != Dismissed {
		t.Errorf("Withdrawn answered %s", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed[a.id] {
		t.Error("The notification stayed up")
	}
}

// Domains and callers come from the client: quoted, escaped, all of them shown
func TestNotificationText(t *testing.T) {
	addr, f := testBus(t)
	a := ask(t, addr, f, "a.example", "b<i>.example Always allowed: c.example", "‮elpmaxe.d")
	f.mu.Lock()
	body := f.bodies[a.id]
	f.mu.Unlock()
	want := `For "a.example", "b&lt;i&gt;.example\u2028Always allowed: c.example", "\u202eelpmaxe.d"` + "\n"
	if !strings.HasPrefix(body, want) {
		t.Errorf("Body %q", body)
	}
	if strings.ContainsAny(body, " ‮") {
		t.Error("A separator or bidi control got through")
	}
}

func TestParseLsof(t *testing.T) {
	out := []byte("p100\ncproxy\nu501\nf7\np4242\nccurl\nu501\nf3\n")
	pid, command, uid := parseLsof(out, 100)
	if pid != 4242 || command != "curl" || uid != 501 {
		t.Errorf("parseLsof: %d %q %d", pid, command, uid)
	}
	if pid, _, _ := parseLsof([]byte("p100\ncproxy\nu501\n"), 100); pid != 0 {
		t.Errorf("found %d with only the proxy listed", pid)
	}
}

func TestParseRequirement(t *testing.T) {
	out := []byte("Executable=/usr/bin/curl\ndesignated => identifier \"com.apple.curl\" and anchor apple\n")
	if got := parseRequirement(out); got != `identifier "com.apple.curl" and anchor apple` {
		t.Errorf("parseRequirement: %q", got)
	}
	if !appSandbox.MatchString("<dict>\n\t<key>com.apple.security.app-sandbox</key>\n\t<true/>\n</dict>") {
		t.Error("App Sandbox entitlement not found")
	}
	if appSandbox.MatchString("<key>com.apple.security.app-sandbox</key><false/>") {
		t.Error("App Sandbox false counted")
	}
}

func TestAnswerFor(t *testing.T) {
	for label, want := range map[string]Answer{labelAlways + "\n": AllowAlways, labelTemp: AllowTemp, labelDeny: Deny,
		"": Dismissed, "Allow": Dismissed} {
		if got := answerFor(label); got != want {
			t.Errorf("answerFor(%q) = %s", label, got)
		}
	}
}

func TestParseAlert(t *testing.T) {
	for out, want := range map[string]string{
		"button returned:Always allow, gave up:false\n": labelAlways,
		"button returned:Deny\n":                        labelDeny,
		"button returned:, gave up:true\n":              "",
		"":                                              "",
	} {
		if got := parseAlert(out); got != want {
			t.Errorf("parseAlert(%q) = %q", out, got)
		}
	}
}
