package gate

// The notification follows orbit-online/agent-sandbox cmd/permissions-broker/internal/notify: keep the two in step

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface = "org.freedesktop.Notifications"
	// The name cosmic-notifications gives in GetServerInformation. It draws no buttons
	cosmicServer = "cosmic-notifications"
)

// An action within this long of the notification appearing is ignored and the question asked again, against
// look-alikes timed to sit where the user is about to click
var notifyMature = time.Second

// AskUser asks with a desktop notification on the session bus
func AskUser(ctx context.Context, caller Caller, domains []string) (Answer, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return Dismissed, fmt.Errorf("Connect to the session bus: %w", err)
	}
	defer conn.Close()
	return askOn(ctx, conn, caller, domains, zenity)
}

// askOn posts a notification with the three buttons. Anything on the session bus can replace it by its id with buttons
// of its own and send signals, so the action keys are random per notification and only signals from the server (the
// current owner of its name) count; a key that isn't ours is a dismissal. A click on the body sends the action named
// default, which comes first, since a server that draws no buttons may answer with the first action: it dismisses, and
// on COSMIC, which draws no buttons, opens dialog instead. When ctx ends the notification is closed
func askOn(ctx context.Context, conn *dbus.Conn, caller Caller, domains []string,
	dialog func(ctx context.Context, summary, body string) (Answer, error)) (Answer, error) {
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(notifyPath), dbus.WithMatchInterface(notifyIface)}
	if err := conn.AddMatchSignal(match...); err != nil {
		return Dismissed, fmt.Errorf("Watch the notifications: %w", err)
	}
	signals := make(chan *dbus.Signal, 64)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	server := conn.Object(notifyName, notifyPath)
	summary, body := promptText(caller, domains)
	for {
		var owner string
		if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, notifyName).
			Store(&owner); err != nil {
			return Dismissed, fmt.Errorf("Find the notification server: %w", err)
		}
		var name, vendor, version, spec string
		cosmic := server.CallWithContext(ctx, notifyIface+".GetServerInformation", 0).
			Store(&name, &vendor, &version, &spec) == nil && name == cosmicServer
		text, defaultLabel := body, "Dismiss"
		if cosmic {
			text, defaultLabel = body+"\nClick to answer.", "Answer…"
		}
		always, temp, deny := randomKey(), randomKey(), randomKey()
		keys := map[string]Answer{always: AllowAlways, temp: AllowTemp, deny: Deny}
		actions := []string{"default", defaultLabel, always, labelAlways, temp, labelTemp, deny, labelDeny}
		var id uint32
		if err := server.CallWithContext(ctx, notifyIface+".Notify", 0, "kmsproxy", uint32(0), "security-medium",
			escapeMarkup(summary), escapeMarkup(text), actions,
			map[string]dbus.Variant{"urgency": dbus.MakeVariant(byte(2))}, int32(0)).Store(&id); err != nil {
			if ctx.Err() != nil {
				return Dismissed, nil
			}
			return Dismissed, fmt.Errorf("Post the notification: %w", err)
		}
		shown := time.Now()
		key, err := awaitAction(ctx, signals, owner, id)
		if err != nil {
			return Dismissed, err
		}
		if ctx.Err() != nil {
			_ = server.Call(notifyIface+".CloseNotification", 0, id).Err
			return Dismissed, nil
		}
		if key != "" && time.Since(shown) < notifyMature {
			continue
		}
		if key == "default" && cosmic {
			return dialog(ctx, summary, body)
		}
		return keys[key], nil
	}
}

// awaitAction waits for the server's answer to notification id: the key of the action invoked, or "" when it closed
// unanswered or ctx ended. Signals from anything other than owner, the server, are ignored
func awaitAction(ctx context.Context, signals <-chan *dbus.Signal, owner string, id uint32) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", nil
		case s, ok := <-signals:
			if !ok {
				return "", errors.New("Lost the session bus")
			}
			if s.Sender != owner || s.Path != notifyPath || len(s.Body) < 2 {
				continue
			}
			if got, ok := s.Body[0].(uint32); !ok || got != id {
				continue
			}
			switch s.Name {
			case notifyIface + ".ActionInvoked":
				key, _ := s.Body[1].(string)
				return key, nil
			case notifyIface + ".NotificationClosed":
				return "", nil
			}
		}
	}
}

// zenity asks in a dialog, for servers that draw no buttons. It prints the label of the button clicked
func zenity(ctx context.Context, summary, body string) (Answer, error) {
	out, err := exec.CommandContext(ctx, "zenity", "--question", "--switch", "--no-markup", "--title=kmsproxy",
		"--text="+summary+"\n\n"+body,
		"--extra-button="+labelAlways, "--extra-button="+labelTemp, "--extra-button="+labelDeny).Output()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return Dismissed, fmt.Errorf("Run zenity: %w", err)
	}
	return answerFor(string(out)), nil
}

func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// randomKey is an action key nothing else on the bus can guess
func randomKey() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
