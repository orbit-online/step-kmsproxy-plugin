package gate

import (
	"context"
	"fmt"
	"os/exec"
)

// AskUser asks with an alert from osascript. The text goes in as arguments to the run handler, so nothing in it is
// read as AppleScript. When ctx ends, osascript is killed and the alert goes with it
func AskUser(ctx context.Context, caller Caller, domains []string) (Answer, error) {
	summary, body := promptText(caller, domains)
	out, err := exec.CommandContext(ctx, "osascript",
		"-e", "on run argv",
		"-e", fmt.Sprintf(`display alert (item 1 of argv) message (item 2 of argv) as warning buttons {%q, %q, %q} default button %q giving up after %d`,
			labelDeny, labelTemp, labelAlways, labelDeny, int(MaxWait.Seconds())),
		"-e", "end run", summary, body).Output()
	if ctx.Err() != nil {
		return Dismissed, nil
	}
	if err != nil {
		return Dismissed, fmt.Errorf("Run osascript: %w", err)
	}
	return answerFor(parseAlert(string(out))), nil
}
