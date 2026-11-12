package gate

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// AskUser asks with an alert from osascript. The text goes in as arguments to the run handler, so nothing in it is
// read as AppleScript. When ctx ends, osascript is killed and the alert goes with it
func AskUser(ctx context.Context, caller Caller, domains []string) (Answer, error) {
	summary, body := promptText(caller, domains)
	// The default button sits on the right
	labels := buttons(caller)
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[len(labels)-1-i] = strconv.Quote(label)
	}
	out, err := exec.CommandContext(ctx, "osascript",
		"-e", "on run argv",
		"-e", fmt.Sprintf(`display alert (item 1 of argv) message (item 2 of argv) as warning buttons {%s} default button %q giving up after %d`,
			strings.Join(quoted, ", "), labelDeny, int(MaxWait.Seconds())),
		"-e", "end run", summary, body).Output()
	if ctx.Err() != nil {
		return Dismissed, nil
	}
	if err != nil {
		return Dismissed, fmt.Errorf("Run osascript: %w", err)
	}
	return answerFor(parseAlert(string(out))), nil
}
