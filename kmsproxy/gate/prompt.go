package gate

import (
	"strconv"
	"strings"
)

// The buttons of every prompt, in the order they're offered
const (
	labelAlways = "Always allow"
	labelTemp   = "Allow for 1 hour"
	labelDeny   = "Deny"
)

// promptText is the question as plain text. The caller and the domains come from the client, so each is quoted: a line
// separator, a bidi control or a zero-width character shows escaped and can't fake a line of the prompt or turn the
// text around. The domains come first in the body, since a server may cut the summary
func promptText(caller Caller, domains []string) (summary, body string) {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = strconv.Quote(d)
	}
	summary = "Allow " + strconv.Quote(caller.Description) + " to use your client certificate?"
	body = "For " + strings.Join(quoted, ", ") + "\nCaller: " + strconv.Quote(caller.ID)
	return summary, body
}

// buttons are the labels a prompt for caller offers, in order: "Always allow" only where Grantable allows it
func buttons(caller Caller) []string {
	if Grantable(caller.ID) {
		return []string{labelAlways, labelTemp, labelDeny}
	}
	return []string{labelTemp, labelDeny}
}

// answerFor maps a button label to its answer, anything else to Dismissed
func answerFor(label string) Answer {
	switch strings.TrimSpace(label) {
	case labelAlways:
		return AllowAlways
	case labelTemp:
		return AllowTemp
	case labelDeny:
		return Deny
	}
	return Dismissed
}
