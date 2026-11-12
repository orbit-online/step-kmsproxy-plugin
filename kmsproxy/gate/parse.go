package gate

// Parsers for the macOS tools the gate runs, here so they are tested on every OS

import (
	"regexp"
	"strconv"
	"strings"
)

var appSandbox = regexp.MustCompile(`<key>com\.apple\.security\.app-sandbox</key>\s*<true\s*/>`)

// parseLsof reads lsof -F pcu output: a process set starts with p<pid>, followed by c<command> and u<uid>. The proxy's
// own end of the connection is skipped
func parseLsof(out []byte, self int) (pid int, command string, uid int) {
	cur := 0
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			cur, _ = strconv.Atoi(line[1:])
			if cur != self && pid == 0 {
				pid = cur
			}
		case 'c':
			if cur == pid && pid != 0 {
				command = line[1:]
			}
		case 'u':
			if cur == pid && pid != 0 {
				uid, _ = strconv.Atoi(line[1:])
			}
		}
	}
	return pid, command, uid
}

// parseRequirement takes the designated requirement from codesign -r- output
func parseRequirement(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if req, ok := strings.CutPrefix(line, "designated => "); ok {
			return strings.TrimSpace(req)
		}
	}
	return ""
}

// parseAlert takes the button from osascript output for display alert, "button returned:Deny, gave up:false". It's
// empty when the alert gave up
func parseAlert(out string) string {
	_, rest, ok := strings.Cut(out, "button returned:")
	if !ok {
		return ""
	}
	button, _, _ := strings.Cut(rest, ", gave up:")
	return strings.TrimSpace(button)
}
