//go:build !linux && !darwin && !windows

package gate

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("The caller gate isn't supported on this OS, run with --no-gate")

func IdentifyCaller(local, remote string) (Caller, error) { return Caller{}, errUnsupported }

func AskUser(ctx context.Context, caller Caller, domains []string) (Answer, error) {
	return Dismissed, errUnsupported
}
