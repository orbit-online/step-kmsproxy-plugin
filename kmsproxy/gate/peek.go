package gate

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// How much a client may send while it waits for an answer before it counts as gone
const maxPeek = 64 << 10

// How often a wait checks whether it should stop
var peekInterval = 200 * time.Millisecond

// PeekConn notices a client hanging up while it waits for the gate. Bytes read meanwhile are kept and returned by Read
// before anything else. WaitClosed and Read must not run at the same time
type PeekConn struct {
	net.Conn
	r      io.Reader
	peeked []byte
	err    error
}

// NewPeekConn wraps conn, reading from r (conn when nil), e.g. a bufio.Reader with bytes already buffered from conn
func NewPeekConn(conn net.Conn, r io.Reader) *PeekConn {
	if r == nil {
		r = conn
	}
	return &PeekConn{Conn: conn, r: r}
}

func (c *PeekConn) Read(b []byte) (int, error) {
	if len(c.peeked) > 0 {
		n := copy(b, c.peeked)
		c.peeked = c.peeked[n:]
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(b)
}

// WaitClosed reads until the client hangs up (true) or ctx ends (false). It polls with short read deadlines, so no
// read is left running when it returns
func (c *PeekConn) WaitClosed(ctx context.Context) bool {
	defer c.Conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		if err := c.Conn.SetReadDeadline(time.Now().Add(peekInterval)); err != nil {
			c.err = err
			return true
		}
		n, err := c.r.Read(buf)
		c.peeked = append(c.peeked, buf[:n]...)
		switch {
		case len(c.peeked) > maxPeek:
			c.err = errors.New("Client sent too much while waiting for the gate")
			return true
		case errors.Is(err, os.ErrDeadlineExceeded):
		case err != nil:
			c.err = err
			return true
		}
	}
	return false
}
