package smtpproxy

import (
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
)

// lingerTimeout bounds how long a connection that is closed after a final
// reply keeps reading what the client still sends, so the client reads the
// reply instead of a TCP reset.
const lingerTimeout = 5 * time.Second

// Close states of a clientConn.
const (
	connOpen int32 = iota
	connCloseAfterReply
	connReplied
)

// listener wraps every accepted connection in a clientConn.
type listener struct{ net.Listener }

// wrapListener returns ln with connections the session can close after its
// reply (closeAfterReply).
func wrapListener(ln net.Listener) net.Listener { return listener{ln} }

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &clientConn{Conn: c}, nil
}

// clientConn lets a session end the connection after the reply to the
// current command, for errors after which the input stream cannot be
// trusted any more: the rest of an aborted DATA would otherwise be read as
// commands. go-smtp has no hook for this, so the connection does it: the
// reply is the next write, later writes are dropped, reads return EOF, and
// Close waits for the client to stop sending (lingering close).
type clientConn struct {
	net.Conn
	state atomic.Int32
}

func (c *clientConn) closeAfterReply() { c.state.CompareAndSwap(connOpen, connCloseAfterReply) }

func (c *clientConn) Write(p []byte) (int, error) {
	switch c.state.Load() {
	case connReplied:
		return len(p), nil
	case connCloseAfterReply:
		n, err := c.Conn.Write(p)
		c.state.Store(connReplied)
		return n, err
	}
	return c.Conn.Write(p)
}

func (c *clientConn) Read(p []byte) (int, error) {
	if c.state.Load() == connReplied {
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}

func (c *clientConn) Close() error {
	if c.state.Load() != connOpen {
		if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		_ = c.Conn.SetReadDeadline(time.Now().Add(lingerTimeout))
		_, _ = io.Copy(io.Discard, c.Conn)
	}
	return c.Conn.Close()
}

// closeAfterReply ends the session's connection once the reply to the
// current command is written. Without the wrapper (a server not started on
// wrapListener) it closes the connection at once: losing the reply is
// better than reading the rest of the message as commands.
func (s *session) closeAfterReply() {
	nc := s.conn.Conn()
	if tc, ok := nc.(*tls.Conn); ok {
		nc = tc.NetConn()
	}
	if cc, ok := nc.(*clientConn); ok {
		cc.closeAfterReply()
		return
	}
	_ = s.conn.Close()
}

// errLineTooLong answers a message line over the server's MaxLineLength.
func errLineTooLong(srv *smtp.Server) *smtp.SMTPError {
	return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0},
		Message: "Line longer than " + strconv.Itoa(srv.MaxLineLength) + " bytes; use quoted-printable or base64"}
}
