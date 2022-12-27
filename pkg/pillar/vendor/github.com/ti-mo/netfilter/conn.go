package netfilter

import (
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Conn represents a Netlink connection to the Netfilter subsystem.
type Conn struct {
	conn *netlink.Conn

	// Marks the Conn as being attached to one or more multicast groups,
	// it can no longer be used for any queries for its remaining lifetime.
	isMulticast bool

	// Mutex to protect isMulticast
	mu sync.RWMutex
}

// Dial opens a new Netlink connection to the Netfilter subsystem
// and returns it wrapped in a Conn structure.
func Dial(config *netlink.Config) (*Conn, error) {
	var c Conn
	var err error

	c.conn, err = netlink.Dial(unix.NETLINK_NETFILTER, config)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// Close closes a Conn.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Query sends a Netfilter message over Netlink and validates the response.
// The call will fail if the Conn is marked as Multicast. Any errors returned
// from the underlying Netlink layer are wrapped using pkg/errors.Wrap(). Use
// errors.Cause() to unwrap to compare to Errno.
func (c *Conn) Query(nlm netlink.Message) ([]netlink.Message, error) {

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isMulticast {
		return nil, errConnIsMulticast
	}

	ret, err := c.conn.Execute(nlm)
	if err != nil {
		return nil, errors.Wrap(err, "netfilter query")
	}

	return ret, nil
}

// JoinGroups attaches the Netlink socket to one or more Netfilter multicast groups.
// Marks the Conn as Multicast, meaning it can no longer be used for any queries.
func (c *Conn) JoinGroups(groups []NetlinkGroup) error {

	if len(groups) == 0 {
		return errNoMulticastGroups
	}

	// Write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, group := range groups {
		err := c.conn.JoinGroup(uint32(group))
		if err != nil {
			return err
		}
	}

	// Mark the Conn as being attached to a multicast group
	c.isMulticast = true

	return nil
}

// LeaveGroups detaches the Netlink socket from one or more Netfilter multicast groups.
// Does not remove the Multicast flag, open a separate Conn for making queries instead.
func (c *Conn) LeaveGroups(groups []NetlinkGroup) error {

	// Write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, group := range groups {
		err := c.conn.LeaveGroup(uint32(group))
		if err != nil {
			return err
		}
	}

	return nil
}

// Receive executes a blocking read on the underlying Netlink socket and returns a Message.
func (c *Conn) Receive() ([]netlink.Message, error) {
	return c.conn.Receive()
}

// IsMulticast returns the Conn's Multicast flag. It is set by calling Listen().
func (c *Conn) IsMulticast() bool {

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.isMulticast
}

// SetOption enables or disables a netlink socket option for the Conn.
func (c *Conn) SetOption(option netlink.ConnOption, enable bool) error {
	return c.conn.SetOption(option, enable)
}

// SetDeadline sets the read and write deadlines associated with the connection.
//
// Deadline functionality is only supported on Go 1.12+. Calling this function
// on older versions of Go will result in an error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the connection.
//
// Deadline functionality is only supported on Go 1.12+. Calling this function
// on older versions of Go will result in an error.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the connection.
//
// Deadline functionality is only supported on Go 1.12+. Calling this function on older versions of Go will result in an error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the Conn.
func (c *Conn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the Conn.
func (c *Conn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}
