package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// RequestType represents valid command types.
type RequestType string

const (
	RequestGet     RequestType = "GET"
	RequestPut     RequestType = "PUT"
	RequestDel     RequestType = "DEL"
	RequestSub     RequestType = "SUB"
	RequestUnsub   RequestType = "UNSUB"
	RequestTrace   RequestType = "TRACE"
	RequestHealth  RequestType = "HEALTH"
	RequestVersion RequestType = "VERSION"
	RequestUnknown RequestType = "UNKNOWN"
)

var (
	ErrMissingField      = errors.New("missing required field")
	ErrUnknownCommand    = errors.New("unknown command")
	ErrInvalidInput      = errors.New("invalid input")
	ErrBase64DecodeError = errors.New("base64 decode error")
)

type Request struct {
	Request   RequestType
	RequestID string
	ClientID  string
	Key       string
	Data      []byte // Decoded data (if present)
}

func parseRequestType(input string) RequestType {
	switch RequestType(input) {
	case RequestGet, RequestPut, RequestDel, RequestSub, RequestUnsub:
		return RequestType(input)
	default:
		return RequestUnknown
	}
}

func UnmarshalRequest(input string) (*Request, error) {
	parts := strings.Fields(input)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid input: expected at least 4 fields, got %d", len(parts))
	}

	cmdType := parseRequestType(parts[0])

	cmd := &Request{
		Request:   cmdType,
		RequestID: parts[1],
		ClientID:  parts[2],
		Key:       parts[3],
	}

	if len(parts) > 4 {
		data, err := base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			return nil, fmt.Errorf("invalid base64 data: %w", err)
		}
		cmd.Data = data
	}

	return cmd, nil
}

func MarshalRequest(cmd *Request) string {
	switch cmd.Request {
	case RequestGet, RequestDel, RequestSub, RequestUnsub, RequestHealth, RequestTrace, RequestVersion:
		return fmt.Sprintf("%s %s %s %s\n", string(cmd.Request), cmd.RequestID, cmd.ClientID, cmd.Key)
	case RequestPut:
		data := base64.StdEncoding.EncodeToString(cmd.Data)
		return fmt.Sprintf("%s %s %s %s %s\n", string(cmd.Request), cmd.RequestID, cmd.ClientID, cmd.Key, data)
	default:
		return string(RequestUnknown)
	}

}

type Marshalable interface {
	Marshal() string
	Debug() string
	Unmarshal(input string) error
}

type HashMapStringBytes map[string][]byte

// Marshal converts the map to string
func (h HashMapStringBytes) Marshal() string {
	var result strings.Builder
	for key, val := range h {
		encoded := base64.StdEncoding.EncodeToString(val)
		result.WriteString(fmt.Sprintf(" %s %s", key, encoded))
	}
	return result.String()
}

// Debug provides debug output
func (h HashMapStringBytes) Debug() string {
	var result strings.Builder
	for key, val := range h {
		if s, err := stringFromBytes(val); err == nil {
			result.WriteString(fmt.Sprintf(" %s %s", key, s))
		} else {
			result.WriteString(fmt.Sprintf(" %s %v", key, val))
		}
	}
	return result.String()
}

// Unmarshal parses string into the map
func (h HashMapStringBytes) Unmarshal(input string) error {
	parts := strings.Fields(input)
	if len(parts)%2 != 0 {
		return ErrInvalidInput
	}

	for i := 0; i < len(parts); i += 2 {
		key := parts[i]
		val, err := base64.StdEncoding.DecodeString(parts[i+1])
		if err != nil {
			return ErrBase64DecodeError
		}
		h[key] = val
	}
	return nil
}

// StringSlice implements Marshalable for []string
type StringSlice []string

// Marshal converts the slice to string
func (s StringSlice) Marshal() string {
	return " " + strings.Join(s, " ")
}

// Debug provides debug output
func (s StringSlice) Debug() string {
	var result strings.Builder
	for _, val := range s {
		result.WriteString(fmt.Sprintf(" %q", val))
	}
	return result.String()
}

// Unmarshal parses string into the slice
func (s *StringSlice) Unmarshal(input string) error {
	*s = strings.Fields(input)
	return nil
}

// StringWrapper implements Marshalable for string
type StringWrapper string

// Marshal converts the string to output format
func (s StringWrapper) Marshal() string {
	return " " + string(s)
}

// Debug provides debug output
func (s StringWrapper) Debug() string {
	return fmt.Sprintf(" %q", s)
}

// Unmarshal parses string
func (s *StringWrapper) Unmarshal(input string) error {
	*s = StringWrapper(input)
	return nil
}

func stringFromBytes(b []byte) (string, error) {
	for _, v := range b {
		if v < 32 || v > 126 {
			return "", errors.New("non-printable character")
		}
	}
	return string(b), nil
}

type Response struct {
	RequestID string
	Status    bool
	Data      Marshalable
}

func UnmarshalResponse(input string) (*Response, error) {
	parts := strings.Fields(input)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid input: expected at least 2 fields, got %d", len(parts))
	}

	status := false
	switch parts[2] {
	case "OK":
		status = true
	case "FAILED":
		status = false
	default:
		return nil, fmt.Errorf("invalid input: status is not recognized. Expected OK or FAILED got %s", parts[1])
	}

	data := strings.Join(parts[3:], " ")
	switch parts[0] {
	case "data":
		d := make(HashMapStringBytes)
		d.Unmarshal(data)
		return &Response{
			RequestID: parts[1],
			Status:    status,
			Data:      d,
		}, nil

	case "trace":
		var d StringSlice
		d.Unmarshal(data)
		return &Response{
			RequestID: parts[1],
			Status:    status,
			Data:      &d,
		}, nil

	case "version":
		var d StringWrapper
		d.Unmarshal(data)
		return &Response{
			RequestID: parts[1],
			Status:    status,
			Data:      &d,
		}, nil
	}

	return &Response{
		RequestID: parts[1],
		Status:    status,
		Data:      nil,
	}, nil
}

func MarshalResponseDebug(resp *Response) string {
	status := ""
	if resp.Status {
		status = "OK"
	} else {
		status = "FAILED"
	}

	if resp.Data != nil {
		data := strings.TrimSpace(resp.Data.Debug())
		if len(data) > 0 {
			return fmt.Sprintf("%s %s %s", resp.RequestID, status, data)
		}
	}

	return fmt.Sprintf("%s %s", resp.RequestID, status)
}

type NotifcationType string

const (
	NotificationHello    NotifcationType = "HELLO"
	NotificationUpdate   NotifcationType = "UPDATE"
	NotificationClose    NotifcationType = "CLOSE"
	NotificationNotFound NotifcationType = "NOTFOUND"
	NotificationUnkown   NotifcationType = "UNKNOWN"
)

type Notification struct {
	Type NotifcationType
	Key  string
	Data []byte
}

func MarshalNotification(n *Notification) string {
	if len(n.Data) > 0 {
		encoded := base64.StdEncoding.EncodeToString(n.Data)
		return fmt.Sprintf("%s %s %s", string(n.Type), n.Key, encoded)
	} else {
		return fmt.Sprintf("%s %s", string(n.Type), n.Key)
	}
}

func parseNotificationType(input string) NotifcationType {
	switch NotifcationType(input) {
	case NotificationHello, NotificationUpdate, NotificationClose, NotificationNotFound:
		return NotifcationType(input)
	default:
		return NotificationUnkown
	}
}

func UnmarshalNotification(input string) (*Notification, error) {
	parts := strings.Fields(input)

	n := &Notification{
		Type: parseNotificationType(parts[0]),
	}

	if len(parts) > 1 {
		n.Key = parts[1]
	}

	if len(parts) > 2 {
		n.Key = parts[1]
		data, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid base64 data: %w", err)
		}
		n.Data = data
	}

	return n, nil
}
