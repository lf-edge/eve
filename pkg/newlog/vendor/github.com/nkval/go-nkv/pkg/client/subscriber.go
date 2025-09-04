package client

import (
	"fmt"
	framed "github.com/getlantern/framed"
	p "github.com/nkval/go-nkv/pkg/protocol"
	"net"
	"time"
)

type Subscriber struct {
	addr       string
	key        string
	uuid       string
	clientUuid string
	tx         chan<- p.Notification
}

func NewSubscriber(addr, key, uuid, clientUuid string) (*Subscriber, <-chan p.Notification) {
	ch := make(chan p.Notification)
	return &Subscriber{
		addr:       addr,
		key:        key,
		uuid:       uuid,
		clientUuid: clientUuid,
		tx:         ch,
	}, ch
}

func (s *Subscriber) Start() {
	for {
		if err := s.connect(); err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
		} else {
			fmt.Println("Disconnected, trying to reconnect...")
		}
		time.Sleep(time.Second)
	}
}

func (s *Subscriber) connect() error {
	conn, err := net.Dial("unix", s.addr)
	if err != nil {
		return fmt.Errorf("Failed to connect to server: %v\n", err)
	}
	codec := framed.NewReadWriteCloser(conn)
	codec.EnableBigFrames()

	defer codec.Close()

	req := p.Request{
		Request:   p.RequestSub,
		RequestID: s.uuid,
		ClientID:  s.clientUuid,
		Key:       s.key,
	}
	_, err = codec.Write([]byte(p.MarshalRequest(&req)))
	if err != nil {
		return fmt.Errorf("Failed to send message: %v\n", err)
	}

	for {
		response, err := codec.ReadFrame()
		if err != nil {
			return fmt.Errorf("Failed to read response: %v\n", err)
		}
		if n, err := p.UnmarshalNotification(string(response)); err != nil {
			fmt.Printf("Failed to marshal request %v", err)
			continue
		} else {
			s.tx <- *n
		}
	}
}
