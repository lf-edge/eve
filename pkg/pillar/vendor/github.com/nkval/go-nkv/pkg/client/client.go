package client

import (
	"bufio"
	"fmt"
	"github.com/google/uuid"
	p "github.com/nkval/go-nkv/pkg/protocol"
	"net"
)

// use this when request was not even sent to server
const DEFAULT_UUID = "0"

type Client struct {
	addr          string
	clientUUID    string
	subscriptions map[string]string
}

func NewClient(addr string) *Client {
	return &Client{
		addr:          addr,
		clientUUID:    generateUuid(),
		subscriptions: make(map[string]string),
	}
}

func (c *Client) Get(key string) (*p.Response, error) {
	return c.sendRequest(p.Request{
		Request:   p.RequestGet,
		RequestID: generateUuid(),
		ClientID:  c.clientUUID,
		Key:       key,
	})

}

func (c *Client) Put(key string, data []byte) (*p.Response, error) {
	return c.sendRequest(p.Request{
		Request:   p.RequestPut,
		RequestID: generateUuid(),
		ClientID:  c.clientUUID,
		Key:       key,
		Data:      data,
	})
}

func (c *Client) Delete(key string) (*p.Response, error) {
	return c.sendRequest(p.Request{
		Request:   p.RequestDel,
		RequestID: generateUuid(),
		ClientID:  c.clientUUID,
		Key:       key,
	})
}

func (c *Client) Subscribe(key string, hdlr func(p.Notification)) (*p.Response, error) {
	if reqID, ok := c.subscriptions[key]; ok {
		return &p.Response{
			RequestID: reqID,
			Status:    false,
		}, nil
	}
	uuid := generateUuid()
	subscriber, rx := NewSubscriber(c.addr, key, uuid, c.clientUUID)

	go subscriber.Start()

	go func() {
		for {
			select {
			case msg := <-rx:
				hdlr(msg)
			}
		}
	}()

	c.subscriptions[key] = uuid

	return &p.Response{
		RequestID: uuid,
		Status:    true,
	}, nil
}

func (c *Client) Unsubscribe(key string) (*p.Response, error) {
	if reqID, ok := c.subscriptions[key]; ok {
		return c.sendRequest(p.Request{
			Request:   p.RequestUnsub,
			RequestID: reqID,
			ClientID:  c.clientUUID,
			Key:       key,
		})
	}
	return &p.Response{
		RequestID: DEFAULT_UUID,
		Status:    false,
	}, nil
}

func (c *Client) sendRequest(req p.Request) (*p.Response, error) {
	conn, err := net.Dial("unix", c.addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to server: %v\n", err)
	}
	defer conn.Close()

	marshalledReq := fmt.Sprintf("%s\n", p.MarshalRequest(&req))
	_, err = conn.Write([]byte(marshalledReq))
	if err != nil {
		return nil, fmt.Errorf("Failed to send message: %v\n", err)
	}

	fmt.Println("-->READING RESPONSE...")
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("Failed to read response: %v\n", err)
	}

	return p.UnmarshalResponse(response)
}

func generateUuid() string {
	return fmt.Sprintf("golang-nkv-client-%s", uuid.New())
}
