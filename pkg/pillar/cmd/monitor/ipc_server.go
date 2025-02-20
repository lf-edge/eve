// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	framed "github.com/getlantern/framed"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// All messages except for Request type, have the following format:
// where type is one of the following:
// Request, Response, NetworkStatus, DPCList, DownloaderStatus
// message is a json object that can be flattened
//   {
//		"type": "Response",
//		"message": {
//   		"Err": "big error",
//	    	"id": 10
//		}
//   }
//
//   {
//    	"RequestType": "SetDPC",
//	    "RequestData": {
//	        "dddd": "test datat"
//	    },
//	    "id": 15
//   }

type request struct {
	ID          uint64          `json:"id" validate:"required"`
	RequestType string          `json:"RequestType" validate:"required"`
	RequestData json.RawMessage `json:"RequestData"`
}

func (r *request) validate() error {
	if r.RequestType == "" {
		return errors.New("RequestType is empty")
	}
	if r.RequestData == nil {
		return errors.New("RequestData is nil")
	}
	// check supported request types
	if (r.RequestType != "SetDPC") && (r.RequestType != "SetServer") {
		return errors.New("Unsupported RequestType " + r.RequestType)
	}
	return nil
}

type response struct {
	// Ok and Err in exactly this spelling are variants or rust's Result<T, E> type
	Ok  string `json:"Ok,omitempty"`
	Err string `json:"Err,omitempty"`
	ID  uint64 `json:"id"` // Id is the id of the request that this response is for
}

type ipcMessage struct {
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message"`
}

type monitorIPCServer struct {
	codec *framed.ReadWriteCloser
	// dataReady chan bool
	ctx *monitor
	sync.Mutex
	clientConnected chan bool
}

// factory method
func newIPCServer(ctx *monitor) *monitorIPCServer {
	return &monitorIPCServer{
		ctx:             ctx,
		clientConnected: make(chan bool),
	}
}

func (s *monitorIPCServer) c() chan bool {
	return s.clientConnected
}

func (s *monitorIPCServer) handleConnection(conn net.Conn) {
	s.Lock()
	defer s.Unlock()
	// the format of the frame is length + data
	// where the length is 32 bit unsigned integer
	s.codec = framed.NewReadWriteCloser(conn)
	s.codec.EnableBigFrames()

	go func() {
		defer s.close()
		s.run()
	}()

	// notify the monitor that the client is connected
	s.ctx.clientConnected <- true
}

// close the server
func (s *monitorIPCServer) close() {
	s.codec.Close()
}

// main loop
func (s *monitorIPCServer) run() {
	// we never exit from the loop until the connection is closed
	// other errors are logged and we continue
	for {
		// read request
		req, err := s.readRequest()
		if err != nil {
			log.Warnf("Error reading request: %v", err)
			// exit if EOF
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		// handle request
		resp := s.handleRequest(req)
		log.Noticef("Response: %v", resp)
		// send response
		if err := s.sendResponse(resp); err != nil {
			if errors.Is(err, io.EOF) {
				log.Notice("Connection closed by client")
				return
			}
			log.Warnf("Error sending response: %v", err)
		}
	}
}

// read request
func (s *monitorIPCServer) readRequest() (*request, error) {
	frame, err := s.codec.ReadFrame()
	if err != nil {
		return nil, err
	}
	log.Noticef("Received frame: %v", string(frame))

	// following code is used for debugging when #[serde(untagged)] line
	// is commented out in the rust code in the IpcMessage struct
	// unmarshal IpcMessage first
	// var ipcMessage IpcMessage
	// if err := json.Unmarshal(frame, &ipcMessage); err != nil {
	// 	return nil, err
	// }

	var request request
	if err := json.Unmarshal(frame, &request); err != nil {
		return nil, err
	}
	return &request, nil
}

// send response
func (s *monitorIPCServer) sendResponse(resp *response) error {
	return s.sendIpcMessage("Response", resp)
}

func (s *monitorIPCServer) sendIpcMessage(t string, msg any) error {
	s.Lock()
	defer s.Unlock()

	var err error
	var data []byte

	if data, err = json.Marshal(msg); err != nil {
		log.Errorf("Failed to Marshal IPC message data: %v", err)
		return err
	}

	ipcMessage := ipcMessage{Type: t, Message: json.RawMessage(data)}

	if data, err = json.Marshal(ipcMessage); err != nil {
		log.Errorf("Failed to Marshal IPC message: %v", err)
		return err
	}

	if t == "TpmLogs" {
		log.Noticef("Sending IPC message: %s", t)
	} else {
		log.Noticef("Sending IPC message: %s", string(data))
	}

	_, err = s.codec.Write(data)

	if err != nil {
		log.Errorf("Failed to send IPC message: %v", err)
	}

	return err
}

func (r *request) errResponse(errorText string, err error) *response {
	if err != nil {
		errorText = errorText + ": " + err.Error()
	}
	return &response{
		Err: errorText,
		ID:  r.ID,
	}
}

func (r *request) okResponse() *response {
	return &response{
		ID: r.ID,
		Ok: "ok",
	}
}

func (r *request) unimplementedResponse() *response {
	return r.errResponse("Unimplemented request", nil)
}

func (r *request) unknownRequestResponse() *response {
	return r.errResponse("Unknown request", nil)
}

func (r *request) malformedRequestResponse(err error) *response {
	errMessage := "Malformed request [" + string(r.RequestData) + "]"
	return r.errResponse(errMessage, err)
}

func (r *request) handleRequest(ctx *monitor) *response {
	switch r.RequestType {
	case "SetDPC":
		// Unmarshal the request data
		var dpc types.DevicePortConfig
		if err := json.Unmarshal(r.RequestData, &dpc); err != nil {
			return r.malformedRequestResponse(err)
		}
		if err := ctx.IPCServer.validateDPC(dpc); err != nil {
			return r.errResponse("Failed to validate DPC", err)
		}
		// unpublish current manual DPC first
		ctx.pubDevicePortConfig.Unpublish(dpc.Key)
		// publish the DPC
		if err := ctx.pubDevicePortConfig.Publish(dpc.Key, dpc); err != nil {
			return r.errResponse("Failed to publish DPC", err)
		}
		return r.okResponse()
	case "SetServer":
		var server string
		if err := json.Unmarshal(r.RequestData, &server); err != nil {
			return r.malformedRequestResponse(err)
		}
		if err := ctx.updateServerFile(server); err != nil {
			return r.errResponse("Failed to update server file", err)
		}
		return r.okResponse()

	default:
		return r.unknownRequestResponse()
	}
}

func (s *monitorIPCServer) validateDPC(_ types.DevicePortConfig) error {
	//TODO: validate DPC
	return nil
}

// handle request
func (s *monitorIPCServer) handleRequest(req *request) *response {
	// validate request
	if err := req.validate(); err != nil {
		return req.errResponse("Failed to validate request", err)
	}
	// handle request
	return req.handleRequest(s.ctx)
}

func (ctx *monitor) startIPCServer() error {
	// Start the RPC server
	sockPath := "/run/monitor.sock"
	log.Noticef("Starting RPC server on %s", sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}

	log.Notice("RPC server started")

	go func() {
		defer listener.Close()
		for {
			log.Notice("Waiting for IPC connection")
			conn, err := listener.Accept()

			if err != nil {
				log.Warnf("Accept for RPC call failed: %v", err)
				continue
			}

			log.Notice("IPC connection accepted")

			// handle remote requests
			go ctx.IPCServer.handleConnection(conn)
		}
	}()
	return nil
}
