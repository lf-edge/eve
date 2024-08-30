// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcom

// ChannelID represents a unique identifier for a communication channel
type ChannelID int

// RequestID represents a unique identifier for a request within a channel
type RequestID int

// HostVPort is the port on which the vsock listens on the host, this is
// the port that the guest should connect. This is vsock port and it won't
// block the usage of the same port in other types of sockets like TCP.
const HostVPort = 2000

const (
	// channel name should be in form of Channel<Name> = baseChannelID + X
	baseChannelID ChannelID = 0

	// ChannelError is the channel for error responses
	ChannelError ChannelID = baseChannelID + iota
	//ChannelTpm is the channel for TPM related requests
	ChannelTpm
)

const (
	// request name should be in form of Request<ChannelName><Request> = X
	baseRequestID RequestID = 0

	//RequestTpmGetEk is the request to get the TPM Endorsement Key
	RequestTpmGetEk = baseRequestID + iota
)

// Base is the base packet for all other packets
// it should be embedded in other packets.
type Base struct {
	// Channel is the channel ID for the packet
	Channel int `json:"channel"`
}

// Error is the response packet for errors
type Error struct {
	// Base is embedded here to set the channel
	Base
	// Error is the error message
	Error string `json:"error"`
}

// TpmRequest is the request packet for TPM related requests
type TpmRequest struct {
	// Base is embedded here to set the channel
	Base
	// Request is the request ID
	Request uint `json:"request"`
	// expand this struct with more fields as needed
}

// TpmResponseEk is the response packet for TPM Endorsement Key request
type TpmResponseEk struct {
	// Base is embedded here to set the channel
	Base
	// Ek is the TPM Endorsement Key
	Ek string `json:"ek"`
}
