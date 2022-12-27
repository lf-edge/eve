# Network Tracing (nettrace package)

## Motivation

Taking [Golang's HTTP client][http-client] as an example - a single HTTP request
(triggered for example by calling [Client.Do()][http-client-do]) uses multiple network
protocols from different layers of the network stack and performs multiple network operations,
some run in sequence and others in parallel. For example, the client first has to resolve
the destination hostname, unless an IP address was given directly instead. It will (most
likely) use the Golang's own resolver to try every configured DNS server one by one. For
every DNS server it may run DNS requests (over UDP or TCP if UDP response is truncated) for
IPv4 and IPv6 in parallel (the [Happy Eyeballs algorithm][rfc6555]). The hostname itself may
resolve into multiple IP addresses and the HTTP client will try one or several of them until
it succeeds to open a TCP connection. For HTTPs it will then follow with the TLS handshake
at the session layer of the network stack. Only then the actual HTTP request is send.
If an HTTP redirect response code is returned, the whole process is repeated for the returned
URL.

This can be even more complicated because:

- TCP connection can be reused between HTTP requests (HTTP keep-alive)
- HTTP client can be configured to use a network proxy. The proxy may listen on HTTP or HTTPs.
  In the latter case the client would establish TLS tunnel inside a TLS tunnel!
- HTTP client can be configured to use a specific source IP address instead of picking
  one dynamically based on a routing decision.

Despite all this complexity, there is only one error value returned and available if a request
fails. Even though the error may [wrap multiple errors][error-wrap] inside, there is often
not enough information needed to troubleshoot a failed HTTP request. For example, quite common
is to receive a timeout error of some sort from the HTTP client. Given that the client performs
multiple network operations synchronously or in parallel and that there are multiple timeouts
configurable for different operations (DNS resolution, TCP handshakes and the request itself
can all have different timeouts), it can be challenging to determine which operation has failed
to finish in time or has consumed unexpected amount of it. Furthermore, the errors returned
are difficult to process and analyse programmatically. The error attributes
(e.g. a destination IP address of a failed TCP handshake) are often not exported and need to be
parsed from the string error message, which is cumbersome. In some cases even the error type
itself is not exported (e.g. `http.httpError`).

The idea of this package is to hook into Golang's HTTP client and capture all kinds of information
available from different network layers of the HTTP request processing (see the next section
to learn what we can observe and record), which, when combined, provides the user with a clear
picture of what was happening behind the scenes. When a request fails, it is much easier
to backtrace to its root cause. Network traces which the package returns are all well-defined
using structures with many exported and documented fields and can be used as an input
for a computer-driven analysis.

For now the package supports only the Golang's HTTP client, but in the future we could add support
for network tracing of some other networking-oriented clients/servers/... written in Go.

## What Can Be Traced

Applying nettrace to Golang's HTTP client, the following set of network traces will be collected:

- record of every HTTP request, including the number of the HTTP version used, HTTP headers
  (optional), content length, response status code and more.
- record of every Dial (see [Transport.DialContext()][http-transport]), with information about
  the destination address, static source address if configured, list of nested Dials performed
  by the resolver, etc.
- record of every UDP "connection" (used for name resolution), including the src/dst IP/port
  4-tuple, conntrack entry (optional), number of payload bytes sent/received, trace of every
  socket read/write operation (optional).
- record of every TCP connection (established or failed to establish), including the src/dst
  IP/port 4-tuple, conntrack entry (optional), number of payload bytes sent/received,
  trace for every socket read/write operation (optional), flag informing if the connection
  was reused, etc.
- record of every DNS query<->reply conversation between the resolver and a DNS server (optional)
- record of every TLS tunnel (established or failed to establish), including summary of peer
  certificates (subject, issuer, validity time range), negotiated protocol and cipher suite, etc.
- packet capture filtered to contain only packets corresponding to traced HTTP requests (optional)

These traces reference each other using trace IDs (see [TraceID](./nettrace.go) data type).
For example, HTTP request trace references recording of the used TCP connection, which then
references Dial where it has originated from.

Moreover, every trace includes one or more timestamps, used to inform when the given operation
began, ended, when the [context][context] was closed, etc. These timestamps are recorded relatively
in the milliseconds precision wrt. time when the tracing started for better readability.

Some of these traces are configurable and can be enabled/disabled - see the set of available
[options](./options.go).

For a full list of available traces and their attributes, see [NetTrace](./nettrace.go) and its
extension [HTTPTrace](./nettrace.go) (adding HTTP specific network traces).

## How To Use It

In order to trace Golang's `http.Client`, it is necessary to let the nettrace package to instantiate
the client (so that it can add some hooks for tracing purposes). Meaning that instead of doing
`client := &http.Client{}`, use the constructor provided by nettrace:

```go
import (
    "github.com/lf-edge/eve/libs/nettrace"
)

func main() {
    // Example config for the HTTP client:
    cfg := nettrace.HTTPClientCfg{
        PreferHTTP2:       false, // Prefer HTTP1/1
        DisableKeepAlives: true,  // Do not reuse connections
        ReqTimeout:        time.Minute,
    }
    // Example options for network tracing:
    opts := []nettrace.TraceOpt{
        &nettrace.WithLogging{},
        &nettrace.WithConntrack{},
        &nettrace.WithSockTrace{},
        &nettrace.WithDNSQueryTrace{},
        &nettrace.WithHTTPReqTrace{
            HeaderFields: nettrace.HdrFieldsOptDisabled,
        },
        &nettrace.WithPacketCapture{
            Interfaces:  []string{"eth0"},
            IncludeICMP: true,
            IncludeARP:  true,
        },
    }
    client, err := nettrace.NewHTTPClient(cfg, opts...)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    // ...
}
```

The returned client wraps the `http.Client` as an exported field, meaning that it exposes
all the methods of the original client, like `Do()`, `Get()`, `Post()`, etc.
If a 3rd party library expects `http.Client` type, simply pass the embedded `client.Client`.

Please DO NOT change the `Client.Transport` field of the embedded client (to further
customize the HTTP client behaviour), otherwise tracing functionality may get broken.
Instead, configure the desired behaviour of the HTTP client inside the `nettrace.HTTPClientCfg`
argument of the `nettrace.NewHTTPClient()` constructor.
The only allowed action is to additionally wrap the Transport with a [RoundTripper][round-tripper]
implementation, which is allowed to for example modify HTTP requests/responses,
but still should call the wrapped Transport for the HTTP request execution.
An example of this is [Transport from the oauth2 package][oauth2-transp], adding
an Authorization header with a token.

With the client constructed, run one or more HTTP requests (using the embedded `http.Client`)
and later use `GetTrace()` to obtain collected network traces:

```go
ctx := context.Background()
req, err := http.NewRequestWithContext(ctx, "GET", "https://www.google.com/", nil)
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}
resp, err := client.Do(req)
if err == nil && resp != nil && resp.Body != nil {
    if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

// ...

httpTrace, pcaps, err := client.GetTrace("example")
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}
traceInJson, err := json.MarshalIndent(httpTrace, "", "  ")
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Printf("Network traces collected from the HTTP client: %s\n", string(traceInJson))
```

Note that communication with the HTTP server continues until the request fails
or the returned body is fully read or closed. In other words, prefer getting network
traces AFTER reading response body.

The returned packet captures (`pcaps` in the example; one for each configured interface)
can be each saved to a file using `PacketCapture.WriteToFile(filename)` and analyzed
e.g. using [Wireshark][wireshark].

When starting a new HTTP request, one may want to remove previously collected network
traces before starting collecting new ones - use `HTTPClient.ClearTrace()` for that.

Lastly, before leaving `HTTPClient` for the garbage collector, call `HTTPClient.Close()`
to ensure that network tracing and packet capturing are stopped and all the resources
held by nettrace are freed.

## Network Trace Example

Attached is an example of all network traces (except for packet capture) collected for
a (NATed) `GET https://www.google.com/` request. This is returned as an instance of `HTTPTrace`
structure and can be marshalled into JSON, an example of which is shown below:

```json
{
  "description": "GET https://www.google.com/",
  "traceBeginAt": "2022-12-23T10:17:45.260618344+01:00",
  "traceEndAt": "+1241ms",
  "dials": [
    {
      "traceID": "tid-3",
      "dialBeginAt": "+72ms",
      "dialEndAt": "+126ms",
      "ctxCloseAt": "+241ms",
      "dstAddress": "www.google.com:443",
      "resolverDials": [
        {
          "dialBeginAt": "+73ms",
          "dialEndAt": "+73ms",
          "nameserver": "8.8.8.8:53",
          "establishedConn": "tid-5"
        },
        {
          "dialBeginAt": "+73ms",
          "dialEndAt": "+73ms",
          "nameserver": "8.8.8.8:53",
          "establishedConn": "tid-7"
        }
      ],
      "sourceIP": "192.168.99.1",
      "establishedConn": "tid-8"
    }
  ],
  "tcpConns": [
    {
      "traceID": "tid-8",
      "fromDial": "tid-3",
      "handshakeBeginAt": "+115ms",
      "handshakeEndAt": "+126ms",
      "connected": true,
      "connCloseAt": "+241ms",
      "addrTuple": {
        "srcIP": "192.168.99.1",
        "srcPort": 33623,
        "dstIP": "142.251.36.132",
        "dstPort": 443
      },
      "reused": false,
      "totalSentBytes": 735,
      "totalRecvBytes": 12657,
      "conntrack": {
        "capturedAt": "+1075ms",
        "status": "assured|src-nat|confirmed|src-nat-done|dst-nat-done|seen-reply",
        "tcpState": "last-ack",
        "mark": 0,
        "addrOrig": {
          "srcIP": "192.168.99.1",
          "srcPort": 33623,
          "dstIP": "142.251.36.132",
          "dstPort": 443
        },
        "addrReply": {
          "srcIP": "142.251.36.132",
          "srcPort": 443,
          "dstIP": "192.168.88.2",
          "dstPort": 33623
        },
        "packetsSent": 24,
        "packetsRecv": 17,
        "bytesSent": 1991,
        "bytesRecv": 13549
      },
      "socketTrace": {
        "socketOps": [
          {
            "type": "write",
            "callAt": "+127ms",
            "returnAt": "+127ms",
            "dataLen": 280
          },
          {
            "type": "read",
            "callAt": "+127ms",
            "returnAt": "+152ms",
            "dataLen": 576
          },
          {
            "type": "read",
            "callAt": "+153ms",
            "returnAt": "+153ms",
            "dataLen": 3713
          },
          {
            "type": "write",
            "callAt": "+172ms",
            "returnAt": "+172ms",
            "dataLen": 64
          },
          {
            "type": "write",
            "callAt": "+172ms",
            "returnAt": "+172ms",
            "dataLen": 86
          },
          {
            "type": "write",
            "callAt": "+172ms",
            "returnAt": "+172ms",
            "dataLen": 67
          },
          {
            "type": "read",
            "callAt": "+172ms",
            "returnAt": "+183ms",
            "dataLen": 62
          },
          {
            "type": "write",
            "callAt": "+183ms",
            "returnAt": "+183ms",
            "dataLen": 31
          },
          {
            "type": "read",
            "callAt": "+183ms",
            "returnAt": "+184ms",
            "dataLen": 31
          },
          {
            "type": "read",
            "callAt": "+184ms",
            "returnAt": "+239ms",
            "dataLen": 1022
          },
          {
            "type": "read",
            "callAt": "+239ms",
            "returnAt": "+239ms",
            "dataLen": 4864
          },
          {
            "type": "read",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 736
          },
          {
            "type": "read",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 1653
          },
          {
            "type": "write",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 48
          },
          {
            "type": "write",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 48
          },
          {
            "type": "write",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 48
          },
          {
            "type": "write",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 39
          },
          {
            "type": "write",
            "callAt": "+240ms",
            "returnAt": "+240ms",
            "dataLen": 24
          },
          {
            "type": "read",
            "callAt": "+240ms",
            "returnAt": "+241ms",
            "returnErr": "read tcp 192.168.99.1:33623-\u003e142.251.36.132:443: use of closed network connection",
            "dataLen": 0
          }
        ]
      }
    }
  ],
  "udpConns": [
    {
      "traceID": "tid-5",
      "fromDial": "tid-3",
      "fromResolver": true,
      "socketCreateAt": "+73ms",
      "connCloseAt": "+115ms",
      "addrTuple": {
        "srcIP": "192.168.99.1",
        "srcPort": 40475,
        "dstIP": "8.8.8.8",
        "dstPort": 53
      },
      "totalSentBytes": 43,
      "totalRecvBytes": 71,
      "conntrack": {
        "capturedAt": "+1074ms",
        "status": "confirmed|src-nat-done|dst-nat-done|seen-reply|src-nat",
        "mark": 0,
        "addrOrig": {
          "srcIP": "192.168.99.1",
          "srcPort": 40475,
          "dstIP": "8.8.8.8",
          "dstPort": 53
        },
        "addrReply": {
          "srcIP": "8.8.8.8",
          "srcPort": 53,
          "dstIP": "192.168.88.2",
          "dstPort": 40475
        },
        "packetsSent": 1,
        "packetsRecv": 1,
        "bytesSent": 71,
        "bytesRecv": 99
      },
      "socketTrace": {
        "socketOps": [
          {
            "type": "write",
            "callAt": "+73ms",
            "returnAt": "+73ms",
            "dataLen": 43
          },
          {
            "type": "read",
            "callAt": "+73ms",
            "returnAt": "+115ms",
            "dataLen": 71
          }
        ]
      }
    },
    {
      "traceID": "tid-7",
      "fromDial": "tid-3",
      "fromResolver": true,
      "socketCreateAt": "+73ms",
      "connCloseAt": "+115ms",
      "addrTuple": {
        "srcIP": "192.168.99.1",
        "srcPort": 49789,
        "dstIP": "8.8.8.8",
        "dstPort": 53
      },
      "totalSentBytes": 43,
      "totalRecvBytes": 59,
      "conntrack": {
        "capturedAt": "+1074ms",
        "status": "seen-reply|src-nat|confirmed|src-nat-done|dst-nat-done",
        "mark": 0,
        "addrOrig": {
          "srcIP": "192.168.99.1",
          "srcPort": 49789,
          "dstIP": "8.8.8.8",
          "dstPort": 53
        },
        "addrReply": {
          "srcIP": "8.8.8.8",
          "srcPort": 53,
          "dstIP": "192.168.88.2",
          "dstPort": 49789
        },
        "packetsSent": 1,
        "packetsRecv": 1,
        "bytesSent": 71,
        "bytesRecv": 87
      },
      "socketTrace": {
        "socketOps": [
          {
            "type": "write",
            "callAt": "+73ms",
            "returnAt": "+74ms",
            "dataLen": 43
          },
          {
            "type": "read",
            "callAt": "+74ms",
            "returnAt": "+115ms",
            "dataLen": 59
          }
        ]
      }
    }
  ],
  "dnsQueries": [
    {
      "traceID": "tid-b",
      "fromDial": "tid-3",
      "connection": "tid-7",
      "dnsQueryMsgs": [
        {
          "sentAt": "+74ms",
          "id": 34311,
          "recursionDesired": true,
          "truncated": false,
          "size": 43,
          "questions": [
            {
              "name": "www.google.com.",
              "type": "A",
              "class": 1
            }
          ],
          "optUDPPayloadSize": 1232
        }
      ],
      "dnsReplyMsgs": [
        {
          "recvAt": "+115ms",
          "id": 34311,
          "authoritative": false,
          "recursionAvailable": true,
          "truncated": false,
          "size": 59,
          "rCode": "no-error",
          "answers": [
            {
              "name": "www.google.com.",
              "type": "A",
              "class": 1,
              "ttl": 227,
              "resolvedVal": "142.251.36.132"
            }
          ]
        }
      ]
    },
    {
      "traceID": "tid-a",
      "fromDial": "tid-3",
      "connection": "tid-5",
      "dnsQueryMsgs": [
        {
          "sentAt": "+73ms",
          "id": 54063,
          "recursionDesired": true,
          "truncated": false,
          "size": 43,
          "questions": [
            {
              "name": "www.google.com.",
              "type": "AAAA",
              "class": 1
            }
          ],
          "optUDPPayloadSize": 1232
        }
      ],
      "dnsReplyMsgs": [
        {
          "recvAt": "+115ms",
          "id": 54063,
          "authoritative": false,
          "recursionAvailable": true,
          "truncated": false,
          "size": 71,
          "rCode": "no-error",
          "answers": [
            {
              "name": "www.google.com.",
              "type": "AAAA",
              "class": 1,
              "ttl": 133,
              "resolvedVal": "2a00:1450:4014:80e::2004"
            }
          ]
        }
      ]
    }
  ],
  "tlsTunnels": [
    {
      "traceID": "tid-9",
      "tcpConn": "tid-8",
      "handshakeBeginAt": "+126ms",
      "handshakeEndAt": "+172ms",
      "didResume": false,
      "peerCerts": [
        {
          "subject": "CN=www.google.com",
          "issuer": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
          "notBefore": "2022-11-28T08:19:01Z",
          "notAfter": "2023-02-20T08:19:00Z",
          "isCA": false
        },
        {
          "subject": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
          "issuer": "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
          "notBefore": "2020-08-13T00:00:42Z",
          "notAfter": "2027-09-30T00:00:42Z",
          "isCA": true
        },
        {
          "subject": "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
          "issuer": "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE",
          "notBefore": "2020-06-19T00:00:42Z",
          "notAfter": "2028-01-28T00:00:42Z",
          "isCA": true
        }
      ],
      "cipherSuite": 4865,
      "negotiatedProto": "h2",
      "serverName": "www.google.com"
    }
  ],
  "httpRequests": [
    {
      "traceID": "tid-2",
      "tcpConn": "tid-8",
      "protoMajor": 2,
      "protoMinor": 0,
      "reqSentAt": "+72ms",
      "reqMethod": "GET",
      "reqURL": "https://www.google.com/",
      "reqContentLen": 0,
      "respRecvAt": "+239ms",
      "respStatusCode": 200,
      "RespContentLen": 15381
    }
  ]
}
```

[http-client]: https://pkg.go.dev/net/http#Client
[http-client-do]: https://pkg.go.dev/net/http#Client.Do
[rfc6555]: https://www.rfc-editor.org/rfc/rfc6555
[error-wrap]: https://pkg.go.dev/errors#Unwrap
[http-transport]: https://pkg.go.dev/net/http#Transport
[context]: https://pkg.go.dev/context
[wireshark]: https://www.wireshark.org/
[round-tripper]: https://pkg.go.dev/net/http#RoundTripper
[oauth2-transp]: https://pkg.go.dev/golang.org/x/oauth2#Transport
