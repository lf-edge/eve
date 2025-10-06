// Copyright(c) 2025 Zededa, Inc.
// All rights reserved.

package nettraceStorage

import (
	"encoding/json"
	"fmt"
	"os"

	nt "github.com/lf-edge/eve-libs/nettrace"
	"go.etcd.io/bbolt"
)

// Bucket names (local to the sink; server does not persist)
const (
	bucketDials      = "dials"
	bucketHTTPReqs   = "httpReqs"
	bucketDNSQueries = "dnsQueries"
	bucketTLSTuns    = "tlsTuns"
	bucketTCPConns   = "tcpConns"
	bucketUDPConns   = "udpConns"
)

// BoltBatchSink offloads batches of netTrace data into BoltDB
// and supports exporting them into a single JSON file.
type BoltBatchSink struct {
	db   *bbolt.DB
	path string
}

// NewBoltBatchSink opens/creates the BoltDB file and initializes buckets.
func NewBoltBatchSink(dbPath string) (*BoltBatchSink, error) {
	db, err := bbolt.Open(dbPath, 0o666, nil)
	if err != nil {
		return nil, err
	}
	s := &BoltBatchSink{db: db, path: dbPath}
	if err := s.ensureBuckets(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// DeleteDBFile deletes the BoltDB file, based on session UUID
func (s *BoltBatchSink) DeleteDBFile() error {
	if s.db != nil {
		_ = s.db.Close()
	}
	return os.Remove(s.path)
}

// Close closes the BoltDB.
func (s *BoltBatchSink) Close() error {
	// i want first to check if db is nil, and then close
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Handler returns a nettrace.BatchCallback to pass into WithBatchOffload.
func (s *BoltBatchSink) Handler() nt.BatchCallback { return s.HandleBatch }

// HandleBatch persists a batch (upsert by TraceID). Safe to call concurrently.
func (s *BoltBatchSink) HandleBatch(b nt.BatchSnapshot) {
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		var err error
		if err = s.upsertDials(tx, b.Dials); err != nil {
			return err
		}
		if err = s.upsertHTTPReqs(tx, b.HTTPReqs); err != nil {
			return err
		}
		if err = s.upsertDNS(tx, b.DNSQueries); err != nil {
			return err
		}
		if err = s.upsertTLS(tx, b.TLSTunnels); err != nil {
			return err
		}
		if err = s.upsertTCP(tx, b.TCPConns); err != nil {
			return err
		}
		if err = s.upsertUDP(tx, b.UDPConns); err != nil {
			return err
		}
		return err
	})
}

// ExportToJSON writes one JSON file with everything persisted in Bbolt.
// Pass the meta you receive from server.GetTrace (which now returns only NetTraceMeta + pcaps).
func (s *BoltBatchSink) ExportToJSON(filePath string, meta nt.NetTrace) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	// open {
	if _, err := f.Write([]byte(`{"description":`)); err != nil {
		return err
	}
	if err := enc.Encode(meta.Description); err != nil {
		return err
	}
	if _, err := f.Write([]byte(`,"traceBeginAt":`)); err != nil {
		return err
	}
	if err := enc.Encode(meta.TraceBeginAt); err != nil {
		return err
	}
	if _, err := f.Write([]byte(`,"traceEndAt":`)); err != nil {
		return err
	}
	if err := enc.Encode(meta.TraceEndAt); err != nil {
		return err
	}

	// sections streamed straight from Bolt
	if err := s.streamBucketJSON(f, enc, `,"dials":[`, `]`, bucketDials); err != nil {
		return err
	}
	if err := s.streamBucketJSON(f, enc, `,"tcpConns":[`, `]`, bucketTCPConns); err != nil {
		return err
	}
	if err := s.streamBucketJSON(f, enc, `,"udpConns":[`, `]`, bucketUDPConns); err != nil {
		return err
	}
	if err := s.streamBucketJSON(f, enc, `,"dnsQueries":[`, `]`, bucketDNSQueries); err != nil {
		return err
	}
	if err := s.streamBucketJSON(f, enc, `,"httpRequests":[`, `]`, bucketHTTPReqs); err != nil {
		return err
	}
	if err := s.streamBucketJSON(f, enc, `,"tlsTunnels":[`, `]`, bucketTLSTuns); err != nil {
		return err
	}

	// close }
	if _, err := f.Write([]byte(`}`)); err != nil {
		return err
	}
	return nil
}

// ---------- internal helpers ----------

func (s *BoltBatchSink) ensureBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{
			bucketDials,
			bucketHTTPReqs,
			bucketDNSQueries,
			bucketTLSTuns,
			bucketTCPConns,
			bucketUDPConns,
		} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
}

func keyFor(id nt.TraceID) []byte { return []byte(fmt.Sprint(id)) }

func putJSON(tx *bbolt.Tx, bucket string, key []byte, v interface{}) error {
	b := tx.Bucket([]byte(bucket))
	if b == nil {
		var err error
		b, err = tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, data)
}

func (s *BoltBatchSink) upsertDials(tx *bbolt.Tx, items []nt.DialTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketDials, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltBatchSink) upsertHTTPReqs(tx *bbolt.Tx, items []nt.HTTPReqTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketHTTPReqs, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltBatchSink) upsertDNS(tx *bbolt.Tx, items []nt.DNSQueryTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketDNSQueries, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltBatchSink) upsertTLS(tx *bbolt.Tx, items []nt.TLSTunnelTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketTLSTuns, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltBatchSink) upsertTCP(tx *bbolt.Tx, items []nt.TCPConnTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketTCPConns, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltBatchSink) upsertUDP(tx *bbolt.Tx, items []nt.UDPConnTrace) error {
	for _, it := range items {
		if err := putJSON(tx, bucketUDPConns, keyFor(it.TraceID), it); err != nil {
			return err
		}
	}
	return nil
}

// streamBucketJSON re-encodes values so the output file is valid JSON.
func (s *BoltBatchSink) streamBucketJSON(f *os.File, enc *json.Encoder, prefix, suffix, bucket string) error {
	if _, err := f.Write([]byte(prefix)); err != nil {
		return err
	}
	first := true
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if !first {
				if _, err := f.Write([]byte(",")); err != nil {
					return err
				}
			}
			var data interface{}
			if err := json.Unmarshal(v, &data); err != nil {
				return err
			}
			if err := enc.Encode(data); err != nil {
				return err
			}
			first = false
			return nil
		})
	})
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(suffix)); err != nil {
		return err
	}
	return nil
}
