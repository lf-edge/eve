//go:build artificialleak

package immcore

import (
	"math/rand"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cmd/watcher"
)

func LeakLinear(block int, every time.Duration) [][]byte {
	_ = every // just to mark as used
	var chunks [][]byte
	ticker := time.NewTicker(every)
	for range ticker.C {
		b := make([]byte, block)
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
		chunks = append(chunks, b)
		if watcher.log != nil {
			watcher.log.Noticef("Leaked another %d bytes, total %.2f Mb\n", block, float64(len(chunks)*block)/1024/1024)
		}
	}
	return chunks
}

func init() {
	go LeakLinear(1024*2, 10*time.Second) // 2KB every 10s
}
