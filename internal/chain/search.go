package chain

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/Camgirlsponsor/turboshake256-1/internal/dfpow"
)

// searchLimit is the per-worker cap before the caller rotates the coinbase
// extra nonce and tries a fresh merkle root.
const searchLimit = 1 << 20

func search(chainID, epoch, header []byte, difficulty uint32, dataset []uint32, workers int) (uint64, [32]byte, uint64, bool) {
	if workers < 1 {
		workers = 1
	}
	type hit struct {
		nonce  uint64
		digest [32]byte
	}
	hits := make(chan hit, workers)
	var stop atomic.Bool
	var attempts atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(start uint64) {
			defer wg.Done()
			local := make([]byte, len(header))
			copy(local, header)
			var n uint64
			stride := uint64(workers)
			for nonce := start; n < searchLimit; nonce += stride {
				if stop.Load() {
					attempts.Add(n)
					return
				}
				binary.LittleEndian.PutUint64(local[76:], nonce)
				res, err := dfpow.Eval(chainID, epoch, local, dataset)
				n++
				if err != nil {
					attempts.Add(n)
					return
				}
				if dfpow.MeetsTarget(res.Digest[:], difficulty) {
					attempts.Add(n)
					stop.Store(true)
					hits <- hit{nonce: nonce, digest: res.Digest}
					return
				}
			}
			attempts.Add(n)
		}(uint64(w))
	}
	go func() {
		wg.Wait()
		close(hits)
	}()
	found, ok := <-hits
	stop.Store(true)
	wg.Wait()
	if !ok {
		return 0, [32]byte{}, attempts.Load(), false
	}
	return found.nonce, found.digest, attempts.Load(), true
}
