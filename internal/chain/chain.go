// Package chain is a single-node DFPoW prototype.
//
// It uses the draft header and the draft epoch rule. The retarget is ASERT
// on the integer difficulty ladder: each step of d is a factor of two in
// work. Ideal interval, half-life, epoch length, and the difficulty clamp
// are prototype parameters so a local demo can move. The write-up's
// recommended epoch for a longer-lived chain is 128 blocks.
package chain

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"github.com/Camgirlsponsor/turboshake256-1/internal/dfpow"
)

const (
	EpochLength       = 8
	IdealBlockTime    = 4
	HalfLife          = 16
	GenesisDifficulty = 10
	MinDifficulty     = 8
	MaxDifficulty     = 16
	Version           = 1
	FutureLimit       = 2 * 60 * 60
	Coin              = 100_000_000
	Subsidy           = 50 * Coin
)

var (
	chainID = func() [16]byte {
		var id [16]byte
		copy(id[:], "dfpow-proto-v01")
		return id
	}()
	genesisEpoch = func() [32]byte {
		var seed [32]byte
		copy(seed[:], "DFPoW-prototype-epoch-seed!!!!!")
		return seed
	}()
	domainTxid   = tag16("DFPW-TXID-v01")
	domainMerkle = tag16("DFPW-MERKLE-v01")
	domainAcct   = tag16("DFPW-ACCT-v01")
)

func tag16(label string) [16]byte {
	var out [16]byte
	copy(out[:], label)
	return out
}

// Block is one confirmed header plus the coinbase it commits to.
type Block struct {
	Height     uint64
	Time       uint32
	Difficulty uint32
	Nonce      uint64
	ExtraNonce uint64
	Note       string
	Amount     uint64
	Header     []byte
	Hash       [32]byte
	Parent     [32]byte
	Merkle     [32]byte
}

// Chain is an in-memory canonical chain guarded by mu.
type Chain struct {
	mu       sync.Mutex
	blocks   []Block
	work     *big.Int
	dataset  []uint32
	dataSeed [32]byte
	haveData bool
	path     string
	now      func() uint32
}

// New starts a chain whose genesis timestamp is now.
func New(now func() uint32) (*Chain, error) {
	if now == nil {
		now = func() uint32 { return uint32(time.Now().Unix()) }
	}
	c := &Chain{work: big.NewInt(0), now: now}
	if err := c.mineGenesis(); err != nil {
		return nil, err
	}
	if err := c.validate(c.blocks[0], nil, c.blocks[0].Time); err != nil {
		return nil, err
	}
	return c, nil
}

// Open loads a chain file, or creates one when path does not exist.
func Open(path string) (*Chain, error) {
	now := func() uint32 { return uint32(time.Now().Unix()) }
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		c, err := New(now)
		if err != nil {
			return nil, err
		}
		c.path = path
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.saveLocked(); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	loaded, err := decode(raw, now)
	if err != nil {
		return nil, err
	}
	loaded.path = path
	return loaded, nil
}

func (c *Chain) mineGenesis() error {
	stamp := c.now()
	block, _, err := c.mineOn(nil, stamp, "genesis", 1)
	if err != nil {
		return err
	}
	c.blocks = []Block{block}
	c.work = dfpowWork(block.Difficulty)
	return nil
}

// Tip returns a copy of the latest block.
func (c *Chain) Tip() Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.blocks[len(c.blocks)-1]
}

// Blocks returns a copy of the chain, oldest first.
func (c *Chain) Blocks() []Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Block, len(c.blocks))
	copy(out, c.blocks)
	return out
}

// Work is the sum of 2^difficulty over the chain.
func (c *Chain) Work() *big.Int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return new(big.Int).Set(c.work)
}

// EpochSeed is the dataset seed for a block at height.
func EpochSeed(blocks []Block, height uint64) []byte {
	if height < EpochLength {
		return genesisEpoch[:]
	}
	start := height - height%EpochLength
	return blocks[start-1].Hash[:]
}

// RequiredDifficulty is the integer ASERT difficulty for a block at height
// with the given timestamp. Genesis is the anchor.
func RequiredDifficulty(genesisTime uint32, height uint64, timestamp uint32) uint32 {
	if height == 0 {
		return GenesisDifficulty
	}
	elapsed := int64(timestamp) - int64(genesisTime)
	scheduled := int64(height) * IdealBlockTime
	delta := divRoundHalfAway(elapsed-scheduled, HalfLife)
	d := int64(GenesisDifficulty) - delta
	if d < MinDifficulty {
		d = MinDifficulty
	}
	if d > MaxDifficulty {
		d = MaxDifficulty
	}
	return uint32(d)
}

func divRoundHalfAway(n, d int64) int64 {
	if n >= 0 {
		return (n + d/2) / d
	}
	return -((-n + d/2) / d)
}

func dfpowWork(difficulty uint32) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(difficulty))
}

// Account derives a prototype account id from a miner name.
// There are no signatures. The name is a label, not a key.
func Account(name string) [32]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write(domainAcct[:])
	_, _ = h.Write([]byte(name))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func coinbaseBytes(height, extra uint64, note string, amount uint64, address [32]byte) []byte {
	rawNote := []byte(note)
	if len(rawNote) > 64 {
		rawNote = rawNote[:64]
	}
	buf := make([]byte, 4+8+8+2+len(rawNote)+32+8)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	binary.LittleEndian.PutUint64(buf[4:12], height)
	binary.LittleEndian.PutUint64(buf[12:20], extra)
	binary.LittleEndian.PutUint16(buf[20:22], uint16(len(rawNote)))
	copy(buf[22:], rawNote)
	off := 22 + len(rawNote)
	copy(buf[off:off+32], address[:])
	binary.LittleEndian.PutUint64(buf[off+32:], amount)
	return buf
}

func txid(payload []byte) [32]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write(domainTxid[:])
	_, _ = h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func merkleRoot(ids [][32]byte) [32]byte {
	level := append([][32]byte(nil), ids...)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := blake3.New(32, nil)
			_, _ = h.Write(domainMerkle[:])
			_, _ = h.Write(level[i][:])
			_, _ = h.Write(level[i+1][:])
			copy(next[i/2][:], h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

func (c *Chain) datasetFor(epoch []byte) ([]uint32, error) {
	var key [32]byte
	copy(key[:], epoch)
	if c.haveData && c.dataSeed == key {
		return c.dataset, nil
	}
	data, err := dfpow.BuildDataset(chainID[:], epoch)
	if err != nil {
		return nil, err
	}
	c.dataset = data
	c.dataSeed = key
	c.haveData = true
	return data, nil
}

// Mine extends the tip. workers is the nonce search width; values below 1
// use one worker.
func (c *Chain) Mine(note string, workers int) (Block, Stats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parent := &c.blocks[len(c.blocks)-1]
	stamp := c.now()
	if stamp <= parent.Time {
		if parent.Time == ^uint32(0) {
			return Block{}, Stats{}, errors.New("chain: timestamp overflow")
		}
		stamp = parent.Time + 1
	}
	block, stats, err := c.mineOn(parent, stamp, note, workers)
	if err != nil {
		return Block{}, Stats{}, err
	}
	if err := c.validate(block, parent, stamp); err != nil {
		return Block{}, Stats{}, err
	}
	c.blocks = append(c.blocks, block)
	c.work.Add(c.work, dfpowWork(block.Difficulty))
	if c.path != "" {
		if err := c.saveLocked(); err != nil {
			return Block{}, Stats{}, err
		}
	}
	return block, stats, nil
}

func (c *Chain) mineOn(parent *Block, stamp uint32, note string, workers int) (Block, Stats, error) {
	note = trimNote(note)
	if note == "" {
		note = "miner"
	}
	height := uint64(0)
	var prev [32]byte
	genesisTime := stamp
	if parent != nil {
		height = parent.Height + 1
		prev = parent.Hash
		genesisTime = c.blocks[0].Time
	}
	difficulty := RequiredDifficulty(genesisTime, height, stamp)
	if uint64(stamp) > uint64(c.now())+FutureLimit {
		return Block{}, Stats{}, errors.New("chain: timestamp is too far ahead")
	}
	epoch := genesisEpoch[:]
	if parent != nil {
		epoch = EpochSeed(c.blocks, height)
	}
	address := Account(note)
	extra := uint64(0)
	dataset, err := c.datasetFor(epoch)
	if err != nil {
		return Block{}, Stats{}, err
	}
	var (
		header []byte
		nonce  uint64
		digest [32]byte
		tries  uint64
		root   [32]byte
	)
	start := time.Now()
	for attempt := 0; attempt < 4; attempt++ {
		payload := coinbaseBytes(height, extra, note, Subsidy, address)
		root = merkleRoot([][32]byte{txid(payload)})
		header, err = dfpow.MakeHeader(Version, prev[:], root[:], stamp, difficulty, 0)
		if err != nil {
			return Block{}, Stats{}, err
		}
		var found bool
		nonce, digest, tries, found = search(chainID[:], epoch, header, difficulty, dataset, workers)
		if found {
			break
		}
		extra++
	}
	if !dfpow.MeetsTarget(digest[:], difficulty) {
		return Block{}, Stats{}, errors.New("chain: search did not find a nonce")
	}
	binary.LittleEndian.PutUint64(header[76:], nonce)
	return Block{
		Height:     height,
		Time:       stamp,
		Difficulty: difficulty,
		Nonce:      nonce,
		ExtraNonce: extra,
		Note:       trimNote(note),
		Amount:     Subsidy,
		Header:     header,
		Hash:       digest,
		Parent:     prev,
		Merkle:     root,
	}, Stats{Attempts: tries, Elapsed: time.Since(start)}, nil
}

func trimNote(note string) string {
	raw := []byte(note)
	if len(raw) > 64 {
		raw = raw[:64]
	}
	return string(raw)
}

func (c *Chain) validate(block Block, parent *Block, now uint32) error {
	if len(block.Header) != dfpow.HeaderBytes {
		return errors.New("chain: header length")
	}
	version, stamp, difficulty, nonce, prev, merkle, err := dfpow.HeaderFields(block.Header)
	if err != nil {
		return err
	}
	if version != Version {
		return errors.New("chain: version")
	}
	if stamp != block.Time || difficulty != block.Difficulty || nonce != block.Nonce {
		return errors.New("chain: header fields do not match the block")
	}
	if block.Amount != Subsidy {
		return errors.New("chain: subsidy")
	}
	genesisTime := block.Time
	if parent == nil {
		if block.Height != 0 {
			return errors.New("chain: genesis height")
		}
		var zero [32]byte
		if !bytesEqual(prev, zero[:]) {
			return errors.New("chain: genesis parent")
		}
		if difficulty != GenesisDifficulty {
			return errors.New("chain: genesis difficulty")
		}
	} else {
		if block.Height != parent.Height+1 {
			return errors.New("chain: height")
		}
		if !bytesEqual(prev, parent.Hash[:]) {
			return errors.New("chain: parent hash")
		}
		if stamp <= parent.Time {
			return errors.New("chain: timestamp does not advance")
		}
		genesisTime = c.blocks[0].Time
		want := RequiredDifficulty(genesisTime, block.Height, stamp)
		if difficulty != want {
			return fmt.Errorf("chain: difficulty %d, required %d", difficulty, want)
		}
	}
	if uint64(stamp) > uint64(now)+FutureLimit {
		return errors.New("chain: timestamp is too far ahead")
	}
	address := Account(block.Note)
	payload := coinbaseBytes(block.Height, block.ExtraNonce, block.Note, block.Amount, address)
	root := merkleRoot([][32]byte{txid(payload)})
	if root != block.Merkle || !bytesEqual(merkle, root[:]) {
		return errors.New("chain: merkle root")
	}
	epoch := genesisEpoch[:]
	if parent != nil {
		epoch = EpochSeed(c.blocks, block.Height)
	}
	dataset, err := c.datasetFor(epoch)
	if err != nil {
		return err
	}
	got, err := dfpow.Eval(chainID[:], epoch, block.Header, dataset)
	if err != nil {
		return err
	}
	if got.Digest != block.Hash || !dfpow.MeetsTarget(got.Digest[:], difficulty) {
		return errors.New("chain: proof of work")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Stats describes one successful search.
type Stats struct {
	Attempts uint64
	Elapsed  time.Duration
}

type fileBlock struct {
	Height     uint64 `json:"height"`
	Header     string `json:"header"`
	Note       string `json:"note"`
	Amount     uint64 `json:"amount"`
	ExtraNonce uint64 `json:"extra_nonce"`
	Hash       string `json:"hash"`
}

type fileChain struct {
	ChainID string      `json:"chain_id"`
	Blocks  []fileBlock `json:"blocks"`
}

func (c *Chain) saveLocked() error {
	if c.path == "" {
		return nil
	}
	payload := fileChain{ChainID: hex.EncodeToString(chainID[:]), Blocks: make([]fileBlock, len(c.blocks))}
	for i, block := range c.blocks {
		payload.Blocks[i] = fileBlock{
			Height:     block.Height,
			Header:     hex.EncodeToString(block.Header),
			Note:       block.Note,
			Amount:     block.Amount,
			ExtraNonce: block.ExtraNonce,
			Hash:       hex.EncodeToString(block.Hash[:]),
		}
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func decode(raw []byte, now func() uint32) (*Chain, error) {
	var payload fileChain
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	gotID, err := hex.DecodeString(payload.ChainID)
	if err != nil || len(gotID) != 16 || !bytesEqual(gotID, chainID[:]) {
		return nil, errors.New("chain: file is for a different chain id")
	}
	if len(payload.Blocks) == 0 {
		return nil, errors.New("chain: empty file")
	}
	c := &Chain{work: big.NewInt(0), now: now, blocks: make([]Block, 0, len(payload.Blocks))}
	for i, stored := range payload.Blocks {
		header, err := hex.DecodeString(stored.Header)
		if err != nil {
			return nil, err
		}
		hashRaw, err := hex.DecodeString(stored.Hash)
		if err != nil || len(hashRaw) != 32 {
			return nil, errors.New("chain: bad block hash")
		}
		_, stamp, difficulty, nonce, prev, merkle, err := dfpow.HeaderFields(header)
		if err != nil {
			return nil, err
		}
		var block Block
		block.Height = stored.Height
		block.Time = stamp
		block.Difficulty = difficulty
		block.Nonce = nonce
		block.ExtraNonce = stored.ExtraNonce
		block.Note = stored.Note
		block.Amount = stored.Amount
		block.Header = header
		copy(block.Hash[:], hashRaw)
		copy(block.Parent[:], prev)
		copy(block.Merkle[:], merkle)
		var parent *Block
		checkNow := stamp
		if i == 0 {
			if now != nil && now() > checkNow {
				checkNow = now()
			}
		} else {
			parent = &c.blocks[i-1]
			checkNow = stamp
			if now != nil && now() > checkNow {
				checkNow = now()
			}
		}
		if err := c.validate(block, parent, checkNow); err != nil {
			return nil, fmt.Errorf("chain: block %d: %w", stored.Height, err)
		}
		c.blocks = append(c.blocks, block)
		c.work.Add(c.work, dfpowWork(block.Difficulty))
	}
	return c, nil
}

// ChainID is the 16-byte prototype network id.
func ChainID() [16]byte { return chainID }

// GenesisEpoch is the dataset seed used before the first epoch boundary.
func GenesisEpoch() [32]byte { return genesisEpoch }

// RandomNote is a short default miner label.
func RandomNote() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
