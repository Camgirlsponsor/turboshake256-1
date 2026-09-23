// Package chain is the DFPoW prototype ledger.
//
// Blocks use the draft header, the draft epoch rule, and ASERT on the
// integer difficulty ladder. Payments are ed25519 transfers against account
// balances. Peers exchange chain files; the chain with more work wins.
package chain

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

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
	fileVersion       = 2
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
)

func tag16(label string) [16]byte {
	var out [16]byte
	copy(out[:], label)
	return out
}

// Block is one confirmed header and the transactions it commits to.
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
	Txs        []Tx
}

// Chain is the canonical chain guarded by mu.
type Chain struct {
	mu       sync.Mutex
	blocks   []Block
	work     *big.Int
	state    map[[32]byte]acct
	mempool  []Tx
	dataset  []uint32
	dataSeed [32]byte
	haveData bool
	path     string
	payee    [32]byte
	signer   ed25519.PrivateKey
	now      func() uint32
}

// New starts an in-memory chain and keeps the genesis key so tests can spend it.
func New(now func() uint32) (*Chain, error) {
	pub, priv, err := NewKey()
	if err != nil {
		return nil, err
	}
	return newChain(now, pub, priv)
}

// Create writes a new chain file whose genesis subsidy pays pub.
func Create(path string, pub [32]byte, priv ed25519.PrivateKey, now func() uint32) (*Chain, error) {
	c, err := newChain(now, pub, priv)
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

func newChain(now func() uint32, pub [32]byte, priv ed25519.PrivateKey) (*Chain, error) {
	if now == nil {
		now = func() uint32 { return uint32(time.Now().Unix()) }
	}
	c := &Chain{
		work:   big.NewInt(0),
		state:  map[[32]byte]acct{},
		now:    now,
		payee:  pub,
		signer: priv,
	}
	if err := c.mineGenesis(); err != nil {
		return nil, err
	}
	parentTime := c.blocks[0].Time
	if err := c.validate(c.blocks[0], nil, parentTime); err != nil {
		return nil, err
	}
	state, err := applyBlock(map[[32]byte]acct{}, c.blocks[0])
	if err != nil {
		return nil, err
	}
	c.state = state
	return c, nil
}

// Open loads a chain file. The file must already exist.
func Open(path string) (*Chain, error) {
	now := func() uint32 { return uint32(time.Now().Unix()) }
	raw, err := os.ReadFile(path)
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
	block, _, err := c.mineOn(nil, nil, stamp, "genesis", c.payee, map[[32]byte]acct{}, nil, nil, 1)
	if err != nil {
		return err
	}
	c.blocks = []Block{block}
	c.work = dfpowWork(block.Difficulty)
	return nil
}

// Payee is the address that receives the next coinbase.
func (c *Chain) Payee() [32]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payee
}

// SetPayee chooses who receives the next coinbase.
func (c *Chain) SetPayee(pub [32]byte) {
	c.mu.Lock()
	c.payee = pub
	c.mu.Unlock()
}

// SigningKey returns the genesis key when this process created the chain.
func (c *Chain) SigningKey() ed25519.PrivateKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.signer) == 0 {
		return nil
	}
	out := make(ed25519.PrivateKey, len(c.signer))
	copy(out, c.signer)
	return out
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

// Balance reports the confirmed balance and the next transfer nonce.
func (c *Chain) Balance(pub [32]byte) (uint64, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.state[pub]
	return a.balance, a.nonce
}

// Mempool returns pending transfers in arrival order.
func (c *Chain) Mempool() []Tx {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Tx, len(c.mempool))
	copy(out, c.mempool)
	return out
}

// Submit accepts a signed transfer into the mempool.
func (c *Chain) Submit(tx Tx) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tx.Kind != kindTransfer {
		return errors.New("chain: only transfers enter the mempool")
	}
	if len(c.mempool) >= maxMempool {
		return errors.New("chain: mempool is full")
	}
	if c.knownTx(tx.ID) {
		return errors.New("chain: transaction already known")
	}
	picked := selectTransfers(c.state, append(append([]Tx{}, c.mempool...), tx), len(c.mempool)+1)
	for _, item := range picked {
		if item.ID == tx.ID {
			c.mempool = append(c.mempool, tx)
			return nil
		}
	}
	return errors.New("chain: transaction does not apply")
}

func (c *Chain) knownTx(id [32]byte) bool {
	for _, tx := range c.mempool {
		if tx.ID == id {
			return true
		}
	}
	for _, block := range c.blocks {
		for _, tx := range block.Txs {
			if tx.ID == id {
				return true
			}
		}
	}
	return false
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

// Mine extends the tip. The coinbase pays the current payee and any transfers
// that apply are included. workers is the nonce search width.
func (c *Chain) Mine(note string, workers int) (Block, Stats, error) {
	c.mu.Lock()
	parent := c.blocks[len(c.blocks)-1]
	blocks := append([]Block(nil), c.blocks...)
	mem := append([]Tx(nil), c.mempool...)
	state := cloneState(c.state)
	payee := c.payee
	stamp := c.now()
	if stamp <= parent.Time {
		if parent.Time == ^uint32(0) {
			c.mu.Unlock()
			return Block{}, Stats{}, errors.New("chain: timestamp overflow")
		}
		stamp = parent.Time + 1
	}
	epoch := EpochSeed(blocks, parent.Height+1)
	dataset, err := c.datasetFor(epoch)
	c.mu.Unlock()
	if err != nil {
		return Block{}, Stats{}, err
	}
	block, stats, err := c.mineOn(blocks, &parent, stamp, note, payee, state, mem, dataset, workers)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocks[len(c.blocks)-1].Hash != parent.Hash {
		return Block{}, Stats{}, errors.New("chain: tip moved")
	}
	if err := c.commit(block); err != nil {
		return Block{}, Stats{}, err
	}
	return block, stats, nil
}

func (c *Chain) mineOn(blocks []Block, parent *Block, stamp uint32, note string, payee [32]byte, state map[[32]byte]acct, mem []Tx, dataset []uint32, workers int) (Block, Stats, error) {
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
		genesisTime = blocks[0].Time
	}
	difficulty := RequiredDifficulty(genesisTime, height, stamp)
	if uint64(stamp) > uint64(c.now())+FutureLimit {
		return Block{}, Stats{}, errors.New("chain: timestamp is too far ahead")
	}
	epoch := genesisEpoch[:]
	if parent != nil {
		epoch = EpochSeed(blocks, height)
	}
	var err error
	if dataset == nil {
		dataset, err = c.datasetFor(epoch)
		if err != nil {
			return Block{}, Stats{}, err
		}
	}
	transfers := []Tx{}
	if parent != nil {
		transfers = selectTransfers(state, mem, maxTransfers)
	}
	var fees uint64
	for _, tx := range transfers {
		var overflow bool
		fees, overflow = add(fees, tx.Fee)
		if overflow {
			return Block{}, Stats{}, errors.New("chain: fee overflow")
		}
	}
	extra := uint64(0)
	var (
		header []byte
		nonce  uint64
		digest [32]byte
		tries  uint64
		root   [32]byte
		txs    []Tx
	)
	start := time.Now()
	for attempt := 0; attempt < 4; attempt++ {
		coinbase := coinbaseTx(height, extra, note, payee, fees)
		txs = append([]Tx{coinbase}, transfers...)
		ids := make([][32]byte, len(txs))
		for i, tx := range txs {
			ids[i] = tx.ID
		}
		root = merkleRoot(ids)
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
	coinbase := coinbaseTx(height, extra, note, payee, fees)
	txs[0] = coinbase
	return Block{
		Height:     height,
		Time:       stamp,
		Difficulty: difficulty,
		Nonce:      nonce,
		ExtraNonce: extra,
		Note:       note,
		Amount:     Subsidy,
		Header:     header,
		Hash:       digest,
		Parent:     prev,
		Merkle:     root,
		Txs:        txs,
	}, Stats{Attempts: tries, Elapsed: time.Since(start)}, nil
}

func (c *Chain) commit(block Block) error {
	parent := &c.blocks[len(c.blocks)-1]
	if err := c.validate(block, parent, block.Time); err != nil {
		return err
	}
	next, err := applyBlock(c.state, block)
	if err != nil {
		return err
	}
	c.state = next
	c.blocks = append(c.blocks, block)
	c.work.Add(c.work, dfpowWork(block.Difficulty))
	c.recheckMempool()
	return c.saveLocked()
}

func (c *Chain) recheckMempool() {
	included := map[[32]byte]bool{}
	for _, tx := range c.blocks[len(c.blocks)-1].Txs {
		included[tx.ID] = true
	}
	pending := make([]Tx, 0, len(c.mempool))
	for _, tx := range c.mempool {
		if !included[tx.ID] {
			pending = append(pending, tx)
		}
	}
	picked := selectTransfers(c.state, pending, maxMempool)
	have := map[[32]byte]bool{}
	for _, tx := range picked {
		have[tx.ID] = true
	}
	// A transfer whose nonce is still in the future stays queued so it can
	// apply once the earlier nonce confirms.
	for _, tx := range pending {
		if have[tx.ID] || verifyTransfer(tx) != nil {
			continue
		}
		if tx.Nonce > c.state[tx.Pubkey].nonce {
			picked = append(picked, tx)
			have[tx.ID] = true
		}
	}
	c.mempool = picked
}

func trimNote(note string) string {
	raw := []byte(note)
	if len(raw) > maxNoteLen {
		raw = raw[:maxNoteLen]
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
	ids := make([][32]byte, len(block.Txs))
	for i, tx := range block.Txs {
		ids[i] = tx.ID
	}
	root := merkleRoot(ids)
	if root != block.Merkle || !bytesEqual(merkle, root[:]) {
		return errors.New("chain: merkle root")
	}
	genesisTime := block.Time
	var prior []Block
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
		if len(c.blocks) == 0 {
			return errors.New("chain: missing genesis")
		}
		genesisTime = c.blocks[0].Time
		want := RequiredDifficulty(genesisTime, block.Height, stamp)
		if difficulty != want {
			return fmt.Errorf("chain: difficulty %d, required %d", difficulty, want)
		}
		prior = c.blocks
	}
	if uint64(stamp) > uint64(now)+FutureLimit {
		return errors.New("chain: timestamp is too far ahead")
	}
	base := map[[32]byte]acct{}
	if parent != nil {
		var err error
		base, err = replay(prior[:parent.Height+1])
		if err != nil {
			return err
		}
	}
	if _, err := applyBlock(base, block); err != nil {
		return err
	}
	epoch := genesisEpoch[:]
	if parent != nil {
		epoch = EpochSeed(prior, block.Height)
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

func replay(blocks []Block) (map[[32]byte]acct, error) {
	state := map[[32]byte]acct{}
	for _, block := range blocks {
		next, err := applyBlock(state, block)
		if err != nil {
			return nil, err
		}
		state = next
	}
	return state, nil
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

// Bytes is the chain file encoding.
func (c *Chain) Bytes() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.marshalLocked()
}

// Consider adopts raw when it is a valid chain with strictly more work.
func (c *Chain) Consider(raw []byte) (bool, error) {
	other, err := decode(raw, c.now)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if other.work.Cmp(c.work) <= 0 {
		return false, nil
	}
	c.blocks = other.blocks
	c.work = other.work
	c.state = other.state
	c.dataset = other.dataset
	c.dataSeed = other.dataSeed
	c.haveData = other.haveData
	c.recheckMempool()
	if err := c.saveLocked(); err != nil {
		return false, err
	}
	return true, nil
}

type fileTx struct {
	Kind      string `json:"kind"`
	Note      string `json:"note,omitempty"`
	Extra     uint64 `json:"extra_nonce,omitempty"`
	Pubkey    string `json:"pubkey"`
	To        string `json:"to,omitempty"`
	Amount    uint64 `json:"amount"`
	Fee       uint64 `json:"fee,omitempty"`
	Nonce     uint64 `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
	ID        string `json:"id"`
}

type fileBlock struct {
	Height uint64   `json:"height"`
	Header string   `json:"header"`
	Hash   string   `json:"hash"`
	Txs    []fileTx `json:"txs"`
}

type fileChain struct {
	Version int         `json:"version"`
	ChainID string      `json:"chain_id"`
	Blocks  []fileBlock `json:"blocks"`
}

func (c *Chain) saveLocked() error {
	if c.path == "" {
		return nil
	}
	raw, err := c.marshalLocked()
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (c *Chain) marshalLocked() ([]byte, error) {
	payload := fileChain{
		Version: fileVersion,
		ChainID: hex.EncodeToString(chainID[:]),
		Blocks:  make([]fileBlock, len(c.blocks)),
	}
	for i, block := range c.blocks {
		stored, err := encodeBlock(block)
		if err != nil {
			return nil, err
		}
		payload.Blocks[i] = stored
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func encodeBlock(block Block) (fileBlock, error) {
	txs := make([]fileTx, len(block.Txs))
	for i, tx := range block.Txs {
		item := fileTx{
			Pubkey: hex.EncodeToString(tx.Pubkey[:]),
			Amount: tx.Amount,
			Fee:    tx.Fee,
			Nonce:  tx.Nonce,
			ID:     hex.EncodeToString(tx.ID[:]),
		}
		switch tx.Kind {
		case kindCoinbase:
			item.Kind = "coinbase"
			item.Note = tx.Note
			item.Extra = tx.Extra
		case kindTransfer:
			item.Kind = "transfer"
			item.To = hex.EncodeToString(tx.Recipient[:])
			item.Signature = hex.EncodeToString(tx.Signature)
		default:
			return fileBlock{}, errors.New("chain: unknown tx kind")
		}
		txs[i] = item
	}
	return fileBlock{
		Height: block.Height,
		Header: hex.EncodeToString(block.Header),
		Hash:   hex.EncodeToString(block.Hash[:]),
		Txs:    txs,
	}, nil
}

func decode(raw []byte, now func() uint32) (*Chain, error) {
	var payload fileChain
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if payload.Version != fileVersion {
		return nil, errors.New("chain: unsupported chain file")
	}
	gotID, err := hex.DecodeString(payload.ChainID)
	if err != nil || len(gotID) != 16 || !bytesEqual(gotID, chainID[:]) {
		return nil, errors.New("chain: file is for a different chain id")
	}
	if len(payload.Blocks) == 0 {
		return nil, errors.New("chain: empty file")
	}
	c := &Chain{work: big.NewInt(0), now: now, state: map[[32]byte]acct{}}
	for i, stored := range payload.Blocks {
		block, err := decodeBlock(stored)
		if err != nil {
			return nil, err
		}
		var parent *Block
		checkNow := block.Time
		if now != nil && now() > checkNow {
			checkNow = now()
		}
		if i > 0 {
			parent = &c.blocks[i-1]
		}
		if err := c.validate(block, parent, checkNow); err != nil {
			return nil, fmt.Errorf("chain: block %d: %w", block.Height, err)
		}
		next, err := applyBlock(c.state, block)
		if err != nil {
			return nil, err
		}
		c.state = next
		c.blocks = append(c.blocks, block)
		c.work.Add(c.work, dfpowWork(block.Difficulty))
	}
	if len(c.blocks) > 0 {
		c.payee = c.blocks[len(c.blocks)-1].Txs[0].Pubkey
	}
	return c, nil
}

func decodeBlock(stored fileBlock) (Block, error) {
	header, err := hex.DecodeString(stored.Header)
	if err != nil {
		return Block{}, err
	}
	hashRaw, err := hex.DecodeString(stored.Hash)
	if err != nil || len(hashRaw) != 32 {
		return Block{}, errors.New("chain: bad block hash")
	}
	_, stamp, difficulty, nonce, prev, merkle, err := dfpow.HeaderFields(header)
	if err != nil {
		return Block{}, err
	}
	if len(stored.Txs) == 0 {
		return Block{}, errors.New("chain: block has no transactions")
	}
	txs := make([]Tx, len(stored.Txs))
	for i, item := range stored.Txs {
		tx, err := decodeTx(item)
		if err != nil {
			return Block{}, err
		}
		if tx.Kind == kindCoinbase {
			tx.Height = stored.Height
		}
		txs[i] = tx
	}
	var block Block
	block.Height = stored.Height
	block.Time = stamp
	block.Difficulty = difficulty
	block.Nonce = nonce
	block.ExtraNonce = txs[0].Extra
	block.Note = txs[0].Note
	block.Amount = txs[0].Amount
	block.Header = header
	copy(block.Hash[:], hashRaw)
	copy(block.Parent[:], prev)
	copy(block.Merkle[:], merkle)
	block.Txs = txs
	return block, nil
}

func decodeTx(item fileTx) (Tx, error) {
	pubRaw, err := hex.DecodeString(item.Pubkey)
	if err != nil || len(pubRaw) != 32 {
		return Tx{}, errors.New("chain: bad public key")
	}
	idRaw, err := hex.DecodeString(item.ID)
	if err != nil || len(idRaw) != 32 {
		return Tx{}, errors.New("chain: bad txid")
	}
	var tx Tx
	copy(tx.Pubkey[:], pubRaw)
	copy(tx.ID[:], idRaw)
	tx.Amount = item.Amount
	tx.Fee = item.Fee
	tx.Nonce = item.Nonce
	switch item.Kind {
	case "coinbase":
		tx.Kind = kindCoinbase
		tx.Note = item.Note
		tx.Extra = item.Extra
		tx.Height = 0
	case "transfer":
		tx.Kind = kindTransfer
		to, err := hex.DecodeString(item.To)
		if err != nil || len(to) != 32 {
			return Tx{}, errors.New("chain: bad recipient")
		}
		copy(tx.Recipient[:], to)
		sig, err := hex.DecodeString(item.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return Tx{}, errors.New("chain: bad signature")
		}
		tx.Signature = sig
	default:
		return Tx{}, errors.New("chain: unknown tx kind")
	}
	return tx, nil
}

// ChainID is the 16-byte prototype network id.
func ChainID() [16]byte { return chainID }

// GenesisEpoch is the dataset seed used before the first epoch boundary.
func GenesisEpoch() [32]byte { return genesisEpoch }

// MarshalTx encodes one transaction for peers.
func MarshalTx(tx Tx) ([]byte, error) {
	stored, err := encodeBlock(Block{Txs: []Tx{tx}})
	if err != nil || len(stored.Txs) != 1 {
		return nil, err
	}
	return json.Marshal(stored.Txs[0])
}

// UnmarshalTx decodes a transaction from MarshalTx.
func UnmarshalTx(raw []byte) (Tx, error) {
	var item fileTx
	if err := json.Unmarshal(raw, &item); err != nil {
		return Tx{}, err
	}
	return decodeTx(item)
}

// LookupTx finds a confirmed or mempool transaction.
// confirmed is false when the transaction is only in the mempool.
func (c *Chain) LookupTx(id [32]byte) (Tx, Block, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, block := range c.blocks {
		for _, tx := range block.Txs {
			if tx.ID == id {
				return tx, block, true, true
			}
		}
	}
	for _, tx := range c.mempool {
		if tx.ID == id {
			return tx, Block{}, false, true
		}
	}
	return Tx{}, Block{}, false, false
}

// FindTx scans confirmed transactions.
func (c *Chain) FindTx(id [32]byte) (Tx, Block, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, block := range c.blocks {
		for _, tx := range block.Txs {
			if tx.ID == id {
				return tx, block, true
			}
		}
	}
	return Tx{}, Block{}, false
}

// History returns confirmed transactions that touch pub, newest first.
func (c *Chain) History(pub [32]byte) []Tx {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Tx
	for i := len(c.blocks) - 1; i >= 0; i-- {
		for _, tx := range c.blocks[i].Txs {
			if tx.Pubkey == pub || tx.Recipient == pub {
				out = append(out, tx)
			}
		}
	}
	return out
}
