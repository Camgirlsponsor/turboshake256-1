package chain

import (
	"path/filepath"
	"testing"

	"github.com/Camgirlsponsor/turboshake256-1/internal/dfpow"
)

func TestPublishedGenesis(t *testing.T) {
	c, err := New(func() uint32 { return GenesisTime })
	if err != nil {
		t.Fatal(err)
	}
	g := c.Blocks()[0]
	const want = "0042f864209999723f97c93e591355e4b38ddbe58a1db45ff144e4ec6cfd3318"
	if hexHash(g.Hash) != want {
		t.Fatalf("genesis %s nonce %d", hexHash(g.Hash), g.Nonce)
	}
	if g.Time != GenesisTime || g.Note != "genesis" || g.Difficulty != GenesisDifficulty {
		t.Fatalf("genesis fields %+v", g)
	}
	if g.Txs[0].Pubkey != genesisPub {
		t.Fatal("genesis coinbase address")
	}
	again, err := New(func() uint32 { return GenesisTime + 10 })
	if err != nil {
		t.Fatal(err)
	}
	if again.Blocks()[0].Hash != g.Hash {
		t.Fatal("genesis was not stable")
	}
}

func hexHash(h [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

func TestRequiredDifficulty(t *testing.T) {
	const anchor = uint32(1_700_000_000)
	if got := RequiredDifficulty(anchor, 0, anchor); got != GenesisDifficulty {
		t.Fatalf("genesis %d", got)
	}
	onTime := anchor + IdealBlockTime
	if got := RequiredDifficulty(anchor, 1, onTime); got != GenesisDifficulty {
		t.Fatalf("on time %d", got)
	}
	late := onTime + HalfLife
	if got := RequiredDifficulty(anchor, 1, late); got != MinDifficulty {
		t.Fatalf("late %d", got)
	}
	early := onTime - HalfLife
	if got := RequiredDifficulty(anchor, 1, early); got != GenesisDifficulty+1 {
		t.Fatalf("early %d", got)
	}
	if got := RequiredDifficulty(anchor, 1, anchor+10_000); got != MinDifficulty {
		t.Fatalf("clamp low %d", got)
	}
	if got := RequiredDifficulty(anchor, 30_000, anchor+1); got != MaxDifficulty {
		t.Fatalf("clamp high %d", got)
	}
}

func TestSubsidyAndSupply(t *testing.T) {
	if got := SubsidyAt(0); got != InitialSubsidy {
		t.Fatalf("genesis subsidy %d", got)
	}
	if got := SubsidyAt(HalvingInterval); got != InitialSubsidy/2 {
		t.Fatalf("first halving %d", got)
	}
	if got := SubsidyAt(HalvingInterval * 2); got != InitialSubsidy/4 {
		t.Fatalf("second halving %d", got)
	}
	if got := SubsidyAt(63 * HalvingInterval); got != 0 {
		t.Fatalf("tail subsidy %d", got)
	}
	if got := Supply(0); got != InitialSubsidy {
		t.Fatalf("supply genesis %d", got)
	}
	if got := Supply(HalvingInterval - 1); got != InitialSubsidy*HalvingInterval {
		t.Fatalf("supply era %d", got)
	}
}

func TestMineLinkAndReject(t *testing.T) {
	anchor := uint32(1_700_000_000)
	clock := anchor
	c, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	genesis := c.Tip()
	if genesis.Height != 0 || genesis.Difficulty != GenesisDifficulty {
		t.Fatalf("genesis %+v", genesis)
	}
	if !dfpow.MeetsTarget(genesis.Hash[:], genesis.Difficulty) {
		t.Fatal("genesis pow")
	}
	clock = anchor + 1
	next, stats, err := c.Mine("alice", 1)
	if err != nil {
		t.Fatal(err)
	}
	if next.Height != 1 || next.Parent != genesis.Hash || next.Note != "alice" {
		t.Fatalf("block %+v", next)
	}
	if stats.Attempts == 0 {
		t.Fatal("no attempts recorded")
	}
	if next.Difficulty != RequiredDifficulty(anchor, 1, clock) {
		t.Fatalf("difficulty %d", next.Difficulty)
	}
	work := c.Work()
	want := dfpowWork(genesis.Difficulty)
	want.Add(want, dfpowWork(next.Difficulty))
	if work.Cmp(want) != 0 {
		t.Fatalf("work %s want %s", work, want)
	}

	bad := next
	bad.Header = append([]byte(nil), next.Header...)
	bad.Header[80] ^= 0x01
	bad.Nonce = next.Nonce ^ (1 << 32)
	parent := c.blocks[0]
	if err := c.validate(bad, &parent, bad.Time); err == nil {
		t.Fatal("tampered nonce was accepted")
	}
}

func TestEpochChanges(t *testing.T) {
	c, err := New(func() uint32 { return GenesisTime })
	if err != nil {
		t.Fatal(err)
	}
	epoch := GenesisEpoch()
	if string(EpochSeed(c.blocks, 0)) != string(epoch[:]) {
		t.Fatal("height 0 epoch")
	}
	if string(EpochSeed(c.blocks, EpochLength-1)) != string(epoch[:]) {
		t.Fatal("epoch should cover the first 128 blocks")
	}
	blocks := make([]Block, EpochLength)
	for i := range blocks {
		blocks[i].Height = uint64(i)
		blocks[i].Hash[0] = byte(i + 1)
		blocks[i].Hash[1] = 0xab
	}
	seed := EpochSeed(blocks, EpochLength)
	prev := blocks[EpochLength-1].Hash
	if string(seed) != string(prev[:]) {
		t.Fatal("epoch seed is not the last hash of the previous epoch")
	}
	if string(seed) == string(epoch[:]) {
		t.Fatal("epoch did not change")
	}
}

func TestPersist(t *testing.T) {
	anchor := uint32(1_700_000_000)
	clock := anchor
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	c, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	c.path = path
	clock = anchor + 1
	if _, _, err := c.Mine("bob", 1); err != nil {
		t.Fatal(err)
	}
	if err := c.saveLocked(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Tip().Hash != c.Tip().Hash || len(loaded.Blocks()) != 2 {
		t.Fatal("reload mismatch")
	}
	if bal, _ := loaded.Balance(c.Payee()); bal != 0 {
		t.Fatalf("reward should still be immature, balance %d", bal)
	}
	if immature, unlocks := loaded.Immature(c.Payee()); immature != InitialSubsidy || unlocks != 1+uint64(CoinbaseMaturity) {
		t.Fatalf("immature %d unlocks %d", immature, unlocks)
	}
}

func TestTransferUpdatesBalances(t *testing.T) {
	anchor := uint32(1_700_000_000)
	clock := anchor
	c, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	miner := c.Payee()
	if bal, nonce := c.Balance(miner); bal != 0 || nonce != 0 {
		t.Fatalf("miner starts with balance %d nonce %d", bal, nonce)
	}
	if immature, _ := c.Immature(genesisPub); immature != InitialSubsidy {
		t.Fatalf("genesis reward %d", immature)
	}
	for {
		bal, _ := c.Balance(miner)
		if bal >= Coin {
			break
		}
		clock++
		if _, _, err := c.Mine("fund", 1); err != nil {
			t.Fatal(err)
		}
	}
	bob, _, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := SignTransfer(c.SigningKey(), bob, Coin, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Submit(tx); err != nil {
		t.Fatal(err)
	}
	if len(c.Mempool()) != 1 {
		t.Fatal("mempool")
	}
	clock = anchor + 1
	block, _, err := c.Mine("pay", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Txs) != 2 || block.Txs[1].ID != tx.ID {
		t.Fatalf("block txs %d", len(block.Txs))
	}
	if bal, _ := c.Balance(bob); bal != Coin {
		t.Fatalf("bob %d", bal)
	}
	if bal, nonce := c.Balance(miner); bal != 2*InitialSubsidy-Coin || nonce != 1 {
		t.Fatalf("miner balance %d nonce %d", bal, nonce)
	}
	if len(c.Mempool()) != 0 {
		t.Fatal("mempool was not cleared")
	}
	if err := c.Submit(tx); err == nil {
		t.Fatal("replayed transaction")
	}
	over, err := SignTransfer(c.SigningKey(), bob, 1000*Coin, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Submit(over); err == nil {
		t.Fatal("overspend")
	}
	bad, err := SignTransfer(c.SigningKey(), bob, Coin, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	bad.Signature[0] ^= 0xff
	body := transferBody(bad.Pubkey, bad.Recipient, bad.Amount, bad.Fee, bad.Nonce)
	bad.ID = txid(transferWire(body, bad.Signature))
	if err := c.Submit(bad); err == nil {
		t.Fatal("bad signature")
	}
}

func TestHeavierChainReplacesTip(t *testing.T) {
	anchor := uint32(1_700_000_000)
	clock := anchor
	local, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := local.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	other, err := decode(raw, func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	clock = anchor + 1
	if _, _, err := other.Mine("a", 1); err != nil {
		t.Fatal(err)
	}
	clock = anchor + 2
	if _, _, err := other.Mine("b", 1); err != nil {
		t.Fatal(err)
	}
	adopted, err := local.Consider(mustBytes(t, other))
	if err != nil || !adopted {
		t.Fatalf("adopted %v %v", adopted, err)
	}
	if local.Tip().Hash != other.Tip().Hash || local.Work().Cmp(other.Work()) != 0 {
		t.Fatal("tip did not follow the heavier chain")
	}
	short, err := decode(raw, func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	adopted, err = local.Consider(mustBytes(t, short))
	if err != nil || adopted {
		t.Fatalf("shorter chain adopted %v %v", adopted, err)
	}
	if local.Tip().Hash != other.Tip().Hash {
		t.Fatal("tip changed for less work")
	}
}

func TestAdoptConnectsBlocks(t *testing.T) {
	anchor := uint32(GenesisTime)
	clock := anchor
	local, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if local.Tip().Hash != other.Tip().Hash {
		t.Fatal("nodes did not share the published genesis")
	}
	clock = anchor + 1
	if _, _, err := other.Mine("a", 1); err != nil {
		t.Fatal(err)
	}
	clock = anchor + 2
	if _, _, err := other.Mine("b", 1); err != nil {
		t.Fatal(err)
	}
	adopted, err := local.Adopt(other.Blocks()[1:])
	if err != nil || !adopted {
		t.Fatalf("adopted %v %v", adopted, err)
	}
	if local.Tip().Hash != other.Tip().Hash {
		t.Fatal("tip did not follow the adopted blocks")
	}
	adopted, err = local.Adopt(other.Blocks()[1:])
	if err != nil || adopted {
		t.Fatalf("equal work adopted %v %v", adopted, err)
	}
}

func mustBytes(t *testing.T, c *Chain) []byte {
	t.Helper()
	raw, err := c.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
