package chain

import (
	"path/filepath"
	"testing"

	"github.com/Camgirlsponsor/turboshake256-1/internal/dfpow"
)

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
	if got := RequiredDifficulty(anchor, 1, late); got != GenesisDifficulty-1 {
		t.Fatalf("late %d", got)
	}
	early := onTime - HalfLife
	if got := RequiredDifficulty(anchor, 1, early); got != GenesisDifficulty+1 {
		t.Fatalf("early %d", got)
	}
	if got := RequiredDifficulty(anchor, 1, anchor+10_000); got != MinDifficulty {
		t.Fatalf("clamp low %d", got)
	}
	if got := RequiredDifficulty(anchor, 50, anchor+1); got != MaxDifficulty {
		t.Fatalf("clamp high %d", got)
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
	anchor := uint32(1_800_000_000)
	clock := anchor
	c, err := New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	genesisEpoch := GenesisEpoch()
	if string(EpochSeed(c.blocks, 0)) != string(genesisEpoch[:]) {
		t.Fatal("height 0 epoch")
	}
	for height := uint64(1); height <= EpochLength; height++ {
		clock = anchor + uint32(height)
		if _, _, err := c.Mine("epoch", 1); err != nil {
			t.Fatal(err)
		}
	}
	boundary := c.Blocks()[EpochLength]
	if boundary.Height != EpochLength {
		t.Fatalf("height %d", boundary.Height)
	}
	seed := EpochSeed(c.blocks, EpochLength)
	prev := c.blocks[EpochLength-1].Hash
	if string(seed) != string(prev[:]) {
		t.Fatal("epoch seed is not the last hash of the previous epoch")
	}
	if string(seed) == string(genesisEpoch[:]) {
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
}
