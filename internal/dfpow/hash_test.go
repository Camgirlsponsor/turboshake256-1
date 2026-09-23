package dfpow

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testHeader(t *testing.T, nonce uint64, difficulty, timestamp uint32) []byte {
	t.Helper()
	prev := make([]byte, 32)
	merkle := bytes.Repeat([]byte{0x11}, 32)
	h, err := MakeHeader(1, prev, merkle, timestamp, difficulty, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVectors(t *testing.T) {
	chainID := []byte("dfpow-test-v0.1\x00")
	epoch := make([]byte, 32)
	for i := range epoch {
		epoch[i] = byte(i)
	}
	dataset, err := BuildDataset(chainID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildDataset(chainID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(dataset) != DatasetWords {
		t.Fatalf("dataset words %d", len(dataset))
	}
	for i := range dataset {
		if dataset[i] != again[i] {
			t.Fatalf("dataset diverged at %d", i)
		}
	}

	got, err := Eval(chainID, epoch, testHeader(t, 1000, 20, 1_700_000_000), dataset)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.Seed[:]) != "2c2c49235865dacb38705af9f0aac7153f981861580369b144db23ec785ae7cb" {
		t.Fatalf("seed %x", got.Seed)
	}
	if hex.EncodeToString(got.Digest[:]) != "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640" {
		t.Fatalf("digest %x", got.Digest)
	}
	if got.Addr != 1106646132 {
		t.Fatalf("addr %d", got.Addr)
	}
	want := []string{"XOR", "XORROT", "ADDROT", "MUL", "ROT", "ADD", "MIX", "SBOX", "ADDROT", "ADD", "XORROT", "SBOX", "XOR", "MUL", "MIX", "ROT"}
	for i, name := range want {
		if got.Schedule[i] != name {
			t.Fatalf("schedule[%d]=%s want %s", i, got.Schedule[i], name)
		}
	}

	other, err := Eval(chainID, epoch, testHeader(t, 1001, 20, 1_700_000_000), dataset)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(other.Digest[:]) != "6408cb97b29fd2ca8ac52af08b806253af719d453fd866c2b5efb4b0b07c28cc" {
		t.Fatalf("nonce 1001 %x", other.Digest)
	}
	bits := 0
	for i := range got.Digest {
		d := got.Digest[i] ^ other.Digest[i]
		for d != 0 {
			bits += int(d & 1)
			d >>= 1
		}
	}
	if bits != 121 {
		t.Fatalf("hamming %d", bits)
	}

	mined, err := Eval(chainID, epoch, testHeader(t, 37, 8, 1_700_000_000), dataset)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(mined.Digest[:]) != "00a02a44532a21a5adc26d4a7041a0b7d28de0c222b55910f0c051fc34e3e978" {
		t.Fatalf("difficulty 8 %x", mined.Digest)
	}
	if !MeetsTarget(mined.Digest[:], 8) || MeetsTarget(mined.Digest[:], 9) {
		t.Fatal("difficulty gate")
	}
}

func TestHistogram(t *testing.T) {
	chainID := []byte("dfpow-test-v0.1\x00")
	epoch := make([]byte, 32)
	for i := range epoch {
		epoch[i] = byte(i)
	}
	got, err := Eval(chainID, epoch, testHeader(t, 1000, 20, 1_700_000_000), nil)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, name := range got.Schedule {
		counts[name]++
	}
	for _, name := range ColorNames {
		if counts[name] != Rounds/8 {
			t.Fatalf("%s count %d", name, counts[name])
		}
	}
	for i := 0; i < 8; i++ {
		seen := map[string]bool{}
		for _, name := range got.Schedule[i*8 : (i+1)*8] {
			seen[name] = true
		}
		if len(seen) != 8 {
			t.Fatalf("group %d is not a permutation", i)
		}
	}
}

func BenchmarkEval(b *testing.B) {
	chainID := []byte("dfpow-test-v0.1\x00")
	epoch := make([]byte, 32)
	dataset, err := BuildDataset(chainID, epoch)
	if err != nil {
		b.Fatal(err)
	}
	prev := make([]byte, 32)
	merkle := bytes.Repeat([]byte{0x11}, 32)
	header, err := MakeHeader(1, prev, merkle, 1_700_000_000, 20, 1000)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Eval(chainID, epoch, header, dataset); err != nil {
			b.Fatal(err)
		}
	}
}
