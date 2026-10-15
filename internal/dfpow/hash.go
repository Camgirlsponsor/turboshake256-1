// Package dfpow is the Go node implementation of DFPoW-256 draft 0.1.
// python/dfpow.py is the independent reference. The vectors in hash_test.go
// must match that reference and docs/DFPoW-256.md.
package dfpow

import (
	"encoding/binary"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

const (
	DatasetBytes = 1 << 20
	ScratchBytes = 1 << 11
	Rounds       = 256

	DatasetWords = DatasetBytes / 4
	ScratchWords = ScratchBytes / 4
	datasetMask  = DatasetWords - 1
	scratchMask  = ScratchWords - 1

	HeaderBytes = 84
	PrefixBytes = 76
	tapeBytes   = 255 + Rounds*12 + (Rounds/8)*7
)

var (
	// ColorNames is the accent schedule, in numeric order.
	ColorNames = [...]string{"XOR", "ADD", "ROT", "MUL", "SBOX", "XORROT", "ADDROT", "MIX"}

	domainSeed  = tag("DFPW-SEED-v01")
	domainData  = tag("DFPW-DATA-v01")
	domainProg  = tag("DFPW-PROG-v01")
	domainFinal = tag("DFPW-FINAL-v01")
	params      = func() [12]byte {
		var p [12]byte
		binary.LittleEndian.PutUint32(p[0:4], DatasetBytes)
		binary.LittleEndian.PutUint32(p[4:8], ScratchBytes)
		binary.LittleEndian.PutUint32(p[8:12], Rounds)
		return p
	}()

	errChainID = errors.New("dfpow: chain_id must be 16 bytes")
	errEpoch   = errors.New("dfpow: epoch_seed must be 32 bytes")
	errHeader  = errors.New("dfpow: header must be 84 bytes")
	errDataset = errors.New("dfpow: dataset has the wrong length")
)

func tag(label string) [16]byte {
	var out [16]byte
	copy(out[:], label)
	return out
}

func rotl32(x uint32, n uint) uint32 {
	n &= 31
	if n == 0 {
		return x
	}
	return (x << n) | (x >> (32 - n))
}

func xof(n int, parts ...[]byte) []byte {
	h := blake3.New(n, nil)
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func sum256(parts ...[]byte) [32]byte {
	raw := xof(32, parts...)
	var out [32]byte
	copy(out[:], raw)
	return out
}

// BuildDataset constructs the epoch dataset. Every finished word depends on
// the entire BLAKE3 output, so a caller cannot seek to a single word.
func BuildDataset(chainID, epochSeed []byte) ([]uint32, error) {
	if len(chainID) != 16 {
		return nil, errChainID
	}
	if len(epochSeed) != 32 {
		return nil, errEpoch
	}
	raw := xof(DatasetBytes, domainData[:], chainID, params[:], epochSeed)
	dataset := make([]uint32, DatasetWords)
	mixed := binary.LittleEndian.Uint32(epochSeed[:4]) ^ binary.LittleEndian.Uint32(epochSeed[4:8])
	for i := 0; i < DatasetWords; i++ {
		entropy := binary.LittleEndian.Uint32(raw[i*4 : (i+1)*4])
		mixed = rotl32(mixed^entropy, 7) * 0x9E3779B9
		dataset[i] = mixed
	}
	for i := DatasetWords - 2; i >= 0; i-- {
		dataset[i] ^= rotl32(dataset[i+1], 5)
	}
	return dataset, nil
}

// MakeHeader packs an 84-byte header. Every integer is little-endian.
func MakeHeader(version uint32, prev, merkle []byte, timestamp, difficulty uint32, nonce uint64) ([]byte, error) {
	if len(prev) != 32 || len(merkle) != 32 {
		return nil, errors.New("dfpow: prev and merkle must be 32 bytes")
	}
	header := make([]byte, HeaderBytes)
	binary.LittleEndian.PutUint32(header[0:4], version)
	copy(header[4:36], prev)
	copy(header[36:68], merkle)
	binary.LittleEndian.PutUint32(header[68:72], timestamp)
	binary.LittleEndian.PutUint32(header[72:76], difficulty)
	binary.LittleEndian.PutUint64(header[76:84], nonce)
	return header, nil
}

// HeaderFields reads the consensus fields out of an 84-byte header.
func HeaderFields(header []byte) (version, timestamp, difficulty uint32, nonce uint64, prev, merkle []byte, err error) {
	if len(header) != HeaderBytes {
		err = errHeader
		return
	}
	version = binary.LittleEndian.Uint32(header[0:4])
	prev = header[4:36]
	merkle = header[36:68]
	timestamp = binary.LittleEndian.Uint32(header[68:72])
	difficulty = binary.LittleEndian.Uint32(header[72:76])
	nonce = binary.LittleEndian.Uint64(header[76:84])
	return
}

// MeetsTarget reports whether digest, read as a big-endian integer, is at
// or below the difficulty target. Byte 0 is the most significant byte.
func MeetsTarget(digest []byte, difficulty uint32) bool {
	if len(digest) != 32 || difficulty > 256 {
		return false
	}
	full := difficulty / 8
	rem := difficulty % 8
	for i := uint32(0); i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	mask := byte(0xFF << (8 - rem))
	return digest[full]&mask == 0
}

type program struct {
	sbox   [256]byte
	rounds [Rounds]roundRec
	colors [Rounds]byte
}

type roundRec struct {
	constant   uint32
	rotation   uint
	b0, b1, b2 byte
	multiplier uint32
}

func parseTape(tape []byte) (program, error) {
	var prog program
	if len(tape) != tapeBytes {
		return prog, fmt.Errorf("dfpow: tape is %d bytes", len(tape))
	}
	i := 0
	for n := 0; n < 256; n++ {
		prog.sbox[n] = byte(n)
	}
	for n := 255; n >= 1; n-- {
		j := int(tape[i]) % (n + 1)
		i++
		prog.sbox[n], prog.sbox[j] = prog.sbox[j], prog.sbox[n]
	}
	for r := 0; r < Rounds; r++ {
		rec := roundRec{
			constant:   binary.LittleEndian.Uint32(tape[i : i+4]),
			rotation:   uint(tape[i+4]%31) + 1,
			b0:         tape[i+5],
			b1:         tape[i+6],
			b2:         tape[i+7],
			multiplier: binary.LittleEndian.Uint32(tape[i+8:i+12]) | 0x80000001,
		}
		i += 12
		prog.rounds[r] = rec
	}
	for g := 0; g < Rounds/8; g++ {
		var order [8]byte
		for n := 0; n < 8; n++ {
			order[n] = byte(n)
		}
		for n := 7; n >= 1; n-- {
			j := int(tape[i]) % (n + 1)
			i++
			order[n], order[j] = order[j], order[n]
		}
		copy(prog.colors[g*8:(g+1)*8], order[:])
	}
	if i != len(tape) {
		return prog, errors.New("dfpow: program tape was not fully consumed")
	}
	return prog, nil
}

func selectIndices(pinned int, b0, b1, b2 byte) (int, int, int, int) {
	pool := make([]int, 0, 7)
	for i := 0; i < 8; i++ {
		if i != pinned {
			pool = append(pool, i)
		}
	}
	take := func(mod int, b byte) int {
		idx := int(b) % mod
		v := pool[idx]
		pool = append(pool[:idx], pool[idx+1:]...)
		return v
	}
	return pinned, take(7, b0), take(6, b1), take(5, b2)
}

func applySbox(sbox *[256]byte, word uint32) uint32 {
	return uint32(sbox[word&0xff]) |
		uint32(sbox[(word>>8)&0xff])<<8 |
		uint32(sbox[(word>>16)&0xff])<<16 |
		uint32(sbox[(word>>24)&0xff])<<24
}

func quarterRound(state *[8]uint32, i0, i1, i2, i3 int) {
	a, b, c, d := state[i0], state[i1], state[i2], state[i3]
	a += b
	d = rotl32(d^a, 16)
	c += d
	b = rotl32(b^c, 12)
	a += b
	d = rotl32(d^a, 8)
	c += d
	b = rotl32(b^c, 7)
	state[i0], state[i1], state[i2], state[i3] = a, b, c, d
}

func applyAccent(op byte, state *[8]uint32, i0, i1, i2, i3 int, sbox *[256]byte, multiplier uint32, rotation uint, dataset []uint32, addr uint32) uint32 {
	a, b, c, d := state[i0], state[i1], state[i2], state[i3]
	switch op {
	case 0: // XOR
		c ^= a ^ b
		d ^= rotl32(c, rotation)
	case 1: // ADD
		c += a + b
		d ^= c
	case 2: // ROT
		c = rotl32(a, rotation) ^ b
		d ^= rotl32(c, 8)
	case 3: // MUL
		product := uint64(b) * uint64(multiplier)
		lo := uint32(product)
		hi := uint32(product >> 32)
		b = lo
		c ^= lo
		d ^= hi
	case 4: // SBOX
		c ^= applySbox(sbox, a)
		d ^= applySbox(sbox, b)
	case 5: // XORROT
		c ^= a ^ rotl32(b, rotation)
		d += c
	case 6: // ADDROT
		c = a + rotl32(b, rotation)
		d ^= rotl32(c, 8)
	case 7: // MIX
		value := dataset[(addr+a+c)&datasetMask]
		a ^= value
		b += value
		c ^= rotl32(value, rotation)
		d ^= value
		addr = addr + value + b
	default:
		panic("dfpow: unknown accent")
	}
	state[i0], state[i1], state[i2], state[i3] = a, b, c, d
	return addr
}

func memoryStep(state *[8]uint32, i0, i1, i2, i3 int, constant uint32, rotation uint, dataset, scratch []uint32, addr uint32) uint32 {
	a, b, c, d := state[i0], state[i1], state[i2], state[i3]
	value := dataset[(addr+c)&datasetMask]
	sidx := (a ^ value) & scratchMask
	saved := scratch[sidx]
	b ^= saved
	d += value
	scratch[sidx] = rotl32((saved^a^constant)+value, 5)
	addr = b + rotl32(value^saved, 3)
	a ^= rotl32(value, rotation)
	state[i0], state[i1], state[i2], state[i3] = a, b, c, d
	return addr
}

func foldScratch(state *[8]uint32, scratch []uint32, addr uint32) uint32 {
	acc := addr
	for i, word := range scratch {
		acc = rotl32(acc+word, 5) ^ uint32(uint64(i)*0x9E3779B9)
	}
	for i := 0; i < 8; i++ {
		state[i] ^= rotl32(acc, uint((i*4+1)&31))
		acc = rotl32(acc^state[i], 3)
	}
	return acc
}

func execute(dataset []uint32, prog program, seed, nonce []byte) (state [8]uint32, addr uint32, scratch []uint32) {
	for i := 0; i < 8; i++ {
		state[i] = binary.LittleEndian.Uint32(seed[i*4 : (i+1)*4])
	}
	state[0] ^= binary.LittleEndian.Uint32(nonce[:4])
	state[1] ^= binary.LittleEndian.Uint32(nonce[4:8])
	scratch = make([]uint32, ScratchWords)
	origin := state[3] & datasetMask
	tumbler := state[5] | 1
	for i := uint32(0); i < ScratchWords; i++ {
		scratch[i] = dataset[(origin+i)&datasetMask] ^ rotl32(tumbler, uint(i&31)) ^ i
	}
	addr = state[7]
	for r := 0; r < Rounds; r++ {
		rec := prog.rounds[r]
		i0, i1, i2, i3 := selectIndices(r&7, rec.b0, rec.b1, rec.b2)
		k := rec.constant ^ uint32(r)
		state[i0] ^= k
		quarterRound(&state, i0, i1, i2, i3)
		addr = applyAccent(prog.colors[r], &state, i0, i1, i2, i3, &prog.sbox, rec.multiplier, rec.rotation, dataset, addr)
		addr = memoryStep(&state, i0, i1, i2, i3, k, rec.rotation, dataset, scratch, addr)
	}
	addr = foldScratch(&state, scratch, addr)
	return state, addr, scratch
}

func finalize(chainID, epochSeed []byte, seed [32]byte, state [8]uint32, addr uint32, scratch, dataset []uint32) [32]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write(domainFinal[:])
	_, _ = h.Write(chainID)
	_, _ = h.Write(params[:])
	_, _ = h.Write(epochSeed)
	_, _ = h.Write(seed[:])
	var buf [4]byte
	for _, word := range state {
		binary.LittleEndian.PutUint32(buf[:], word)
		_, _ = h.Write(buf[:])
	}
	binary.LittleEndian.PutUint32(buf[:], addr)
	_, _ = h.Write(buf[:])
	for i := uint32(0); i < 8; i++ {
		idx := (state[i] + i*0x9E3779B9) & scratchMask
		binary.LittleEndian.PutUint32(buf[:], scratch[idx])
		_, _ = h.Write(buf[:])
	}
	for i := uint32(0); i < 8; i++ {
		idx := (state[i] ^ addr ^ (i * 0x85EBCA6B)) & datasetMask
		binary.LittleEndian.PutUint32(buf[:], dataset[idx])
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Result is one execution, including the fields the test vectors lock.
type Result struct {
	Digest   [32]byte
	Seed     [32]byte
	Addr     uint32
	Schedule []string
}

// Eval runs the proof-of-work function. dataset may be nil, in which case it
// is built from chainID and epochSeed. A dataset from any other input is a
// caller bug and will not match the network.
func Eval(chainID, epochSeed, header []byte, dataset []uint32) (Result, error) {
	if len(chainID) != 16 {
		return Result{}, errChainID
	}
	if len(epochSeed) != 32 {
		return Result{}, errEpoch
	}
	if len(header) != HeaderBytes {
		return Result{}, errHeader
	}
	if dataset == nil {
		var err error
		dataset, err = BuildDataset(chainID, epochSeed)
		if err != nil {
			return Result{}, err
		}
	} else if len(dataset) != DatasetWords {
		return Result{}, errDataset
	}
	prefix := header[:PrefixBytes]
	nonce := header[PrefixBytes:]
	seed := sum256(domainSeed[:], chainID, params[:], epochSeed, prefix, nonce)
	prog, err := parseTape(xof(tapeBytes, domainProg[:], chainID, params[:], seed[:]))
	if err != nil {
		return Result{}, err
	}
	state, addr, scratch := execute(dataset, prog, seed[:], nonce)
	names := make([]string, Rounds)
	for i, c := range prog.colors {
		names[i] = ColorNames[c]
	}
	return Result{
		Digest:   finalize(chainID, epochSeed, seed, state, addr, scratch, dataset),
		Seed:     seed,
		Addr:     addr,
		Schedule: names,
	}, nil
}

// Schedule returns the nonce-specific accent list without executing it.
func Schedule(chainID, epochSeed, header []byte) ([]string, error) {
	if len(chainID) != 16 {
		return nil, errChainID
	}
	if len(epochSeed) != 32 {
		return nil, errEpoch
	}
	if len(header) != HeaderBytes {
		return nil, errHeader
	}
	seed := sum256(domainSeed[:], chainID, params[:], epochSeed, header[:PrefixBytes], header[PrefixBytes:])
	prog, err := parseTape(xof(tapeBytes, domainProg[:], chainID, params[:], seed[:]))
	if err != nil {
		return nil, err
	}
	names := make([]string, Rounds)
	for i, c := range prog.colors {
		names[i] = ColorNames[c]
	}
	return names, nil
}

// SelfCheck refuses to start a node whose hasher disagrees with draft 0.1.
func SelfCheck() error {
	chainID := []byte("dfpow-test-v0.1\x00")
	epoch := make([]byte, 32)
	for i := range epoch {
		epoch[i] = byte(i)
	}
	prev := make([]byte, 32)
	merkle := make([]byte, 32)
	for i := range merkle {
		merkle[i] = 0x11
	}
	header, err := MakeHeader(1, prev, merkle, 1_700_000_000, 20, 1000)
	if err != nil {
		return err
	}
	got, err := Eval(chainID, epoch, header, nil)
	if err != nil {
		return err
	}
	const want = "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640"
	if hexEncode(got.Digest[:]) != want {
		return fmt.Errorf("dfpow: self-check digest %s", hexEncode(got.Digest[:]))
	}
	return nil
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}
