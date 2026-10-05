package chain

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"lukechampine.com/blake3"
)

const (
	kindCoinbase = 1
	kindTransfer = 2
	maxNoteLen   = 64
	maxTransfers = 16
	maxMempool   = 64
)

var domainSig = tag16("DFPW-SIG-v01")

// IsCoinbase reports whether the transaction mints the block subsidy.
func (tx Tx) IsCoinbase() bool { return tx.Kind == kindCoinbase }

// Tx is one confirmed or pending transaction.
// A coinbase pays the miner the subsidy plus the fees in that block.
// A transfer moves amount from the sender to the recipient and pays fee
// to the miner. The sender's nonce must equal their confirmed sequence.
type Tx struct {
	Kind      uint8
	Height    uint64
	Extra     uint64
	Note      string
	Pubkey    [32]byte
	Recipient [32]byte
	Amount    uint64
	Fee       uint64
	Nonce     uint64
	Signature []byte
	ID        [32]byte
}

type pending struct {
	amount uint64
	height uint64
}

type acct struct {
	balance uint64
	nonce   uint64
	pending []pending
}

// NewKey returns an ed25519 address and the private key that spends it.
// The address is the 32-byte public key.
func NewKey() (pub [32]byte, priv ed25519.PrivateKey, err error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return pub, nil, err
	}
	copy(pub[:], public)
	return pub, private, nil
}

// SignTransfer builds a transfer authorized by priv. The nonce is the
// sender's next sequence number, starting at zero.
func SignTransfer(priv ed25519.PrivateKey, to [32]byte, amount, fee, nonce uint64) (Tx, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Tx{}, errors.New("chain: private key")
	}
	var from [32]byte
	copy(from[:], priv.Public().(ed25519.PublicKey))
	if from == to {
		return Tx{}, errors.New("chain: sender and recipient are the same")
	}
	if amount == 0 {
		return Tx{}, errors.New("chain: amount is zero")
	}
	if _, overflow := add(amount, fee); overflow {
		return Tx{}, errors.New("chain: amount overflow")
	}
	body := transferBody(from, to, amount, fee, nonce)
	sig := ed25519.Sign(priv, sigMessage(body))
	tx := Tx{
		Kind:      kindTransfer,
		Pubkey:    from,
		Recipient: to,
		Amount:    amount,
		Fee:       fee,
		Nonce:     nonce,
		Signature: sig,
	}
	tx.ID = txid(transferWire(body, sig))
	return tx, nil
}

func sigMessage(body []byte) []byte {
	msg := make([]byte, 0, 16+len(body))
	msg = append(msg, domainSig[:]...)
	msg = append(msg, body...)
	return msg
}

func transferBody(from, to [32]byte, amount, fee, nonce uint64) []byte {
	buf := make([]byte, 4+1+32+32+8+8+8)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	buf[4] = kindTransfer
	copy(buf[5:37], from[:])
	copy(buf[37:69], to[:])
	binary.LittleEndian.PutUint64(buf[69:77], amount)
	binary.LittleEndian.PutUint64(buf[77:85], fee)
	binary.LittleEndian.PutUint64(buf[85:93], nonce)
	return buf
}

func transferWire(body, sig []byte) []byte {
	out := make([]byte, 0, len(body)+len(sig))
	out = append(out, body...)
	out = append(out, sig...)
	return out
}

func coinbaseTx(height, extra uint64, note string, miner [32]byte, subsidy, fees uint64) Tx {
	note = trimNote(note)
	tx := Tx{
		Kind:   kindCoinbase,
		Height: height,
		Extra:  extra,
		Note:   note,
		Pubkey: miner,
		Amount: subsidy,
		Fee:    fees,
	}
	tx.ID = txid(coinbaseBytes(tx))
	return tx
}

func coinbaseBytes(tx Tx) []byte {
	note := []byte(tx.Note)
	buf := make([]byte, 4+1+8+8+2+len(note)+32+8+8)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	buf[4] = kindCoinbase
	binary.LittleEndian.PutUint64(buf[5:13], tx.Height)
	binary.LittleEndian.PutUint64(buf[13:21], tx.Extra)
	binary.LittleEndian.PutUint16(buf[21:23], uint16(len(note)))
	copy(buf[23:], note)
	off := 23 + len(note)
	copy(buf[off:off+32], tx.Pubkey[:])
	binary.LittleEndian.PutUint64(buf[off+32:off+40], tx.Amount)
	binary.LittleEndian.PutUint64(buf[off+40:off+48], tx.Fee)
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

func verifyTransfer(tx Tx) error {
	if tx.Kind != kindTransfer {
		return errors.New("chain: not a transfer")
	}
	if len(tx.Signature) != ed25519.SignatureSize {
		return errors.New("chain: signature length")
	}
	if tx.Pubkey == tx.Recipient {
		return errors.New("chain: sender and recipient are the same")
	}
	if tx.Amount == 0 {
		return errors.New("chain: amount is zero")
	}
	if _, overflow := add(tx.Amount, tx.Fee); overflow {
		return errors.New("chain: amount overflow")
	}
	body := transferBody(tx.Pubkey, tx.Recipient, tx.Amount, tx.Fee, tx.Nonce)
	if txid(transferWire(body, tx.Signature)) != tx.ID {
		return errors.New("chain: txid")
	}
	if !ed25519.Verify(tx.Pubkey[:], sigMessage(body), tx.Signature) {
		return errors.New("chain: signature")
	}
	return nil
}

func applyTransfer(state map[[32]byte]acct, tx Tx) error {
	if err := verifyTransfer(tx); err != nil {
		return err
	}
	from := state[tx.Pubkey]
	if from.nonce != tx.Nonce {
		return errors.New("chain: nonce")
	}
	cost, overflow := add(tx.Amount, tx.Fee)
	if overflow || from.balance < cost {
		return errors.New("chain: insufficient balance")
	}
	from.balance -= cost
	from.nonce++
	state[tx.Pubkey] = from
	to := state[tx.Recipient]
	next, overflow := add(to.balance, tx.Amount)
	if overflow {
		return errors.New("chain: balance overflow")
	}
	to.balance = next
	state[tx.Recipient] = to
	return nil
}

func applyBlock(prior map[[32]byte]acct, block Block) (map[[32]byte]acct, error) {
	if len(block.Txs) == 0 || block.Txs[0].Kind != kindCoinbase {
		return nil, errors.New("chain: coinbase")
	}
	cb := block.Txs[0]
	subsidy := SubsidyAt(block.Height)
	if cb.Amount != subsidy || cb.Height != block.Height || cb.Note != block.Note || cb.Extra != block.ExtraNonce {
		return nil, errors.New("chain: coinbase fields")
	}
	if cb.ID != txid(coinbaseBytes(cb)) {
		return nil, errors.New("chain: coinbase txid")
	}
	if len(block.Txs)-1 > maxTransfers {
		return nil, errors.New("chain: too many transfers")
	}
	state := cloneState(prior)
	if err := matureState(state, block.Height); err != nil {
		return nil, err
	}
	var fees uint64
	seen := map[[32]byte]bool{cb.ID: true}
	for _, tx := range block.Txs[1:] {
		if seen[tx.ID] {
			return nil, errors.New("chain: duplicate tx")
		}
		seen[tx.ID] = true
		if err := applyTransfer(state, tx); err != nil {
			return nil, err
		}
		var overflow bool
		fees, overflow = add(fees, tx.Fee)
		if overflow {
			return nil, errors.New("chain: fee overflow")
		}
	}
	if cb.Fee != fees {
		return nil, errors.New("chain: fee total")
	}
	credit, overflow := add(cb.Amount, fees)
	if overflow {
		return nil, errors.New("chain: subsidy overflow")
	}
	miner := state[cb.Pubkey]
	miner.pending = append(miner.pending, pending{amount: credit, height: block.Height})
	state[cb.Pubkey] = miner
	return state, nil
}

// matureState credits coinbases that have CoinbaseMaturity blocks above them.
// A reward from height h is spendable in a block at height h+CoinbaseMaturity.
func matureState(state map[[32]byte]acct, height uint64) error {
	for key, acct := range state {
		if len(acct.pending) == 0 {
			continue
		}
		keep := make([]pending, 0, len(acct.pending))
		for _, item := range acct.pending {
			if height >= item.height+uint64(CoinbaseMaturity) {
				next, overflow := add(acct.balance, item.amount)
				if overflow {
					return errors.New("chain: balance overflow")
				}
				acct.balance = next
				continue
			}
			keep = append(keep, item)
		}
		acct.pending = keep
		state[key] = acct
	}
	return nil
}

func selectTransfers(prior map[[32]byte]acct, mem []Tx, limit int) []Tx {
	if limit > maxTransfers {
		limit = maxTransfers
	}
	left := append([]Tx(nil), mem...)
	state := cloneState(prior)
	picked := make([]Tx, 0, limit)
	for len(picked) < limit && len(left) > 0 {
		next := make([]Tx, 0, len(left))
		progress := false
		for _, tx := range left {
			if len(picked) >= limit {
				next = append(next, tx)
				continue
			}
			if err := applyTransfer(state, tx); err != nil {
				next = append(next, tx)
				continue
			}
			picked = append(picked, tx)
			progress = true
		}
		left = next
		if !progress {
			break
		}
	}
	return picked
}

func cloneState(in map[[32]byte]acct) map[[32]byte]acct {
	out := make(map[[32]byte]acct, len(in))
	for k, v := range in {
		if len(v.pending) > 0 {
			v.pending = append([]pending(nil), v.pending...)
		}
		out[k] = v
	}
	return out
}

func add(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}

func merkleRoot(ids [][32]byte) [32]byte {
	level := append([][32]byte(nil), ids...)
	if len(level) == 0 {
		return txid(nil)
	}
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
