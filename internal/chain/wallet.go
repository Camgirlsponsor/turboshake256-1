package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

// Wallet holds the keys this node can spend. Addresses are public keys.
// The chain file does not contain private keys.
type Wallet struct {
	path string
	keys []walletKey
}

type walletKey struct {
	Label   string `json:"label"`
	Public  string `json:"public"`
	Private string `json:"private"`
}

type walletFile struct {
	Keys []walletKey `json:"keys"`
}

// LoadWallet reads path, or returns an empty wallet when the file is absent.
func LoadWallet(path string) (*Wallet, error) {
	w := &Wallet{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return w, nil
	}
	if err != nil {
		return nil, err
	}
	var file walletFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	w.keys = file.Keys
	for _, key := range w.keys {
		if _, _, err := decodeKey(key); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Ensure returns the first address, creating and saving one when the wallet is empty.
func (w *Wallet) Ensure(label string) ([32]byte, ed25519.PrivateKey, error) {
	if len(w.keys) > 0 {
		return decodeKey(w.keys[0])
	}
	return w.Create(label)
}

// Create adds a key, saves the file, and returns it.
func (w *Wallet) Create(label string) ([32]byte, ed25519.PrivateKey, error) {
	if label == "" {
		label = "address"
	}
	pub, priv, err := NewKey()
	if err != nil {
		return pub, nil, err
	}
	w.keys = append(w.keys, walletKey{
		Label:   label,
		Public:  hex.EncodeToString(pub[:]),
		Private: hex.EncodeToString(priv),
	})
	if err := w.save(); err != nil {
		return pub, nil, err
	}
	return pub, priv, nil
}

// Import stores an existing key under label. Used by tests and by a node
// that already mined the genesis block with this key.
func (w *Wallet) Import(label string, priv ed25519.PrivateKey) ([32]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return [32]byte{}, errors.New("chain: private key")
	}
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	for _, key := range w.keys {
		if key.Public == hex.EncodeToString(pub[:]) {
			return pub, nil
		}
	}
	w.keys = append(w.keys, walletKey{
		Label:   label,
		Public:  hex.EncodeToString(pub[:]),
		Private: hex.EncodeToString(priv),
	})
	return pub, w.save()
}

// Addresses lists public keys in wallet order.
func (w *Wallet) Addresses() [][32]byte {
	out := make([][32]byte, 0, len(w.keys))
	for _, key := range w.keys {
		pub, _, err := decodeKey(key)
		if err != nil {
			continue
		}
		out = append(out, pub)
	}
	return out
}

// Label returns the stored name for an address.
func (w *Wallet) Label(pub [32]byte) string {
	want := hex.EncodeToString(pub[:])
	for _, key := range w.keys {
		if key.Public == want {
			return key.Label
		}
	}
	return ""
}

// Private returns the key that spends pub.
func (w *Wallet) Private(pub [32]byte) (ed25519.PrivateKey, error) {
	want := hex.EncodeToString(pub[:])
	for _, key := range w.keys {
		if key.Public == want {
			_, priv, err := decodeKey(key)
			return priv, err
		}
	}
	return nil, errors.New("chain: key is not in this wallet")
}

func decodeKey(key walletKey) ([32]byte, ed25519.PrivateKey, error) {
	var pub [32]byte
	raw, err := hex.DecodeString(key.Public)
	if err != nil || len(raw) != 32 {
		return pub, nil, errors.New("chain: wallet public key")
	}
	copy(pub[:], raw)
	privRaw, err := hex.DecodeString(key.Private)
	if err != nil || len(privRaw) != ed25519.PrivateKeySize {
		return pub, nil, errors.New("chain: wallet private key")
	}
	priv := ed25519.PrivateKey(privRaw)
	var derived [32]byte
	copy(derived[:], priv.Public().(ed25519.PublicKey))
	if derived != pub {
		return pub, nil, errors.New("chain: wallet key mismatch")
	}
	return pub, priv, nil
}

func (w *Wallet) save() error {
	if w.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(walletFile{Keys: w.keys}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}
