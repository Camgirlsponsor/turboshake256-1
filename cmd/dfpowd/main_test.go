package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Camgirlsponsor/turboshake256-1/internal/chain"
)

func TestViewerMinesABlock(t *testing.T) {
	clock := uint32(time.Now().Unix())
	node, err := chain.New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	wallet := &chain.Wallet{}
	if _, err := wallet.Import("miner", node.SigningKey()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newServer(node, wallet, nil).routes())
	defer srv.Close()

	home, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	home.Body.Close()
	if home.StatusCode != http.StatusOK {
		t.Fatalf("home %d", home.StatusCode)
	}

	before, err := http.Get(srv.URL + "/api/chain")
	if err != nil {
		t.Fatal(err)
	}
	defer before.Body.Close()
	var snap map[string]any
	if err := json.NewDecoder(before.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap["height"].(float64) != 0 {
		t.Fatalf("height %v", snap["height"])
	}

	res, err := http.Post(srv.URL+"/api/mine", "application/json", bytes.NewBufferString(`{"note":"viewer-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var mined map[string]any
	if err := json.NewDecoder(res.Body).Decode(&mined); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mine %d %v", res.StatusCode, mined)
	}
	block := mined["block"].(map[string]any)
	if block["height"].(float64) != 1 || block["note"] != "viewer-test" {
		t.Fatalf("block %v", block)
	}
	ops := block["schedule"].([]any)
	if len(ops) != 8 {
		t.Fatalf("schedule %v", ops)
	}
	txs := block["transactions"].([]any)
	if len(txs) != 1 {
		t.Fatalf("txs %v", txs)
	}
	if node.Tip().Height != 1 {
		t.Fatalf("tip %d", node.Tip().Height)
	}
}

func TestSendThenMinePaysRecipient(t *testing.T) {
	clock := uint32(time.Now().Unix())
	node, err := chain.New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	wallet := &chain.Wallet{}
	miner, err := wallet.Import("miner", node.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := chain.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	node.SetPayee(miner)
	srv := httptest.NewServer(newServer(node, wallet, nil).routes())
	defer srv.Close()

	payload, _ := json.Marshal(map[string]any{
		"from":   hexOf(miner),
		"to":     hexOf(bob),
		"amount": chain.Coin,
		"fee":    uint64(0),
	})
	res, err := http.Post(srv.URL+"/api/send", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("send %d %s", res.StatusCode, body)
	}
	if len(node.Mempool()) != 1 {
		t.Fatal("mempool")
	}
	mined, err := http.Post(srv.URL+"/api/mine", "application/json", bytes.NewBufferString(`{"note":"pay"}`))
	if err != nil {
		t.Fatal(err)
	}
	mined.Body.Close()
	if mined.StatusCode != http.StatusOK {
		t.Fatalf("mine %d", mined.StatusCode)
	}
	bal, _ := node.Balance(bob)
	if bal != chain.Coin {
		t.Fatalf("bob balance %d", bal)
	}
	addrRes, err := http.Get(srv.URL + "/api/address/" + hexOf(bob))
	if err != nil {
		t.Fatal(err)
	}
	defer addrRes.Body.Close()
	var addr map[string]any
	if err := json.NewDecoder(addrRes.Body).Decode(&addr); err != nil {
		t.Fatal(err)
	}
	if addr["balance"].(float64) != float64(chain.Coin) {
		t.Fatalf("address %v", addr)
	}
}

func TestPeerSyncsHeavierChainAndTransaction(t *testing.T) {
	clock := uint32(time.Now().Unix())
	origin, err := chain.New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := origin.Mine("origin", 1); err != nil {
		t.Fatal(err)
	}
	originSrv := httptest.NewServer(newServer(origin, &chain.Wallet{}, nil).routes())
	defer originSrv.Close()

	follower, err := chain.New(func() uint32 { return clock })
	if err != nil {
		t.Fatal(err)
	}
	node := newServer(follower, &chain.Wallet{}, []string{originSrv.URL})
	followSrv := httptest.NewServer(node.routes())
	defer followSrv.Close()
	node.sync()
	if follower.Tip().Hash != origin.Tip().Hash {
		t.Fatal("follower did not adopt the heavier chain")
	}

	bob, _, err := chain.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := chain.SignTransfer(origin.SigningKey(), bob, chain.Coin, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := chain.MarshalTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, followSrv.URL+"/peer/tx", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("peer tx %d", res.StatusCode)
	}
	if len(follower.Mempool()) != 1 {
		t.Fatal("follower mempool")
	}
}

func hexOf(pub [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range pub {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

func newServer(c *chain.Chain, w *chain.Wallet, peers []string) *server {
	if w == nil {
		w = &chain.Wallet{}
	}
	bases := make([]string, 0, len(peers))
	for _, peer := range peers {
		bases = append(bases, peerURL(peer))
	}
	return &server{
		chain:  c,
		wallet: w,
		peers:  bases,
		client: &http.Client{Timeout: 5 * time.Second},
		status: map[string]peerView{},
	}
}
