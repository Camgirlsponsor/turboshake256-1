package main

import (
	"bytes"
	"encoding/json"
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
	srv := httptest.NewServer(newHandler(node))
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
	if node.Tip().Height != 1 {
		t.Fatalf("tip %d", node.Tip().Height)
	}
}
