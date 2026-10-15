package main

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Camgirlsponsor/turboshake256-1/internal/chain"
	"github.com/Camgirlsponsor/turboshake256-1/internal/dfpow"
)

//go:embed web/index.html
var web embed.FS

func main() {
	if err := dfpow.SelfCheck(); err != nil {
		log.Fatal(err)
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mine":
		mine(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n  dfpowd mine -n 12 [-data chain.json] [-wallet wallet.json]\n  dfpowd serve [-addr 127.0.0.1:8080] [-data chain.json] [-wallet wallet.json] [-peer host:port]\n\nWallet, send, and mine accept connections from localhost only.\n")
}

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func mine(args []string) {
	fs := flag.NewFlagSet("mine", flag.ExitOnError)
	n := fs.Int("n", 8, "blocks to mine after the current tip")
	path := fs.String("data", "chain.json", "chain file")
	walletPath := fs.String("wallet", "wallet.json", "wallet file")
	note := fs.String("note", "local", "coinbase note")
	_ = fs.Parse(args)
	c, _ := openNode(*path, *walletPath)
	printBlock(c.Tip(), chain.Stats{})
	for i := 0; i < *n; i++ {
		block, stats, err := c.Mine(*note, runtime.NumCPU())
		if err != nil {
			log.Fatal(err)
		}
		printBlock(block, stats)
	}
	fmt.Printf("work %s  file %s\n", c.Work().String(), *path)
}

func printBlock(block chain.Block, stats chain.Stats) {
	line := fmt.Sprintf("height %-4d  d=%-2d  nonce=%-8d  txs=%-3d  hash=%s  %s",
		block.Height, block.Difficulty, block.Nonce, len(block.Txs), hex.EncodeToString(block.Hash[:8]), block.Note)
	if stats.Attempts > 0 {
		line += fmt.Sprintf("  %d hashes  %s", stats.Attempts, stats.Elapsed.Round(time.Millisecond))
	}
	fmt.Println(line)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	path := fs.String("data", "chain.json", "chain file")
	walletPath := fs.String("wallet", "wallet.json", "wallet file")
	var peers stringsFlag
	fs.Var(&peers, "peer", "peer host:port or URL (repeatable)")
	_ = fs.Parse(args)
	node := openServer(*path, *walletPath, peers)
	go node.loop()
	payee := node.chain.Payee()
	log.Printf("DFPoW node at http://%s  tip %d  payee %s", *addr, node.chain.Tip().Height, hex.EncodeToString(payee[:8]))
	log.Fatal(http.ListenAndServe(*addr, node.routes()))
}

func openNode(path, walletPath string) (*chain.Chain, *chain.Wallet) {
	wallet, err := chain.LoadWallet(walletPath)
	if err != nil {
		log.Fatal(err)
	}
	pub, _, err := wallet.Ensure("miner")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		priv, err := wallet.Private(pub)
		if err != nil {
			log.Fatal(err)
		}
		c, err := chain.Create(path, pub, priv, nil)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote published genesis to %s", path)
		return c, wallet
	} else if err != nil {
		log.Fatal(err)
	}
	c, err := chain.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	c.SetPayee(pub)
	return c, wallet
}

func openServer(path, walletPath string, peers []string) *server {
	c, w := openNode(path, walletPath)
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

func peerURL(peer string) string {
	peer = strings.TrimRight(strings.TrimSpace(peer), "/")
	if strings.Contains(peer, "://") {
		return peer
	}
	return "http://" + peer
}

type peerView struct {
	Addr   string `json:"addr"`
	Height uint64 `json:"height,omitempty"`
	Work   string `json:"work,omitempty"`
	Error  string `json:"error,omitempty"`
}

type server struct {
	chain  *chain.Chain
	wallet *chain.Wallet
	peers  []string
	client *http.Client
	mu     sync.Mutex
	status map[string]peerView
}

func (s *server) loop() {
	s.sync()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.sync()
	}
}

func (s *server) sync() {
	for _, peer := range s.peers {
		s.syncPeer(peer)
	}
}

func (s *server) syncPeer(peer string) {
	var status struct {
		Height  uint64 `json:"height"`
		Hash    string `json:"hash"`
		Work    string `json:"work"`
		Genesis string `json:"genesis"`
		ChainID string `json:"chain_id"`
	}
	view := peerView{Addr: peer}
	if err := s.getJSON(peer+"/peer/status", &status); err != nil {
		view.Error = err.Error()
		s.setPeer(view)
		return
	}
	view.Height = status.Height
	view.Work = status.Work
	id := chain.ChainID()
	if status.ChainID != "" && status.ChainID != hex.EncodeToString(id[:]) {
		view.Error = "different chain id"
		s.setPeer(view)
		return
	}
	genesis, ok := s.chain.BlockAt(0)
	if !ok || (status.Genesis != "" && status.Genesis != hex.EncodeToString(genesis.Hash[:])) {
		view.Error = "different genesis"
		s.setPeer(view)
		return
	}
	remote, ok := new(big.Int).SetString(status.Work, 10)
	if !ok {
		view.Error = "bad work"
		s.setPeer(view)
		return
	}
	if remote.Cmp(s.chain.Work()) > 0 {
		if err := s.pullBlocks(peer, status.Height); err != nil {
			view.Error = err.Error()
			s.setPeer(view)
			return
		}
		if remote.Cmp(s.chain.Work()) > 0 && s.chain.Tip().Height >= status.Height {
			log.Printf("peer %s has more work at height %d than the adopted chain", peer, status.Height)
		}
	}
	s.setPeer(view)
}

func (s *server) pullBlocks(peer string, remoteHeight uint64) error {
	localHeight := s.chain.Tip().Height
	hi := localHeight
	if remoteHeight < hi {
		hi = remoteHeight
	}
	match, err := s.commonHeight(peer, hi)
	if err != nil {
		return err
	}
	var batch []chain.Block
	from := match + 1
	for from <= remoteHeight {
		part, err := s.fetchBlocks(peer, from, 32)
		if err != nil {
			return err
		}
		if len(part) == 0 {
			break
		}
		batch = append(batch, part...)
		from += uint64(len(part))
	}
	if len(batch) == 0 {
		return nil
	}
	adopted, err := s.chain.Adopt(batch)
	if err != nil {
		return err
	}
	if adopted {
		log.Printf("adopted blocks from %s at height %d", peer, s.chain.Tip().Height)
		go s.broadcastBlocks(s.chain.BlocksFrom(match+1, int(s.chain.Tip().Height-match)), peer)
	}
	return nil
}

func (s *server) commonHeight(peer string, hi uint64) (uint64, error) {
	if hi == 0 {
		return 0, nil
	}
	step := uint64(1)
	h := hi
	for {
		part, err := s.fetchBlocks(peer, h, 1)
		if err != nil {
			return 0, err
		}
		local, ok := s.chain.BlockAt(h)
		if ok && len(part) == 1 && part[0].Hash == local.Hash {
			return h, nil
		}
		if h == 0 {
			return 0, errors.New("peer chain does not share this genesis")
		}
		if h <= step {
			h = 0
			continue
		}
		h -= step
		if step < 256 {
			step *= 2
		}
	}
}

func (s *server) fetchBlocks(peer string, from uint64, limit int) ([]chain.Block, error) {
	url := fmt.Sprintf("%s/peer/blocks?from=%d&limit=%d", peer, from, limit)
	raw, err := s.getBytes(url)
	if err != nil {
		return nil, err
	}
	return chain.UnmarshalBlocks(raw)
}

func (s *server) setPeer(view peerView) {
	s.mu.Lock()
	s.status[view.Addr] = view
	s.mu.Unlock()
}

func (s *server) peersSnapshot() []peerView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]peerView, 0, len(s.peers))
	for _, peer := range s.peers {
		view, ok := s.status[peer]
		if !ok {
			view = peerView{Addr: peer}
		}
		out = append(out, view)
	}
	return out
}

func (s *server) broadcastBlocks(blocks []chain.Block, except string) {
	if len(blocks) == 0 {
		return
	}
	raw, err := chain.MarshalBlocks(blocks)
	if err != nil {
		log.Printf("broadcast: %v", err)
		return
	}
	for _, peer := range s.peers {
		if peer == except {
			continue
		}
		s.post(peer+"/peer/blocks", raw)
	}
}

func (s *server) relayTx(raw []byte, except string) {
	for _, peer := range s.peers {
		if peer == except {
			continue
		}
		s.post(peer+"/peer/tx", raw)
	}
}

func (s *server) post(url string, raw []byte) {
	resp, err := s.client.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		log.Printf("post %s: %v", url, err)
		return
	}
	resp.Body.Close()
}

func (s *server) getJSON(url string, dest any) error {
	raw, err := s.getBytes(url)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

func (s *server) getBytes(url string) ([]byte, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer status %d", resp.StatusCode)
	}
	return raw, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("GET /api/chain", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.snapshot())
	})
	mux.HandleFunc("GET /api/mempool", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"transactions": txViews(s.chain.Mempool(), 0, false)})
	})
	mux.HandleFunc("GET /api/wallet", s.walletView)
	mux.HandleFunc("POST /api/wallet/new", localOnly(s.walletNew))
	mux.HandleFunc("POST /api/send", localOnly(s.send))
	mux.HandleFunc("POST /api/mine", localOnly(s.mine))
	mux.HandleFunc("GET /api/block/{id}", s.block)
	mux.HandleFunc("GET /api/tx/{id}", s.tx)
	mux.HandleFunc("GET /api/address/{id}", s.address)
	mux.HandleFunc("GET /peer/status", s.peerStatus)
	mux.HandleFunc("GET /peer/blocks", s.peerBlocks)
	mux.HandleFunc("POST /peer/blocks", s.peerAcceptBlocks)
	mux.HandleFunc("GET /peer/chain", s.peerChain)
	mux.HandleFunc("POST /peer/chain", s.peerAccept)
	mux.HandleFunc("POST /peer/tx", s.peerTx)
	return mux
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	f, err := web.Open("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, f)
}

func (s *server) mine(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Note    string `json:"note"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Address != "" {
		pub, err := parseID(body.Address)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if _, err := s.wallet.Private(pub); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		s.chain.SetPayee(pub)
	}
	block, stats, err := s.chain.Mine(body.Note, runtime.NumCPU())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	go s.broadcastBlocks([]chain.Block{block}, "")
	writeJSON(w, map[string]any{
		"block":      blockView(s.chain.Blocks(), block),
		"attempts":   stats.Attempts,
		"elapsed_ms": stats.Elapsed.Milliseconds(),
		"chain":      s.snapshot(),
	})
}

func (s *server) send(w http.ResponseWriter, r *http.Request) {
	var body struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Amount uint64 `json:"amount"`
		Fee    uint64 `json:"fee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	from, err := parseID(body.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	to, err := parseID(body.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	priv, err := s.wallet.Private(from)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	_, nonce := s.chain.Balance(from)
	tx, err := chain.SignTransfer(priv, to, body.Amount, body.Fee, nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.chain.Submit(tx); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	raw, err := chain.MarshalTx(tx)
	if err == nil {
		go s.relayTx(raw, "")
	}
	writeJSON(w, map[string]any{"transaction": txView(tx, 0, false)})
}

func (s *server) walletView(w http.ResponseWriter, r *http.Request) {
	addrs := s.wallet.Addresses()
	items := make([]map[string]any, 0, len(addrs))
	for _, pub := range addrs {
		bal, nonce := s.chain.Balance(pub)
		immature, unlocks := s.chain.Immature(pub)
		items = append(items, map[string]any{
			"label":    s.wallet.Label(pub),
			"address":  hex.EncodeToString(pub[:]),
			"balance":  bal,
			"immature": immature,
			"unlocks":  unlocks,
			"nonce":    nonce,
		})
	}
	writeJSON(w, map[string]any{"addresses": items})
}

func (s *server) walletNew(w http.ResponseWriter, r *http.Request) {
	n := len(s.wallet.Addresses()) + 1
	pub, _, err := s.wallet.Create(fmt.Sprintf("address-%d", n))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"label":   s.wallet.Label(pub),
		"address": hex.EncodeToString(pub[:]),
		"balance": 0,
		"nonce":   0,
	})
}

func (s *server) block(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	blocks := s.chain.Blocks()
	for _, block := range blocks {
		if fmt.Sprint(block.Height) == id || hex.EncodeToString(block.Hash[:]) == id {
			writeJSON(w, blockView(blocks, block))
			return
		}
	}
	http.NotFound(w, r)
}

func (s *server) tx(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	tx, block, confirmed, ok := s.chain.LookupTx(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	view := txView(tx, block.Height, confirmed)
	if confirmed {
		view["block"] = hex.EncodeToString(block.Hash[:])
	}
	writeJSON(w, view)
}

func (s *server) address(w http.ResponseWriter, r *http.Request) {
	pub, err := parseID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	bal, nonce := s.chain.Balance(pub)
	immature, unlocks := s.chain.Immature(pub)
	hist := s.chain.History(pub)
	views := make([]map[string]any, 0, len(hist))
	for _, tx := range hist {
		_, block, confirmed, ok := s.chain.LookupTx(tx.ID)
		height := uint64(0)
		if ok && confirmed {
			height = block.Height
		}
		views = append(views, txView(tx, height, confirmed))
	}
	writeJSON(w, map[string]any{
		"address":      hex.EncodeToString(pub[:]),
		"balance":      bal,
		"immature":     immature,
		"unlocks":      unlocks,
		"nonce":        nonce,
		"label":        s.wallet.Label(pub),
		"transactions": views,
	})
}

func (s *server) peerStatus(w http.ResponseWriter, r *http.Request) {
	tip := s.chain.Tip()
	genesis, _ := s.chain.BlockAt(0)
	id := chain.ChainID()
	writeJSON(w, map[string]any{
		"height":   tip.Height,
		"hash":     hex.EncodeToString(tip.Hash[:]),
		"work":     s.chain.Work().String(),
		"genesis":  hex.EncodeToString(genesis.Hash[:]),
		"chain_id": hex.EncodeToString(id[:]),
	})
}

func (s *server) peerBlocks(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("from is required"))
		return
	}
	limit := 32
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, errors.New("limit"))
			return
		}
		limit = n
	}
	if limit > 64 {
		limit = 64
	}
	raw, err := chain.MarshalBlocks(s.chain.BlocksFrom(from, limit))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(raw)
}

func (s *server) peerAcceptBlocks(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	blocks, err := chain.UnmarshalBlocks(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(blocks) > 64 {
		writeErr(w, http.StatusBadRequest, errors.New("too many blocks"))
		return
	}
	adopted, err := s.chain.Adopt(blocks)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if adopted {
		log.Printf("adopted pushed blocks at height %d", s.chain.Tip().Height)
		go s.broadcastBlocks(blocks, "")
	}
	writeJSON(w, map[string]any{"adopted": adopted, "height": s.chain.Tip().Height})
}

func (s *server) peerChain(w http.ResponseWriter, r *http.Request) {
	raw, err := s.chain.Bytes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(raw)
}

func (s *server) peerAccept(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	adopted, err := s.chain.Consider(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if adopted {
		log.Printf("adopted pushed chain at height %d", s.chain.Tip().Height)
	}
	writeJSON(w, map[string]any{"adopted": adopted, "height": s.chain.Tip().Height})
}

func (s *server) peerTx(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	tx, err := chain.UnmarshalTx(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.chain.Submit(tx); err != nil {
		if strings.Contains(err.Error(), "already known") {
			writeJSON(w, map[string]any{"accepted": false})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	go s.relayTx(raw, "")
	writeJSON(w, map[string]any{"accepted": true})
}

func (s *server) snapshot() map[string]any {
	blocks := s.chain.Blocks()
	views := make([]map[string]any, 0, len(blocks))
	for i := len(blocks) - 1; i >= 0; i-- {
		views = append(views, blockView(blocks, blocks[i]))
	}
	now := uint32(time.Now().Unix())
	tip := blocks[len(blocks)-1]
	nextTime := now
	if nextTime <= tip.Time {
		nextTime = tip.Time + 1
	}
	id := chain.ChainID()
	return map[string]any{
		"height":            tip.Height,
		"work":              s.chain.Work().String(),
		"next_difficulty":   chain.RequiredDifficulty(blocks[0].Time, tip.Height+1, nextTime),
		"epoch_length":      chain.EpochLength,
		"ideal_block_time":  chain.IdealBlockTime,
		"half_life":         chain.HalfLife,
		"chain_id":          hex.EncodeToString(id[:]),
		"supply":            chain.Supply(tip.Height),
		"coin":              chain.Coin,
		"initial_subsidy":   chain.InitialSubsidy,
		"halving_interval":  chain.HalvingInterval,
		"coinbase_maturity": chain.CoinbaseMaturity,
		"genesis":           hex.EncodeToString(blocks[0].Hash[:]),
		"tip_schedule":      tipSchedule(blocks, tip),
		"mempool":           txViews(s.chain.Mempool(), 0, false),
		"peers":             s.peersSnapshot(),
		"blocks":            views,
	}
}

func tipSchedule(blocks []chain.Block, tip chain.Block) []string {
	epoch := chain.EpochSeed(blocks, tip.Height)
	id := chain.ChainID()
	schedule, err := dfpow.Schedule(id[:], epoch, tip.Header)
	if err != nil {
		return nil
	}
	return schedule
}

func blockView(blocks []chain.Block, block chain.Block) map[string]any {
	epoch := chain.EpochSeed(blocks, block.Height)
	id := chain.ChainID()
	schedule, err := dfpow.Schedule(id[:], epoch, block.Header)
	ops := []string{}
	if err == nil && len(schedule) >= 8 {
		ops = schedule[:8]
	}
	miner := ""
	if len(block.Txs) > 0 {
		miner = hex.EncodeToString(block.Txs[0].Pubkey[:])
	}
	return map[string]any{
		"height":       block.Height,
		"hash":         hex.EncodeToString(block.Hash[:]),
		"parent":       hex.EncodeToString(block.Parent[:]),
		"merkle":       hex.EncodeToString(block.Merkle[:]),
		"difficulty":   block.Difficulty,
		"nonce":        block.Nonce,
		"timestamp":    block.Time,
		"note":         block.Note,
		"subsidy":      block.Amount,
		"miner":        miner,
		"epoch_seed":   hex.EncodeToString(epoch),
		"schedule":     ops,
		"transactions": txViews(block.Txs, block.Height, true),
	}
}

func txViews(txs []chain.Tx, height uint64, confirmed bool) []map[string]any {
	out := make([]map[string]any, 0, len(txs))
	for _, tx := range txs {
		out = append(out, txView(tx, height, confirmed))
	}
	return out
}

func txView(tx chain.Tx, height uint64, confirmed bool) map[string]any {
	kind := "transfer"
	if tx.IsCoinbase() {
		kind = "coinbase"
	}
	view := map[string]any{
		"kind":      kind,
		"id":        hex.EncodeToString(tx.ID[:]),
		"from":      hex.EncodeToString(tx.Pubkey[:]),
		"amount":    tx.Amount,
		"fee":       tx.Fee,
		"nonce":     tx.Nonce,
		"confirmed": confirmed,
	}
	if confirmed {
		view["height"] = height
	}
	if tx.IsCoinbase() {
		view["note"] = tx.Note
	} else {
		view["to"] = hex.EncodeToString(tx.Recipient[:])
	}
	return view
}

func localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !loopback(r.RemoteAddr) {
			writeErr(w, http.StatusForbidden, errors.New("wallet and mining stay on localhost"))
			return
		}
		next(w, r)
	}
}

func loopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseID(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return out, errors.New("expected 32-byte hex")
	}
	copy(out[:], raw)
	return out, nil
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
