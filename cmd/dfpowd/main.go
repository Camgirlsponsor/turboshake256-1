package main

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
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
	fmt.Fprintf(os.Stderr, "usage:\n  dfpowd mine -n 12 [-data chain.json]\n  dfpowd serve [-addr 127.0.0.1:8080] [-data chain.json]\n")
}

func open(path string) *chain.Chain {
	c, err := chain.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	return c
}

func mine(args []string) {
	fs := flag.NewFlagSet("mine", flag.ExitOnError)
	n := fs.Int("n", 8, "blocks to mine after the current tip")
	path := fs.String("data", "chain.json", "chain file")
	note := fs.String("note", "local", "coinbase name")
	_ = fs.Parse(args)
	c := open(*path)
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
	line := fmt.Sprintf("height %-4d  d=%-2d  nonce=%-8d  hash=%s  %s",
		block.Height, block.Difficulty, block.Nonce, hex.EncodeToString(block.Hash[:8]), block.Note)
	if stats.Attempts > 0 {
		line += fmt.Sprintf("  %d hashes  %s", stats.Attempts, stats.Elapsed.Round(time.Millisecond))
	}
	fmt.Println(line)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	path := fs.String("data", "chain.json", "chain file")
	_ = fs.Parse(args)
	c := open(*path)
	log.Printf("DFPoW prototype at http://%s  tip %d", *addr, c.Tip().Height)
	log.Fatal(http.ListenAndServe(*addr, newHandler(c)))
}

func newHandler(c *chain.Chain) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	})
	mux.HandleFunc("/api/chain", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, snapshot(c))
	})
	mux.HandleFunc("/api/mine", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Note string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		block, stats, err := c.Mine(body.Note, runtime.NumCPU())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]any{
			"block":      blockView(c.Blocks(), block),
			"attempts":   stats.Attempts,
			"elapsed_ms": stats.Elapsed.Milliseconds(),
			"chain":      snapshot(c),
		})
	})
	return mux
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

func snapshot(c *chain.Chain) map[string]any {
	blocks := c.Blocks()
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
		"height":           tip.Height,
		"work":             c.Work().String(),
		"next_difficulty":  chain.RequiredDifficulty(blocks[0].Time, tip.Height+1, nextTime),
		"epoch_length":     chain.EpochLength,
		"ideal_block_time": chain.IdealBlockTime,
		"half_life":        chain.HalfLife,
		"chain_id":         hex.EncodeToString(id[:]),
		"blocks":           views,
	}
}

func blockView(blocks []chain.Block, block chain.Block) map[string]any {
	epoch := chain.EpochSeed(blocks, block.Height)
	id := chain.ChainID()
	schedule, err := dfpow.Schedule(id[:], epoch, block.Header)
	ops := []string{}
	if err == nil && len(schedule) >= 8 {
		ops = schedule[:8]
	}
	return map[string]any{
		"height":     block.Height,
		"hash":       hex.EncodeToString(block.Hash[:]),
		"parent":     hex.EncodeToString(block.Parent[:]),
		"difficulty": block.Difficulty,
		"nonce":      block.Nonce,
		"timestamp":  block.Time,
		"note":       block.Note,
		"subsidy":    block.Amount,
		"epoch_seed": hex.EncodeToString(epoch),
		"schedule":   ops,
	}
}
