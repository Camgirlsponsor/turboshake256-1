# DFPoW-256

Dynamic Function Proof of Work, draft 0.1. A research specification and a reference implementation.

The consensus check is ordinary: an 84-byte header, a 32-byte digest, and `digest <= target`. The nonce does not select an input to one fixed hash. It selects the hash. BLAKE3 turns the header and the nonce into a seed, the seed expands into a 256-round program, and the program walks a shared epoch dataset and a private scratchpad. Verifiers rebuild that program. The block does not carry it.

The full write-up, including the byte-level spec and the test vectors, is [docs/DFPoW-256.md](docs/DFPoW-256.md).

## What changed from the sketch

The generated program stays. A few things that would have made it a poor consensus function do not.

- Every round is a ChaCha quarter-round, then one of the eight named operations, then a data-dependent memory step. The eight operations are shuffled inside each group of eight rounds, so every nonce runs each operation 32 times. There is no all-XOR program and no even multiplier to hunt for.
- The big buffer is a 1 MiB epoch dataset, mixed so a caller cannot seek into the BLAKE3 output and materialize one word. The nonce gets a 2 KiB private scratchpad, and a final sweep commits every scratch word. Filling 16–32 KiB from the nonce on every attempt would mostly time the XOF, and a seekable pad can be recomputed at the addresses that are actually read.
- The nonce is inside the seed and is mixed into the initial state. One construction covers both "the nonce picks the function" and "the function is given the nonce."
- Difficulty `d` means the top `d` bits of the digest are zero, with probability exactly `2^(-d)`. The work of that block is `2^d`. The difficulty word is part of the hashed header, and it has to equal the chain's retarget output.
- `chain_id` and the parameter triple are inside every BLAKE3 preimage. Changing the dataset size or the round count changes every digest.

This is not a claim of cryptographic security, and it is not an attempt to ban ASICs. A SHA-256 miner cannot run it. A chip built for this datapath could. The draft says that explicitly, and it keeps the dataset at 1 MiB so the algorithm can be specified and reimplemented before anyone pretends to know the right memory size.

## Layout

| Path | What it is |
| --- | --- |
| `docs/DFPoW-256.md` | Design, normative spec, vectors |
| `python/dfpow.py` | Independent reference hasher |
| `python/test_dfpow.py` | Vectors and structural checks |
| `internal/dfpow` | Go hasher. It must match the Python vectors |
| `internal/chain` | Ledger: coinbase, signed transfers, balances, most-work chain |
| `cmd/dfpowd` | Node, wallet, peer sync, and block explorer |
| `gpu/` | OpenCL hasher, one nonce per work-item |

## Running the tests

```bash
pip install -r requirements.txt
cd python && python3 -m unittest -v
```

The Python reference depends on the official BLAKE3 library (`blake3` 1.0.9). Draft 0.1 is identified by the vectors in the spec. An implementation that prints a different digest for nonce 1000 is not this draft.

## Prototype node

Go is the node. Python remains the check on the hasher. A node mines into `chain.json`, keeps spendable keys in `wallet.json`, and serves an explorer.

Payments are ed25519 transfers. The address is the public key. Each transfer carries a sequence number, an amount, and a fee. The coinbase pays the miner's address the subsidy plus the fees in that block. Balances are the result of replaying the chain. A node with more total work replaces the local chain.

```bash
go test ./...
go run ./cmd/dfpowd mine -n 12
go run ./cmd/dfpowd serve
```

The explorer listens on `127.0.0.1:8080`. It shows blocks, transactions, and addresses, and the wallet on that page can create an address and send coins. Mine a block to confirm a payment.

A second node with an empty data directory joins the first chain instead of mining a rival genesis:

```bash
go run ./cmd/dfpowd serve -addr 127.0.0.1:8080 -data /tmp/dfpow-a/chain.json -wallet /tmp/dfpow-a/wallet.json
go run ./cmd/dfpowd serve -addr 127.0.0.1:8081 -data /tmp/dfpow-b/chain.json -wallet /tmp/dfpow-b/wallet.json -peer 127.0.0.1:8080
```

Blocks and transactions are pushed to peers, and each node also asks its peers for a heavier chain every two seconds. Epoch length is 8 blocks, the ideal interval is 4 seconds, and the ASERT half-life is 16 seconds, so difficulty moves during a short session. Those are prototype settings. The write-up's recommended epoch for a longer-lived chain is 128 blocks. There is no authentication on the peer port; keep it on localhost unless you mean to share the chain.

## Hashing on a GPU

`gpu/dfpow-gpu` is the same draft in OpenCL C. The host builds the 1 MiB epoch dataset once and uploads it. The kernel `dfpow_batch` gives each work-item one nonce: BLAKE3 seed, 3,551-byte program tape, 256 rounds, private scratchpad, BLAKE3 finalizer. The difficulty word stays in the 76-byte prefix; the nonce is not written back over it.

The host binary includes that source and checks it against the draft vectors before launching the kernel. A GPU is used when the OpenCL platform has one. Otherwise the same kernel runs on a CPU device (pocl is enough).

```bash
sudo apt install ocl-icd-opencl-dev pocl-opencl-icd
cd gpu && make test
./dfpow-gpu bench 1024
```

`make test` runs the host vectors and a short OpenCL batch. Nonce 1000 must still digest to `747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640`. The scratchpad and the tape are private to each work-item, so a GPU will spill them and occupancy will be modest. This is a correct parallel hasher, not a tuned miner, and it does not change the draft's hardware conclusion: a purpose-built chip can still implement the same datapath.
