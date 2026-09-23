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
| `internal/chain` | Single-node chain: coinbase, epoch seed, integer ASERT |
| `cmd/dfpowd` | Miner and local block viewer |

## Running the tests

```bash
pip install -r requirements.txt
cd python && python3 -m unittest -v
```

The Python reference depends on the official BLAKE3 library (`blake3` 1.0.9). Draft 0.1 is identified by the vectors in the spec. An implementation that prints a different digest for nonce 1000 is not this draft.

## Prototype node

Go is the node. Python remains the check on the hasher. The prototype is one process: it mines into `chain.json` and can serve a page that shows each block's hash, difficulty, and the first eight accents of that nonce's program.

```bash
go test ./...
go run ./cmd/dfpowd mine -n 12
go run ./cmd/dfpowd serve
```

The viewer listens on `127.0.0.1:8080`. Epoch length is 8 blocks, the ideal interval is 4 seconds, and the ASERT half-life is 16 seconds, so difficulty moves during a short session. Those are prototype settings. The write-up's recommended epoch for a longer-lived chain is 128 blocks. Coinbase payments are labeled names, not signatures, and nothing is broadcast to a peer.
