# Hash Function Benchmarks

Compares preparation/proving/verification performance across different hash functions: Baseline (dummy), Skyscraper, SHA256, Keccak256, BLAKE3, and Poseidon.

## Hash Functions

| Hash       | Feature Flag      | Notes                                                               |
| ---------- | ----------------- | ------------------------------------------------------------------- |
| Baseline   | `hash-dummy`      | No-op hash, measures non-hashing overhead                           |
| Skyscraper | `hash-skyscraper` | Default                                                             |
| SHA256     | `hash-sha256`     | SHA2 family hash function                                           |
| Keccak256  | `hash-keccak256`  | SHA3 family hash function                                           |
| BLAKE3     | `hash-blake3`     | general-purpose hash                                                |
| Poseidon   | `hash-poseidon`   | Algebraic hash, ZK-friendly, but not suitable for native operations |

## Prerequisites

Install the Noir toolchain:

```bash
noirup --version v1.0.0-beta.11
```

Compile the age verification circuit used by the benchmark:

```bash
cd noir-examples/noir-passport-examples/complete_age_check
nargo compile
cd ../../..
```

## Running Benchmarks

Make sure you are in the root directory and run the script from root. This is because paths are relative to root.

```bash
# Default: 5 iterations
./scripts/benchmark_hash.sh

# Custom iterations
./scripts/benchmark_hash.sh 10
```

Results are saved to `benchmark_results/comparison_<timestamp>.md`.
