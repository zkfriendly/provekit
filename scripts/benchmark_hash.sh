#!/bin/bash
set -e

ITERATIONS=${1:-5}
CIRCUIT="noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json"
INPUT="noir-examples/noir-passport-examples/complete_age_check/Prover.toml"
RESULTS="benchmark_results"
TS=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS"

calc() { python3 -c "$1"; }

extract_mem() {
    local bytes=$(echo "$1" | grep "maximum resident set size" | awk '{print $1}')
    python3 -c "print(int($bytes / 1024 / 1024))"
}

stats_time() {
    local arr=("$@")
    local sum=0 min=${arr[0]} max=${arr[0]}
    for v in "${arr[@]}"; do
        sum=$(calc "print($sum + $v)")
        min=$(calc "print(min($min, $v))")
        max=$(calc "print(max($max, $v))")
    done
    calc "print(f'{$sum / ${#arr[@]}:.2f} {$min:.2f} {$max:.2f}')"
}

stats_mem() {
    local arr=("$@")
    local sum=0 min=${arr[0]} max=${arr[0]}
    for v in "${arr[@]}"; do
        sum=$(calc "print($sum + $v)")
        min=$(calc "print(min($min, $v))")
        max=$(calc "print(max($max, $v))")
    done
    calc "print(f'{int($sum / ${#arr[@]})} {int($min)} {int($max)}')"
}

run_benchmark() {
    local name="$1" features="$2"
    local workdir="$RESULTS/${name}_work"
    mkdir -p "$workdir"
    
    echo "=== $name ==="
    cargo build --release --bin provekit-cli --no-default-features --features "$features" 2>&1 | grep -E "Compiling|Finished" || true
    
    local -a prep_t prove_t verify_t prep_m prove_m verify_m
    
    for i in $(seq 1 $ITERATIONS); do
        echo "  Run $i/$ITERATIONS"
        
        local t0=$(calc 'import time; print(time.time())')
        local out=$(/usr/bin/time -l ./target/release/provekit-cli prepare "$CIRCUIT" --pkp "$workdir/prover.pkp" --pkv "$workdir/verifier.pkv" 2>&1)
        local t1=$(calc 'import time; print(time.time())')
        prep_t+=($(calc "print(f'{$t1 - $t0:.3f}')"))
        prep_m+=($(extract_mem "$out"))
        
        t0=$(calc 'import time; print(time.time())')
        out=$(/usr/bin/time -l ./target/release/provekit-cli prove "$workdir/prover.pkp" "$INPUT" --out "$workdir/proof.np" 2>&1)
        t1=$(calc 'import time; print(time.time())')
        prove_t+=($(calc "print(f'{$t1 - $t0:.3f}')"))
        prove_m+=($(extract_mem "$out"))
        
        t0=$(calc 'import time; print(time.time())')
        out=$(/usr/bin/time -l ./target/release/provekit-cli verify "$workdir/verifier.pkv" "$workdir/proof.np" 2>&1)
        t1=$(calc 'import time; print(time.time())')
        verify_t+=($(calc "print(f'{$t1 - $t0:.3f}')"))
        verify_m+=($(extract_mem "$out"))
    done
    
    read prep_t_avg prep_t_min prep_t_max <<< $(stats_time "${prep_t[@]}")
    read prove_t_avg prove_t_min prove_t_max <<< $(stats_time "${prove_t[@]}")
    read verify_t_avg verify_t_min verify_t_max <<< $(stats_time "${verify_t[@]}")
    read prep_m_avg prep_m_min prep_m_max <<< $(stats_mem "${prep_m[@]}")
    read prove_m_avg prove_m_min prove_m_max <<< $(stats_mem "${prove_m[@]}")
    read verify_m_avg verify_m_min verify_m_max <<< $(stats_mem "${verify_m[@]}")
    
    eval "${name}_prep_t='$prep_t_avg ($prep_t_min-$prep_t_max)'"
    eval "${name}_prove_t='$prove_t_avg ($prove_t_min-$prove_t_max)'"
    eval "${name}_verify_t='$verify_t_avg ($verify_t_min-$verify_t_max)'"
    eval "${name}_prep_m='$prep_m_avg ($prep_m_min-$prep_m_max)'"
    eval "${name}_prove_m='$prove_m_avg ($prove_m_min-$prove_m_max)'"
    eval "${name}_verify_m='$verify_m_avg ($verify_m_min-$verify_m_max)'"
}

echo "ProveKit Hash Benchmark - $ITERATIONS iterations"
echo ""

run_benchmark "dummy" "hash-dummy"
run_benchmark "skyscraper" "hash-skyscraper"
run_benchmark "sha256" "hash-sha256"

echo ""
echo "=== Results ==="
echo ""
echo "Time (s) - avg (min-max):"
echo "| Phase   | Dummy | Skyscraper | SHA256 |"
echo "|---------|-------|------------|--------|"
echo "| Prepare | $dummy_prep_t | $skyscraper_prep_t | $sha256_prep_t |"
echo "| Prove   | $dummy_prove_t | $skyscraper_prove_t | $sha256_prove_t |"
echo "| Verify  | $dummy_verify_t | $skyscraper_verify_t | $sha256_verify_t |"
echo ""
echo "Memory (MB) - avg (min-max):"
echo "| Phase   | Dummy | Skyscraper | SHA256 |"
echo "|---------|-------|------------|--------|"
echo "| Prepare | $dummy_prep_m | $skyscraper_prep_m | $sha256_prep_m |"
echo "| Prove   | $dummy_prove_m | $skyscraper_prove_m | $sha256_prove_m |"
echo "| Verify  | $dummy_verify_m | $skyscraper_verify_m | $sha256_verify_m |"

cat > "$RESULTS/comparison_${TS}.md" << EOF
# Hash Benchmark - $(date)

Iterations: $ITERATIONS

## Time (s) - avg (min-max)

| Phase   | Dummy | Skyscraper | SHA256 |
|---------|-------|------------|--------|
| Prepare | $dummy_prep_t | $skyscraper_prep_t | $sha256_prep_t |
| Prove   | $dummy_prove_t | $skyscraper_prove_t | $sha256_prove_t |
| Verify  | $dummy_verify_t | $skyscraper_verify_t | $sha256_verify_t |

## Memory (MB) - avg (min-max)

| Phase   | Dummy | Skyscraper | SHA256 |
|---------|-------|------------|--------|
| Prepare | $dummy_prep_m | $skyscraper_prep_m | $sha256_prep_m |
| Prove   | $dummy_prove_m | $skyscraper_prove_m | $sha256_prove_m |
| Verify  | $dummy_verify_m | $skyscraper_verify_m | $sha256_verify_m |
EOF

echo ""
echo "Saved: $RESULTS/comparison_${TS}.md"
