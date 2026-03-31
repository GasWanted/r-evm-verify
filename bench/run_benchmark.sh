#!/usr/bin/env bash
# Benchmark: r-evm-verify vs Halmos
# Compares wall-clock time on the same contracts.
set -e

cd "$(dirname "$0")/.."

# Environment for Z3 build
export C_INCLUDE_PATH=/usr/lib/gcc/x86_64-linux-gnu/11/include
export LIBCLANG_PATH=/home/box/.local/lib/python3.10/site-packages/clang/native
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/11/include"

echo "=============================================="
echo "r-evm-verify vs Halmos Benchmark"
echo "=============================================="
echo ""
echo "CPU cores: $(nproc)"
echo "Halmos version: $(halmos --version 2>&1)"
echo "r-evm-verify: $(cargo run -p r-evm-verify -- --version 2>&1 | grep -oP '[\d.]+' || echo 'dev')"
echo ""

# Build r-evm-verify in release mode
echo "Building r-evm-verify (release)..."
cargo build -p r-evm-verify --release 2>&1 | tail -1
REVM="./target/release/r-evm-verify"
echo ""

printf "%-25s %-15s %-15s %-10s %-20s\n" "Contract" "r-evm-verify" "Halmos" "Speedup" "Findings"
printf "%-25s %-15s %-15s %-10s %-20s\n" "--------" "------------" "------" "-------" "--------"

# --- Benchmark 1: SimpleOverflow ---
echo "" >&2
echo "Running Bench1: SimpleOverflow..." >&2

# r-evm-verify
start=$(date +%s%N)
revm_out=$($REVM scan bench/r-evm-verify/SimpleOverflow.hex 2>/dev/null || true)
end=$(date +%s%N)
revm_ms=$(( (end - start) / 1000000 ))
revm_findings=$(echo "$revm_out" | grep -c "issue\|Overflow\|Reentrancy" || echo "0")

# Halmos
start=$(date +%s%N)
halmos_out=$(cd bench/halmos && halmos --contract Bench1Test --function check_overflow --loop 2 --solver-timeout-assertion 10000 2>&1 || true)
end=$(date +%s%N)
halmos_ms=$(( (end - start) / 1000000 ))
halmos_findings=$(echo "$halmos_out" | grep -c "Counterexample\|FAIL" || echo "0")

if [ "$halmos_ms" -gt 0 ]; then
    speedup=$(echo "scale=1; $halmos_ms / $revm_ms" | bc 2>/dev/null || echo "N/A")
else
    speedup="N/A"
fi

printf "%-25s %-15s %-15s %-10s %-20s\n" \
    "SimpleOverflow" "${revm_ms}ms" "${halmos_ms}ms" "${speedup}x" "revm:$revm_findings hal:$halmos_findings"

# --- Benchmark 2: VulnerableVault (reentrancy) ---
echo "Running Bench2: VulnerableVault..." >&2

start=$(date +%s%N)
revm_out=$($REVM scan bench/r-evm-verify/Reentrancy.hex 2>/dev/null || true)
end=$(date +%s%N)
revm_ms=$(( (end - start) / 1000000 ))
revm_findings=$(echo "$revm_out" | grep -c "issue\|Reentrancy" || echo "0")

# Halmos doesn't have built-in reentrancy detection, so we measure scan time only
start=$(date +%s%N)
halmos_out=$(cd bench/halmos && halmos --contract Bench1Test --function check_overflow --loop 2 --solver-timeout-assertion 10000 2>&1 || true)
end=$(date +%s%N)
halmos_ms=$(( (end - start) / 1000000 ))

if [ "$halmos_ms" -gt 0 ]; then
    speedup=$(echo "scale=1; $halmos_ms / $revm_ms" | bc 2>/dev/null || echo "N/A")
else
    speedup="N/A"
fi

printf "%-25s %-15s %-15s %-10s %-20s\n" \
    "VulnerableVault" "${revm_ms}ms" "${halmos_ms}ms (ref)" "${speedup}x" "revm:$revm_findings"

# --- Benchmark 3: SimpleERC20 ---
echo "Running Bench3: SimpleERC20..." >&2

start=$(date +%s%N)
revm_out=$($REVM scan bench/r-evm-verify/ERC20.hex 2>/dev/null || true)
end=$(date +%s%N)
revm_ms=$(( (end - start) / 1000000 ))
revm_findings=$(echo "$revm_out" | grep -c "issue\|Overflow\|Reentrancy" || echo "0")

start=$(date +%s%N)
halmos_out=$(cd bench/halmos && halmos --contract Bench3Test --function check_transfer_conservation --loop 2 --solver-timeout-assertion 10000 2>&1 || true)
end=$(date +%s%N)
halmos_ms=$(( (end - start) / 1000000 ))
halmos_findings=$(echo "$halmos_out" | grep -c "Counterexample\|FAIL" || echo "0")

if [ "$halmos_ms" -gt 0 ]; then
    speedup=$(echo "scale=1; $halmos_ms / $revm_ms" | bc 2>/dev/null || echo "N/A")
else
    speedup="N/A"
fi

printf "%-25s %-15s %-15s %-10s %-20s\n" \
    "SimpleERC20" "${revm_ms}ms" "${halmos_ms}ms" "${speedup}x" "revm:$revm_findings hal:$halmos_findings"

echo ""
echo "Notes:"
echo "  r-evm-verify: symbolic execution with Z3 path pruning + overflow detection"
echo "  Halmos: symbolic execution with Z3 (Python)"
echo "  Halmos doesn't have built-in reentrancy detection (Bench2 is reference only)"
