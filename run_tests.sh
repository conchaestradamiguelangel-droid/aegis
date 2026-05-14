#!/usr/bin/env bash
# AEGIS — Test runner completo
# Uso: ./run_tests.sh [--gate-only] [--verbose]

set -euo pipefail
cd "$(dirname "$0")"

GATE_ONLY=false
VERBOSE=false
for arg in "$@"; do
  [ "$arg" = "--gate-only" ] && GATE_ONLY=true
  [ "$arg" = "--verbose" ]   && VERBOSE=true
done

PASS=0; FAIL=0; KNOWN=0
run_test() {
  local name="$1" file="$2" is_gate="$3"
  local output
  output=$(python3 "$file" 2>&1)
  local rc=$?
  local result=$(echo "$output" | grep -E 'RESULTADO:|Resultado:' | head -1 | sed 's/^[[:space:]]*//')
  if [ $rc -eq 0 ]; then
    echo "  ✓ $name — $result"
    ((PASS++)) || true
  else
    if [ "$is_gate" = "true" ]; then
      echo "  ✗ GATE FAIL: $name — $result"
      [ "$VERBOSE" = "true" ] && echo "$output" | grep -E '✗|FAIL' || true
      ((FAIL++)) || true
    else
      echo "  ⚠ KNOWN: $name — $result"
      ((KNOWN++)) || true
    fi
  fi
}

echo
echo "═══════════════════════════════════════════════════"
echo "  AEGIS Security Test Suite"
echo "═══════════════════════════════════════════════════"
echo
echo "── GATE (security-critical) ─────────────────────"
run_test "C0 Crypto"          tests/test_crypto.py      true
run_test "C0-C9 System"       tests/test_aegis.py       true
run_test "C5 AMTD"            tests/test_amtd.py        true
run_test "C3 Detector"        tests/test_detector.py    true
run_test "C7 Forensic"        tests/test_forensic.py    true
run_test "E2E Pipeline"       tests/test_e2e_pipeline.py true
run_test "Red Team A1"        tests/redteam_A1.py       true
run_test "Red Team A2"        tests/redteam_A2.py       true
run_test "Red Team B1"        tests/redteam_B1.py       true
run_test "Red Team B2"        tests/redteam_B2.py       true
run_test "Red Team C1"        tests/redteam_C1.py       true
run_test "Red Team C2"        tests/redteam_C2.py       true
run_test "Red Team D1"        tests/redteam_D1.py       true
run_test "Red Team D2"        tests/redteam_D2.py       true
run_test "Red Team E1"        tests/redteam_E1.py       true
run_test "Red Team E2"        tests/redteam_E2.py       true
echo

if [ "$GATE_ONLY" = "false" ]; then
  echo "── KNOWN LIMITS (non-blocking) ──────────────────"
  run_test "C6 Bubble"         tests/test_bubble.py      false
  run_test "C8 Learning"       tests/test_learning.py    false
  run_test "Load E1"           tests/test_load.py        false
  echo
fi

echo "═══════════════════════════════════════════════════"
echo "  Gate passed: $PASS | Gate failed: $FAIL | Known limits: $KNOWN"
echo "═══════════════════════════════════════════════════"
echo
[ $FAIL -eq 0 ] && echo "  ✅ SISTEMA LISTO PARA DEPLOY" && exit 0
echo "  ❌ GATE FALLIDO — NO DEPLOY" && exit 1
