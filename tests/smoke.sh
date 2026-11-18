#!/usr/bin/env bash
# Smoke test: scans a throwaway local HTTP server and checks input validation.
set -u
cd "$(dirname "$0")/.."
PORT=18080
python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1

fail=0
check() { if eval "$2"; then echo "  ok   $1"; else echo "  FAIL $1"; fail=1; fi; }

out=$(./netscanner -h 127.0.0.1 -p 18000-18100 -t 300)
check "finds open port"        'grep -q "TCP $PORT" <<<"$out"'
check "single port with -p N"  './netscanner -h 127.0.0.1 -p $PORT | grep -q "Ports:   $PORT - $PORT"'
check "rejects reversed range" '! ./netscanner -h 127.0.0.1 -p 500-100 2>/dev/null'
check "rejects port > 65535"   '! ./netscanner -h 127.0.0.1 -p 70000 2>/dev/null'
check "rejects zero timeout"   '! ./netscanner -h 127.0.0.1 -t 0 2>/dev/null'
check "rejects huge CIDR"      '! ./netscanner -h 10.0.0.0/8 2>/dev/null'
check "CIDR skips net/bcast"   './netscanner -h 127.0.0.0/30 -p $PORT -t 300 | grep -q "(2 hosts)"'
exp=$(./netscanner -h 127.0.0.1 -p $PORT -t 300 -e)
check "explain: unknown port is LOW" 'grep -q "\[LOW     \] $PORT" <<<"$exp"'
check "explain: grade A (98/100)"    'grep -q "Grade: A (98/100)" <<<"$exp"'
check "explain: nothing open = A"    './netscanner -h 127.0.0.1 -p 1 -t 300 -e | grep -q "Grade: A (100/100)"'
TMP=$(mktemp)
./netscanner -h 127.0.0.1 -p $PORT -t 300 -e -o "$TMP" >/dev/null
check "explain goes into -o file"    'grep -q "Grade: A" "$TMP"'
rm -f "$TMP"
ST=$(mktemp -u)
dscan() { ./netscanner -h 127.0.0.1 -p 18000-18100 -t 300 -d "$ST"; }
dscan >/dev/null; r=$?
check "diff: first run is baseline (exit 0)" '[ $r -eq 0 ] && grep -q "127.0.0.1 tcp $PORT" "$ST"'
dscan >/dev/null; r=$?
check "diff: no change (exit 0)"             '[ $r -eq 0 ]'
python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 & SERVER2=$!; sleep 1
d=$(dscan); r=$?
check "diff: new port (exit 2)"              '[ $r -eq 2 ] && grep -q "NEW .* 18081" <<<"$d"'
kill $SERVER2; sleep 0.5
d=$(dscan); r=$?
check "diff: closed port (exit 2)"           '[ $r -eq 2 ] && grep -q "CLOSED .* 18081" <<<"$d"'
./netscanner -h 127.0.0.1 -p 1 -t 300 -d "$ST" >/dev/null
check "diff: other ranges kept in state"     'grep -q "tcp $PORT" "$ST"'
echo "not a state file" > "$ST"
./netscanner -h 127.0.0.1 -p 1 -t 300 -d "$ST" >/dev/null 2>&1; r=$?
check "diff: refuses to overwrite other files" '[ $r -eq 1 ] && grep -q "not a state file" "$ST"'
rm -f "$ST"
exit $fail
