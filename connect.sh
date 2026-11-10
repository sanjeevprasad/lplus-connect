#!/bin/sh
# One connect attempt: restart sdpd with RESP/LINKPUB, tap the phone into
# the connect flow, then wait on the engine markers. Usage: connect.sh <resp> <linkpub-hex>
set -u
resp="${1:-ok2}"
linkpub="${2:-}"
cd "$(dirname "$0")" || exit 2

pkill -f "lplus sdpd" 2>/dev/null
RESP="$resp" LINKPUB="$linkpub" nohup ./target/debug/lplus sdpd \
  --csp 10151 \
  --log ../capture/sdp-rs.bin > /tmp/lplus-sdpd.log 2>&1 &
sleep 5
adb shell input tap 636 2473   # Got it popup
sleep 1.5
adb shell input tap 713 1250   # PC card
./waitlex.sh "openConnection result|CONNECTION_FAIL|scp_connect_result" 25

echo "=== engine outcome ==="
tail -c 300000 "${TAPLOG:-$(dirname "$0")/../capture/tap-logcat.txt}" \
  | grep -aiE "openConnection result|EstablishLink|onBeforeConnect|CloudProbe|scp_connect_result|CONNECTION|link_switch|getSupportConnectorTypes|TLV|deserial|link info|LinkInfo|service.?node" \
  | tail -20 | cut -c1-195
echo "=== sdpd tcp ==="
grep -a "\[tcp\]\|\[pub\]" /tmp/lplus-sdpd.log | tail -8
