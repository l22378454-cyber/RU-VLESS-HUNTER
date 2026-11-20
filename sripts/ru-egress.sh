#!/usr/bin/env bash
# Использование: sudo ./scripts/ru-egress.sh socks5://user:pass@1.2.3.4:1080 -- xray-knife http -f TCP_config.txt -t 48
set -euo pipefail
PROXY="$1"; shift; [ "${1:-}" = "--" ] && shift
NS=ru-egress
U=$(echo "$PROXY" | sed -E 's#^socks5://##; s#@.*##; s#:.*##')
P=$(echo "$PROXY" | sed -E 's#^socks5://##; s#@.*##; s#.*:##')
H=$(echo "$PROXY" | sed -E 's#^socks5://##; s#.*@##; s#:.*##')
PORT=$(echo "$PROXY" | sed -E 's#.*:##')

ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

cat > /tmp/sb.json <<EOF
{"log":{"level":"warn"},
 "inbounds":[{"type":"tun","address":["172.19.0.1/30"],"auto_route":true,"strict_route":false}],
 "outbounds":[{"type":"socks","server":"$H","server_port":$PORT,
               "username":"$U","password":"$P"}]}
EOF

ip netns exec "$NS" sing-box run -c /tmp/sb.json &
SB=$!
sleep 3
ip netns exec "$NS" "$@"
RC=$?
kill $SB 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
exit $RC
