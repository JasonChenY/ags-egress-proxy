#!/usr/bin/env bash
# ags-egress-proxy 统一入口：按 MODE 选择 gateway / redirect / tproxy / tun
#
# 通用环境变量：
#   MODE                gateway | redirect | tproxy | tun   （默认 gateway）
#
# 客户端三模式（redirect / tproxy / tun）共用：
#   AGS_SANDBOX_ID      沙箱 ID
#   AGS_SOCKS_SECRET    base64 密钥（须与网关 secret 一致）
#   AGS_SOCKS_PROXY     网关地址 ip:port（脚本会自动拆出 ip / port）
#
# gateway 模式：
#   GATEWAY_CONFIG      配置文件路径（默认 /app/gateway.yaml）
#
# tproxy 模式额外：
#   GATEWAY_IF          承接下游流量的入接口（PREROUTING -i）
#
# redirect / tproxy 可选：
#   REDIRECT_LISTEN     覆盖默认监听地址
#
# tun 模式可选：
#   TUN_DEV / TUN_MTU / TUN_LOCAL_IP
set -euo pipefail

MODE=${MODE:-gateway}
BIN=/app/bin
SCRIPTS=/app/scripts

split_proxy() {
  : "${AGS_SOCKS_PROXY:?redirect/tproxy/tun 模式需要 AGS_SOCKS_PROXY=ip:port}"
  PROXY_IP=${AGS_SOCKS_PROXY%:*}
  PROXY_PORT=${AGS_SOCKS_PROXY##*:}
}

case "$MODE" in
  gateway)
    exec "$BIN/gateway" -config "${GATEWAY_CONFIG:-/app/gateway.yaml}"
    ;;

  redirect)
    split_proxy
    "$SCRIPTS/setup-redirect.sh" "$PROXY_IP" "$PROXY_PORT"
    exec "$BIN/sandbox-redirect" -mode redirect -proxy "$AGS_SOCKS_PROXY" \
      ${REDIRECT_LISTEN:+-listen "$REDIRECT_LISTEN"}
    ;;

  tproxy)
    split_proxy
    : "${GATEWAY_IF:?tproxy 模式需要 GATEWAY_IF=<入接口>}"
    "$SCRIPTS/setup-redirect.sh" "$PROXY_IP" "$PROXY_PORT" --gateway "$GATEWAY_IF"
    exec "$BIN/sandbox-redirect" -mode tproxy -proxy "$AGS_SOCKS_PROXY" \
      ${REDIRECT_LISTEN:+-listen "$REDIRECT_LISTEN"}
    ;;

  tun)
    split_proxy
    "$SCRIPTS/setup-tun.sh" "$PROXY_IP" "$PROXY_PORT"
    exec "$BIN/sandbox-tun2socks" -proxy "$AGS_SOCKS_PROXY" \
      ${TUN_DEV:+-dev "$TUN_DEV"} \
      ${TUN_MTU:+-mtu "$TUN_MTU"} \
      ${TUN_LOCAL_IP:+-local-ip "$TUN_LOCAL_IP"}
    ;;

  *)
    echo "未知 MODE=$MODE（可选: gateway | redirect | tproxy | tun）" >&2
    exit 1
    ;;
esac
