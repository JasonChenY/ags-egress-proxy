#!/usr/bin/env bash
# AGS 沙箱内 iptables 透明代理配置（方案 A 客户端 · 推荐，性能优于 TUN）
#
# 模式一（默认启用）：本机出流量 —— nat OUTPUT + REDIRECT，仅 TCP
# 模式二（注释供选）：网关转发   —— mangle PREROUTING + TPROXY
#   适用场景：沙箱内还有别的 netns / 容器把本机当网关出网
#
# 用法: ./setup-redirect.sh <SOCKS_IP> [SOCKS_PORT] [--gateway <入接口>]
set -euo pipefail

SOCKS_IP=${1:?用法: $0 <SOCKS_IP> [SOCKS_PORT] [--gateway <入接口>]}
SOCKS_PORT=${2:-1080}
PROXY_PORT=15000    # sandbox-redirect -mode redirect 监听端口
TPROXY_PORT=15001   # sandbox-redirect -mode tproxy  监听端口

# 排除网段：仅环回与链路本地恒不走代理
# 注意：私网段（10/172.16/192.168）可能是要访问的目标，故不在此排除，让其走代理
EXCLUDE_CIDRS=(
  127.0.0.0/8
  169.254.0.0/16
)

# ==================== 模式一：本机出流量（nat OUTPUT + REDIRECT）====================
iptables -t nat -N AGS_OUT 2>/dev/null || true
iptables -t nat -F AGS_OUT

for cidr in "${EXCLUDE_CIDRS[@]}"; do
  iptables -t nat -A AGS_OUT -d "$cidr" -j RETURN
done
# 关键：到网关自身的连接必须直连，否则代理进程自己也被 REDIRECT → 死循环
iptables -t nat -A AGS_OUT -d "$SOCKS_IP" -j RETURN

iptables -t nat -A AGS_OUT -p tcp -j REDIRECT --to-ports "$PROXY_PORT"
iptables -t nat -C OUTPUT -p tcp -j AGS_OUT 2>/dev/null || \
  iptables -t nat -A OUTPUT -p tcp -j AGS_OUT

# ==================== 模式二：网关转发（mangle PREROUTING + TPROXY）====================
# 启用方法：解开注释；<入接口> 改为承接下游流量的实际接口（如 veth / bridge）
GATEWAY_IF=""
for arg in "$@"; do
  case "$arg" in
    --gateway) GATEWAY_IF="SET_BELOW" ;;
    *) [ "$GATEWAY_IF" = "SET_BELOW" ] && GATEWAY_IF="$arg" ;;
  esac
done

if [ -n "$GATEWAY_IF" ] && [ "$GATEWAY_IF" != "SET_BELOW" ]; then
  echo "启用 TPROXY 网关模式，入接口: $GATEWAY_IF"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # fwmark 1 的包查 100 号路由表：本地环回，交给本机 TPROXY 监听
  ip rule add fwmark 1 table 100 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

  iptables -t mangle -N AGS_IN 2>/dev/null || true
  iptables -t mangle -F AGS_IN
  for cidr in "${EXCLUDE_CIDRS[@]}"; do
    iptables -t mangle -A AGS_IN -d "$cidr" -j RETURN
  done
  iptables -t mangle -A AGS_IN -d "$SOCKS_IP" -j RETURN
  iptables -t mangle -A AGS_IN -p tcp -j TPROXY \
    --on-port "$TPROXY_PORT" --tproxy-mark 1
  iptables -t mangle -C PREROUTING -i "$GATEWAY_IF" -p tcp -j AGS_IN 2>/dev/null || \
    iptables -t mangle -A PREROUTING -i "$GATEWAY_IF" -p tcp -j AGS_IN
fi

echo "---- nat AGS_OUT ----"
iptables -t nat -S AGS_OUT
echo
echo "完成。启动代理进程（两个终端或 systemd/supervisor 托管）:"
echo "  redirect 模式（本机出流量）:"
echo "    AGS_SANDBOX_ID=<沙箱ID> AGS_SOCKS_SECRET=<base64密钥> \\"
echo "    ./sandbox-redirect -mode redirect -proxy ${SOCKS_IP}:${SOCKS_PORT}"
echo
echo "  tproxy 模式（网关转发，需先开 --gateway）:"
echo "    AGS_SANDBOX_ID=<沙箱ID> AGS_SOCKS_SECRET=<base64密钥> \\"
echo "    ./sandbox-redirect -mode tproxy -proxy ${SOCKS_IP}:${SOCKS_PORT}"
echo
echo "回滚:"
echo "  iptables -t nat -D OUTPUT -p tcp -j AGS_OUT && iptables -t nat -F AGS_OUT && iptables -t nat -X AGS_OUT"
echo "  [tproxy] iptables -t mangle -D PREROUTING -i $GATEWAY_IF -p tcp -j AGS_IN && iptables -t mangle -F AGS_IN && iptables -t mangle -X AGS_IN && ip rule del fwmark 1 table 100 && ip route del local 0.0.0.0/0 dev lo table 100"
