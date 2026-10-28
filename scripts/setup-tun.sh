#!/usr/bin/env bash
# AGS 沙箱内 TUN 模式配置（方案 A 客户端 · tun2socks 路线）
# 前提：镜像内含 iproute2（ip 命令）；沙箱默认 privileged，可直接 tuntap
# 用法: ./setup-tun.sh <SOCKS_IP> [SOCKS_PORT]
set -euo pipefail

SOCKS_IP=${1:?用法: $0 <SOCKS_IP> [SOCKS_PORT]}
SOCKS_PORT=${2:-1080}
DEV=tun0
LOCAL_IP=198.18.0.1          # 与 sandbox-tun2socks -local-ip 一致
FAKE_PREFIX=198.18.0.0/15    # 本机侧网段，仅作 tun0 地址，不做 fake DNS

# 例外网段：仅环回与链路本地走原网卡直连
# 注意：私网段（10/172.16/192.168）可能是要访问的目标，故不排除，让其走 tun→代理
EXCLUDE_CIDRS=(
  169.254.0.0/16
  127.0.0.0/8
)

DEFAULT_ROUTE=$(ip route show default | head -1)
GW=$(echo "$DEFAULT_ROUTE"  | awk '{print $3}')
WAN_DEV=$(echo "$DEFAULT_ROUTE" | awk '{print $5}')
echo "默认网关: $GW  出接口: $WAN_DEV"

# 1. 建 TUN 设备（内核 CONFIG_TUN=y，沙箱 privileged 可直接建）
# 预检 /dev/net/tun：容器里常缺此节点，缺则尝试补建，失败给出明确指引
if [ ! -c /dev/net/tun ]; then
  echo "警告: /dev/net/tun 不存在，尝试创建…" >&2
  mkdir -p /dev/net
  if ! mknod /dev/net/tun c 10 200 2>/dev/null; then
    echo "错误: 无法创建 /dev/net/tun。请确认：" >&2
    echo "  1) 容器启动带 --device /dev/net/tun（或 --privileged）" >&2
    echo "  2) 宿主机已加载 tun 模块: modprobe tun" >&2
    echo "  3) 容器具备 CAP_NET_ADMIN" >&2
    exit 1
  fi
  chmod 600 /dev/net/tun
fi
# 设备创建：幂等。已存在则复用（避免 TUNSETIFF: Device or resource busy）
if ip link show "$DEV" >/dev/null 2>&1; then
  echo "$DEV 已存在，复用"
else
  ip tuntap add dev "$DEV" mode tun
fi
ip addr add "$LOCAL_IP/15" dev "$DEV" 2>/dev/null || true   # 地址可能已存在
ip link set "$DEV" mtu 1400 up

# 2. 例外路由：走原网卡直连（防环路 + 保住 DNS / 控制面 / socks 通道本身）
ip route replace "$SOCKS_IP/32" via "$GW" dev "$WAN_DEV"
for dns in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf); do
  ip route replace "$dns/32" via "$GW" dev "$WAN_DEV" 2>/dev/null || true
done
for cidr in "${EXCLUDE_CIDRS[@]}"; do
  ip route replace "$cidr" via "$GW" dev "$WAN_DEV" 2>/dev/null || true
done

# 2b. 数据面网关回程保护（关键）：
# AGS 控制面/数据面连接全部是 inbound（客户端→数据网关→from_world 端口映射→沙箱），
# from_world 只 DNAT 目标不改源 → 沙箱内连接 peer = 数据网关出口 IP。
# TUN 全量导流会把这些连接的回程也吸进 tun0 → 控制面断连。
#
# 方案一（默认，零配置）：按 conntrack 方向排除——别人发起的连接（REPLY 方向）走原网卡，
#   自动覆盖后续新建的 inbound 连接，无需预知网关网段。
# 方案二（叠加兜底）：学习当前 established 连接的 peer IP，逐个 /32 直连。
#   适合无 iptables 的镜像；只保护脚本运行时的存量连接。
CONNTRACK_GUARD=1
if [ "${NO_CONNTRACK_GUARD:-0}" = "1" ] || ! command -v iptables >/dev/null 2>&1; then
  CONNTRACK_GUARD=0
fi
if [ "$CONNTRACK_GUARD" = "1" ]; then
  ip rule add fwmark 100 table 100 2>/dev/null || true
  ip route replace default via "$GW" dev "$WAN_DEV" table 100 2>/dev/null || true
  iptables -t mangle -N AGS_REPLY 2>/dev/null || true
  iptables -t mangle -F AGS_REPLY
  # 只有"非本机发起"的连接回程是 REPLY 方向；本机应用主动出连始终是 ORIGINAL 方向
  iptables -t mangle -A AGS_REPLY -m conntrack --ctstate ESTABLISHED --ctdir REPLY \
    -j MARK --set-mark 100
  iptables -t mangle -C OUTPUT -j AGS_REPLY 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j AGS_REPLY
  echo "已启用 conntrack 回程保护（fwmark 100 → table 100 → $WAN_DEV）"
fi
if [ "${LEARN_PEERS:-$([ "$CONNTRACK_GUARD" = "0" ] && echo 1 || echo 0)}" = "1" ]; then
  echo "学习存量 established 连接 peer（无 conntrack 保护时的兜底）…"
  ss -Htn state established 2>/dev/null | awk '{print $4}' \
    | sed -E 's/^\[?([0-9a-fA-F.:]+)\]?:[0-9]+$/\1/' | sort -u \
    | while read -r ip; do
        case "$ip" in ""|*"("*|*:*) continue ;; esac
        ip route replace "$ip/32" via "$GW" dev "$WAN_DEV" 2>/dev/null || true
      done
  echo "提示：兜底模式只保护脚本运行时的存量连接；新 inbound 连接仍可能断，"
  echo "      建议手工把数据网关网段补进 EXCLUDE_CIDRS（获取方法见 README）。"
fi

# 3. 把其余 IPv4 全量导入 tun0（0/1 + 128/1 比默认路由更精确，优先命中）
ip route replace 0.0.0.0/1 dev "$DEV"
ip route replace 128.0.0.0/1 dev "$DEV"

echo "---- 路由表 ----"
ip route show
[ "$CONNTRACK_GUARD" = "1" ] && { echo "---- 策略路由 ----"; ip rule show; }

echo
echo "完成。启动代理进程:"
echo "  AGS_SANDBOX_ID=<沙箱ID> AGS_SOCKS_SECRET=<base64密钥> \\"
echo "  ./sandbox-tun2socks -proxy ${SOCKS_IP}:${SOCKS_PORT}"
echo
echo "回滚:"
echo "  ip route del 0.0.0.0/1 dev $DEV && ip route del 128.0.0.0/1 dev $DEV"
[ "$CONNTRACK_GUARD" = "1" ] && echo "  iptables -t mangle -D OUTPUT -j AGS_REPLY && iptables -t mangle -F AGS_REPLY && iptables -t mangle -X AGS_REPLY && ip rule del fwmark 100 table 100 && ip route del default table 100"
echo "  ip link del $DEV"
