# ags-egress-proxy 多模式镜像
# 一个镜像内含 gateway / sandbox-redirect / sandbox-tun2socks 三个二进制，
# 运行时按环境变量 MODE 选择入口（见 docker-entrypoint.sh）。
#
# 支持交叉编译：builder 固定跑在构建主机原生架构（$BUILDPLATFORM），由 Go 用
# GOARCH 交叉编译出目标架构二进制（纯 Go、CGO 关闭，无需 QEMU、快）。
#
# 构建（在 x86 机器上原生构建 amd64，最省心，apt 不经 QEMU）：
#   docker buildx build -t ags-egress-proxy --load .
# 显式指定目标平台（交叉/多架构，需 buildx）：
#   docker buildx build --platform linux/amd64 -t ags-egress-proxy --load .
#   docker buildx build --platform linux/amd64,linux/arm64 -t <repo>/ags-egress-proxy --push .
# envd 默认带入（amd64）；若构建 arm64 镜像不想带 envd，加 --build-arg ENVD_ARCH=arm64
#
# 运行示例见文件末尾注释。

# 全局 ARG：供 FROM 行选择 envd 来源。用独立变量 ENVD_ARCH（带默认值 amd64），
# 与编译用的 TARGETARCH 解耦——这样不传 --platform 也不会出现 FROM envd-（空）报错，
# 且不会污染 builder 阶段的 TARGETARCH（交叉编译仍由 buildx 注入的 TARGETARCH 驱动）。
# 要让 arm64 镜像不带 envd：构建时加 --build-arg ENVD_ARCH=arm64
ARG ENVD_ARCH=amd64

# ---------- 构建阶段（交叉编译）----------
# --platform=$BUILDPLATFORM：builder 跑在构建主机原生架构，不被 QEMU 模拟
FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS builder

# buildx 按 --platform 注入目标 OS/ARCH（无 --platform 时为空 → Go 用原生架构）
ARG TARGETOS
ARG TARGETARCH

# 国内构建环境走七牛 goproxy 镜像（proxy.golang.org 被墙，DNS 直接超时）
# 覆盖：docker build --build-arg GOPROXY=... ；GONOSUMDB 关校验库避免 sum.golang.org 超时
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=off

WORKDIR /src

# 先拉依赖，利用层缓存（go.sum 必须随仓库提交；tun2socks 依赖 gVisor）
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 纯 Go、无 cgo → 静态二进制。GOOS/GOARCH 让 Go 交叉编译出目标架构。
# -mod=mod：按需补全 gVisor 间接依赖（仓库 go.mod/go.sum 可能不全）。
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=mod -trimpath -ldflags "-s -w" \
    -o /out/ ./gateway ./sandbox-redirect ./sandbox-tun2socks

# ---------- envd 来源（按目标架构选择）----------
# amd64：从官方镜像取 envd 到暂存 rootfs（envd 镜像多为 amd64-only）
FROM debian:bookworm-slim AS envd-amd64
COPY --from=ccr.ccs.tencentyun.com/ags-image/envd:v0.5.14 --chmod=755 \
     /usr/bin/envd /envd-rootfs/usr/bin/envd

# 其他架构（arm64 等）：空暂存 rootfs，不带入 envd
FROM debian:bookworm-slim AS envd-arm64
RUN mkdir -p /envd-rootfs

# 选择 envd 来源：ENVD_ARCH=amd64 带入 envd；=arm64 则为空（不带 envd）
FROM envd-${ENVD_ARCH} AS envd-stage

# ---------- 运行阶段 ----------
# 用 glibc 基础镜像，保证外部 COPY 进来的 envd 可运行
FROM debian:bookworm-slim

# 运行依赖 + 调试工具
# 客户端模式需要 iptables / iproute2 / bash / gawk（配套 setup 脚本）
# 本阶段按目标平台构建（apt 自动取对应架构的包）；ltrace 在 arm64 无包，单独 best-effort
ENV DEBIAN_FRONTEND=noninteractive
# 换用腾讯云公网镜像（deb822 的 debian.sources 与旧版 sources.list 都处理）
RUN for f in /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; do \
      [ -f "$f" ] && sed -i 's|deb.debian.org|mirrors.cloud.tencent.com|g' "$f" || true; \
    done
RUN apt-get update && apt-get install -y --no-install-recommends \
    # === 脚本运行所需 ===
    bash \
    gawk \
    # === 网络调试 ===
    iproute2 \
    iputils-ping \
    dnsutils \
    curl \
    wget \
    netcat-openbsd \
    telnet \
    tcpdump \
    traceroute \
    nmap \
    # === 进程/系统调试 ===
    procps \
    htop \
    strace \
    lsof \
    sysstat \
    # === 文本/文件 ===
    vim-tiny \
    less \
    jq \
    tree \
    # === iptables / nftables ===
    iptables \
    iptables-persistent \
    ipset \
    conntrack \
    nftables \
    # === 其他 ===
    ca-certificates \
    gnupg \
    # ltrace 在部分架构（如 Debian arm64）无包，单独 best-effort 安装
    && (apt-get install -y --no-install-recommends ltrace \
        || echo "ltrace 不可用（可能是 arm64），已跳过") \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 二进制、脚本、网关示例配置
COPY --from=builder /out/ /app/bin/
COPY scripts/ /app/scripts/
COPY gateway/gateway.yaml /app/gateway.yaml
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/scripts/*.sh /app/docker-entrypoint.sh

# AGS envd：仅 amd64 带入（arm64 的暂存 rootfs 为空，这里相当于不复制）
COPY --from=envd-stage /envd-rootfs/ /

# ---------- 环境变量（默认值 / 占位，运行时覆盖）----------
# 注意：AGS_SOCKS_SECRET 属敏感信息，不在此设默认值，运行时用 -e 传入
ENV MODE=gateway \
    GATEWAY_CONFIG=/app/gateway.yaml \
    AGS_SANDBOX_ID="" \
    AGS_SOCKS_PROXY="" \
    GATEWAY_IF="" \
    REDIRECT_LISTEN="" \
    TUN_DEV="" \
    TUN_MTU="" \
    TUN_LOCAL_IP=""

ENTRYPOINT ["/app/docker-entrypoint.sh"]

# ---------- 运行示例 ----------
# 网关（公网机器，需挂载/烤入真实 gateway.yaml）：
#   docker run -d -p 1080:1080 \
#     -e MODE=gateway \
#     -v $PWD/gateway.yaml:/app/gateway.yaml:ro \
#     ags-egress-proxy
#
# redirect 客户端（沙箱侧，改本机出流量）：
#   docker run -d --cap-add=NET_ADMIN \
#     -e MODE=redirect \
#     -e AGS_SANDBOX_ID=<沙箱ID> -e AGS_SOCKS_SECRET=<base64密钥> \
#     -e AGS_SOCKS_PROXY=172.16.137.128:1080 \
#     ags-egress-proxy
#
# tproxy 客户端（本机做转发网关）：
#   docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW \
#     --sysctl net.ipv4.ip_forward=1 \
#     -e MODE=tproxy -e GATEWAY_IF=eth0 \
#     -e AGS_SANDBOX_ID=<沙箱ID> -e AGS_SOCKS_SECRET=<base64密钥> \
#     -e AGS_SOCKS_PROXY=172.16.137.128:1080 \
#     ags-egress-proxy
#
# tun 客户端（需要 /dev/net/tun，宿主先 modprobe tun）：
#   docker run -d --cap-add=NET_ADMIN --device /dev/net/tun \
#     -e MODE=tun \
#     -e AGS_SANDBOX_ID=<沙箱ID> -e AGS_SOCKS_SECRET=<base64密钥> \
#     -e AGS_SOCKS_PROXY=172.16.137.128:1080 \
#     ags-egress-proxy
