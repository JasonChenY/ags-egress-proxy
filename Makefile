# Makefile —— 交叉编译 ags-egress-proxy
#
# 这些二进制依赖 Linux 专有能力（iptables REDIRECT/TPROXY、SO_ORIGINAL_DST；
# sandbox-tun2socks 另需 TUN + gVisor），因此目标平台固定为 Linux；在
# macOS/arm 开发机上交叉编译出可在 x86 机器上运行的格式。
#
# 常用：
#   make              交叉编译默认目标到 bin/linux_amd64/（默认 x86-64）
#   make GOARCH=386   编译 32 位 x86（i386）
#   make gateway      只编译某一个
#   make tidy         go mod tidy（仅拉取 yaml.v3，gVisor 已剔除）
#   make clean        清理产物
#
# 说明：sandbox-tun2socks 依赖 gVisor，当前以 //go:build ignore 暂时排除，
# 且 go.mod 已移除 gVisor require；默认只编译 gateway 与 sandbox-redirect。
# 重新启用 tun2socks 见下方 tun2socks 目标的注释。

# ---- 目标平台 ----
# x86 机器：64 位用 amd64，32 位用 386。
GOOS   ?= linux
GOARCH ?= amd64

# 纯 Go、无 cgo —— 关掉 CGO 产出静态二进制，可在任意同架构 Linux 上直接运行，
# 不依赖目标机的 glibc 版本。
CGO_ENABLED ?= 0

# 产物目录按平台分开，避免不同架构互相覆盖。
BIN_DIR := bin/$(GOOS)_$(GOARCH)

# 可执行目标（目录名即包名）。
# sandbox-tun2socks 依赖 gVisor，当前以 //go:build ignore 排除，不在默认构建内。
CMDS := gateway sandbox-redirect

# 链接参数：-s -w 去符号表/调试信息，减小体积。
# （源码未定义 version 变量，故不做 -X 注入，避免写进不存在的符号。）
LDFLAGS := -s -w

GOBUILD := CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
           go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all build $(CMDS) tun2socks tidy clean info

all: build

build: $(CMDS)

# 每个命令独立成目标，便于单独构建：make gateway
$(CMDS):
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/$@ ./$@
	@echo "built $(BIN_DIR)/$@"

# 重新启用 sandbox-tun2socks（gVisor）：
#   1) 在 go.mod 恢复一个有效版本的 gvisor.dev/gvisor；
#   2) 删除 sandbox-tun2socks/main.go 顶部的 //go:build ignore 行；
#   3) make tidy；之后再 make tun2socks。
tun2socks:
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/sandbox-tun2socks ./sandbox-tun2socks
	@echo "built $(BIN_DIR)/sandbox-tun2socks"

# go mod tidy（仅 yaml.v3）。
tidy:
	go mod tidy

clean:
	rm -rf bin/

# 查看当前交叉编译配置。
info:
	@echo "GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED)"
	@echo "OUT=$(BIN_DIR)"
