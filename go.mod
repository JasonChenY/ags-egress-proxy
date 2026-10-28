module ags-egress-proxy

go 1.23.1

toolchain go1.23.3

require (
	gopkg.in/yaml.v3 v3.0.1
	// gVisor 无常规 semver tag，版本取自合成的 go 分支：go get gvisor.dev/gvisor@go
	gvisor.dev/gvisor v0.0.0-20250723014020-312865986418
)
