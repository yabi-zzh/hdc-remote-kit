BINARY  := hdc-remote
PKG     := ./cmd/hdc-remote
DIST    := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOEXE   := $(shell go env GOEXE)

# 交叉编译目标平台
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all help build run test fmt vet clean release

all: build

## help: 显示可用目标
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'

## build: 为当前平台构建二进制
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY)$(GOEXE) $(PKG)

## run: 直接运行服务
run:
	go run $(PKG)

## test: 运行全部测试
test:
	go test ./...

## fmt: 格式化源码
fmt:
	gofmt -w internal cmd

## vet: 运行静态检查
vet:
	go vet ./...

## clean: 清理构建产物
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

## release: 交叉编译全部目标平台到 dist/（产物名含版本号与平台）
release: clean
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(DIST)/$(BINARY)-$(VERSION)-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
	@echo "done -> $(DIST)/"
