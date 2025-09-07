BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -Wall

GO ?= go
BIN_DIR := ./bin

BPF_SRCS := \
	bpf/process_filter.bpf.c \
	bpf/xdp_dropper.bpf.c \
	bpf/xdp_dropper_dynamic.bpf.c

BPF_OBJS := $(patsubst %.c,%.o,$(BPF_SRCS))

GO_BINS := \
	$(BIN_DIR)/dynamic-gatekeeper \
	$(BIN_DIR)/gatekeeper \
	$(BIN_DIR)/process-gatekeeper

.PHONY: all bpf go clean run dirs

all: dirs bpf go

dirs:
	@mkdir -p $(BIN_DIR)

bpf: $(BPF_OBJS)

%.o: %.c
	@echo "==> Building BPF object: $@"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

go: $(GO_BINS)

$(BIN_DIR)/dynamic-gatekeeper:
	@echo "==> Building dynamic-gatekeeper"
	$(GO) build -o $@ ./cmd/dynamic

$(BIN_DIR)/gatekeeper:
	@echo "==> Building gatekeeper"
	$(GO) build -o $@ ./cmd/static

$(BIN_DIR)/process-gatekeeper:
	@echo "==> Building process-gatekeeper"
	$(GO) build -o $@ ./process-filter

BIN ?= process-gatekeeper
run: dirs bpf go
	@echo "==> Running $(BIN) (with sudo)"
	@sudo $(BIN_DIR)/$(BIN)

clean:
	@echo "==> Cleaning"
	@rm -f $(BPF_OBJS)
	@rm -f $(GO_BINS)
