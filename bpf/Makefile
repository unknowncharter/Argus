# BPF CO-RE build for agent_observer
CLANG  ?= clang
LLVM_STRIP ?= llvm-strip
ARCH   := $(shell uname -m)
# For x86_64 use x86; aarch64 use arm64
ifeq ($(ARCH),x86_64)
  ARCH := x86
endif
ifeq ($(ARCH),aarch64)
  # keep aarch64
endif

KERNEL_HEADERS ?= /lib/modules/$(shell uname -r)/build
# libbpf headers (bpf_helpers.h, bpf_tracing.h) - from libbpf-dev or kernel tools/lib/bpf
LIBBPF_HEADERS ?= /usr/include
# Arch include path so that asm/types.h resolves (linux/types.h -> asm/types.h).
# Some kernel-header packages don't ship arch/.../asm/types.h; use userspace asm path as fallback.
KERNEL_ARCH_INC ?= $(KERNEL_HEADERS)/arch/$(ARCH)/include
KERNEL_ARCH_GEN ?= $(KERNEL_HEADERS)/arch/$(ARCH)/include/generated
# Fallback for asm/types.h (e.g. Ubuntu kernel headers without full arch tree)
ASM_TYPES_FALLBACK ?= /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I$(KERNEL_HEADERS)/include -I$(LIBBPF_HEADERS) -Wall
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include/uapi -I$(KERNEL_HEADERS)/include/generated
BPF_CFLAGS += -I$(KERNEL_ARCH_INC) -I$(KERNEL_ARCH_GEN)
# After kernel paths so <asm/types.h> from uapi/linux/types.h can resolve
BPF_CFLAGS += -I$(ASM_TYPES_FALLBACK)

OUT_DIR := .
OBJ     := agent_observer.bpf.o

.PHONY: all clean

all: $(OUT_DIR)/$(OBJ)

$(OUT_DIR)/$(OBJ): agent_observer.bpf.c agent_observer.h
	$(CLANG) $(BPF_CFLAGS) -c agent_observer.bpf.c -o $@
	# Do not strip: cilium/ebpf needs BTF in the object to load maps

clean:
	rm -f $(OUT_DIR)/$(OBJ)
