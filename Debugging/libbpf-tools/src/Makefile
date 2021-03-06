# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = emadlatency emadump trapagg resmon

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/map_helpers.o \
	#

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/emadlatency.o: emadlatency.h
$(OUTPUT)/emadlatency.bpf.o: emadlatency.h

$(OUTPUT)/resmon.o: resmon.h
$(OUTPUT)/resmon-back.o: resmon.h
$(OUTPUT)/resmon-c.o: resmon.h
$(OUTPUT)/resmon-d.o: resmon.h
$(OUTPUT)/resmon-jrpc.o: resmon.h
$(OUTPUT)/resmon-reg.o: resmon.h
$(OUTPUT)/resmon-sock.o: resmon.h
$(OUTPUT)/resmon-stat.o: resmon.h
$(OUTPUT)/resmon.bpf.o: resmon.h

# Build application binary
emadlatency trapagg: %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT) $(OUTPUT)/%.bpf.o
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

resmon: CFLAGS += $(shell pkgconf --libs libelf libnl-3.0 libnl-genl-3.0 json-c)
resmon:		$(OUTPUT)/resmon.o \
		$(OUTPUT)/resmon-back.o \
		$(OUTPUT)/resmon-c.o \
		$(OUTPUT)/resmon-d.o \
		$(OUTPUT)/resmon-jrpc.o \
		$(OUTPUT)/resmon-reg.o \
		$(OUTPUT)/resmon-sock.o \
		$(OUTPUT)/resmon-stat.o \
		$(OUTPUT)/resmon-dl.o \
		$(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT) $(OUTPUT)/resmon.bpf.o
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) -lz $^ -o $@
$(OUTPUT)/resmon-dl.o: INCLUDES += $(shell pkgconf --cflags libnl-3.0 libnl-genl-3.0)
$(OUTPUT)/resmon-dl.o: $(OUTPUT)/resmon.skel.h
$(OUTPUT)/resmon-d.o: $(OUTPUT)/resmon.skel.h

emadump: %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -lpcap -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

