# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
INCLUDES := $(COMMON_INCLUDE)
CFLAGS := -g -Wall

APPS := resmon
EXTRA_BIN := resmon-exporter.py
resmon-OBJECTS :=		\
	$(OUTPUT)/resmon.o	\
	$(OUTPUT)/resmon-back.o	\
	$(OUTPUT)/resmon-c.o	\
	$(OUTPUT)/resmon-d.o	\
	$(OUTPUT)/resmon-dl.o	\
	$(OUTPUT)/resmon-jrpc.o	\
	$(OUTPUT)/resmon-reg.o	\
	$(OUTPUT)/resmon-sock.o	\
	$(OUTPUT)/resmon-stat.o	\
	#
SYSTEMD_UNITS :=				\
	$(OUTPUT)/resmon.service		\
	$(OUTPUT)/resmon-exporter.service	\
	#
EXTRA_CLEAN :=			\
	$(OUTPUT)/resmon.bpf.o	\
	$(OUTPUT)/resmon.skel.h	\
	#
TESTS :=		\
	test.sh		\
	#

BUILT := $(APPS) $(SYSTEMD_UNITS)

PACKAGE = resmon
include ../common.mk

.PHONY: all
all: $(BUILT)

.PHONY: install
install: $(BUILT) $(EXTRA_BIN)
	$(call do_install_program,$(APPS) $(EXTRA_BIN),$(BINDIR))
	$(call do_install_program,$(SYSTEMD_UNITS),$(SYSTEMDSYSTEMUNITDIR))

.PHONY: test
test: $(TESTS:%=run-%)

run-%: % resmon
	$(call msg,RUN,$*)
	$(Q)./$*

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

resmon: CFLAGS += $(shell pkgconf --libs libelf json-c libsystemd \
		    libnl-3.0 libnl-genl-3.0)
resmon: $(resmon-OBJECTS) $(LIBBPF_OBJ) $(COMMON_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) -lz $^ -o $@

$(OUTPUT)/%.o: %.c resmon.h mlxsw.h $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/resmon-dl.o: INCLUDES += $(shell pkgconf --cflags libnl-3.0 \
				     libnl-genl-3.0)

$(OUTPUT)/resmon.bpf.o: INCLUDES += $(LIBBPF_INCLUDE)
$(OUTPUT)/resmon.bpf.o: resmon.bpf.c resmon.h ../common/vmlinux.h
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/resmon-back.o: INCLUDES += $(LIBBPF_INCLUDE) -I$(OUTPUT)
$(OUTPUT)/resmon-back.o: $(OUTPUT)/resmon.skel.h

%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%: %.in | $(OUTPUT)
	$(call msg,SED,$*)
	$(Q)sed -e '$(VAR_SUBSTITUTIONS)' $< > $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(foreach tgt,$(APPS),$($(tgt)-OBJECTS))
	$(Q)rm -f $(BUILT) $(EXTRA_CLEAN)
	$(Q)rmdir $(OUTPUT)

.DELETE_ON_ERROR:
