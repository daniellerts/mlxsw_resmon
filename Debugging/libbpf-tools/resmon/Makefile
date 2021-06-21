# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
INCLUDES := $(COMMON_INCLUDE)
APPS := resmon
resmon-OBJECTS :=		\
	$(OUTPUT)/resmon.o	\
	$(OUTPUT)/resmon-back.o	\
	$(OUTPUT)/resmon-c.o	\
	$(OUTPUT)/resmon-d.o	\
	$(OUTPUT)/resmon-jrpc.o	\
	$(OUTPUT)/resmon-sock.o	\
	#
SYSTEMD_UNITS :=				\
	$(OUTPUT)/resmon.service		\
	#

BUILT := $(APPS) $(SYSTEMD_UNITS)

PACKAGE = resmon
include ../common.mk

.PHONY: all
all: $(BUILT)

.PHONY: install
install: $(BUILT)
	$(call do_install_program,$(APPS),$(BINDIR))
	$(call do_install_program,$(SYSTEMD_UNITS),$(SYSTEMDSYSTEMUNITDIR))

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

resmon: CFLAGS += $(shell pkgconf --libs libelf json-c libsystemd)
resmon: $(resmon-OBJECTS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) -lz $^ -o $@

$(OUTPUT)/%.o: %.c resmon.h $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%: %.in | $(OUTPUT)
	$(call msg,SED,$*)
	$(Q)sed -e '$(VAR_SUBSTITUTIONS)' $< > $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(foreach tgt,$(APPS),$($(tgt)-OBJECTS))
	$(Q)rm -f $(BUILT)
	$(Q)rmdir $(OUTPUT)

.DELETE_ON_ERROR:
