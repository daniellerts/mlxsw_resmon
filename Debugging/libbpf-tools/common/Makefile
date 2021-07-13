# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
INCLUDES := $(LIBBPF_INCLUDE)
LIBS := libcommon.a
libcommon.a-OBJECTS := \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/map_helpers.o \
	#

include ../common.mk

all: libcommon.a

libcommon.a: $(libcommon.a-OBJECTS)
	ar cru $@ $^

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(foreach tgt,$(APPS) $(LIBS),$(tgt) $($(tgt)-OBJECTS))
