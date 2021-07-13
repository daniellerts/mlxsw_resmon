# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
LIBBPF_SRC := libbpf/src
export LIBBPF_OUTPUT := $(abspath .libbpf-output)
export LIBBPF_INCLUDE := -I$(LIBBPF_OUTPUT)
export LIBBPF_OBJ := $(abspath $(LIBBPF_OUTPUT)/libbpf.a)
export top_srcdir := $(abspath .)
DIRS = src

.PHONY: all
all: $(DIRS)

.PHONY: $(DIRS)
$(DIRS): %: %/all

define RECURSE_DIR
$(1)/clean:
	$(Q)$(MAKE) -C $$(@D) clean
$(1)/%: $$(LIBBPF_OBJ)
	$(Q)$(MAKE) -C $$(@D) $$*
endef

$(foreach dir,$(DIRS),$(eval $(call RECURSE_DIR,$(dir))))

common/%: $(LIBBPF_OBJ)
	$(Q)$(MAKE) -C $(@D) $*
common/clean:
	$(Q)$(MAKE) -C $(@D) clean

.PHONY: clean
clean: $(foreach dir,$(DIRS),$(dir)/clean)
	$(call msg,CLEAN)
	$(Q)rm -rf $(LIBBPF_OUTPUT) $(APPS)

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) \
		| $(LIBBPF_OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(LIBBPF_OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# delete failed targets
.DELETE_ON_ERROR:

# keep the libbpf intermediate target
.SECONDARY:

