# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(top_srcdir)/tools/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
SYSCONFDIR = $(PREFIX)/etc
LOCALSTATEDIR = $(PREFIX)/var
RUNSTATEDIR = $(LOCALSTATEDIR)/run
DOCDIR = $(DATAROOTDIR)/doc/$(PACKAGE)
MANDIR = $(DATAROOTDIR)/man
MAN1DIR = $(MANDIR)/man1
SYSTEMDSYSTEMUNITDIR = $(shell pkgconf --variable=systemdsystemunitdir systemd)
DESTDIR =

VAR_SUBSTITUTIONS = 			\
	s|@BINDIR@|$(BINDIR)|g;		\
	s|@SYSCONFDIR@|$(SYSCONFDIR)|g;	\
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

define __do_install
	$(call msg,INSTALL,$1)
	$(Q)if [ ! -d '$(DESTDIR)$2' ]; then		\
		$4 -d -m 755 '$(DESTDIR)$2';	\
	fi;
	$(Q)$4 $(if $3,-m $3,) $1 '$(DESTDIR)$2'
endef

define do_install_program
	$(call __do_install,$1,$2,$3,$(INSTALL_PROGRAM))
endef

define do_install_data
	$(call __do_install,$1,$2,$3,$(INSTALL_DATA))
endef
