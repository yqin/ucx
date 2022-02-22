#
# Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

bin_PROGRAMS = ucx_allgather

noinst_HEADERS = \
	ucx_core.h \
	ucx_allgather_common.h \
	ucx_allgather_daemon.h \
	ucx_allgather_client.h

ucx_allgather_LDFLAGS  = -ldl -lglib-2.0 -g


ucx_allgather_CXXFLAGS = \
	$(BASE_CXXFLAGS) \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib64/glib-2.0/include

ucx_allgather_CPPFLAGS = $(BASE_CPPFLAGS) -I/usr/include/glib-2.0/ -I/usr/lib64/glib-2.0/include -g

ucx_allgather_LDADD    = \
	$(top_builddir)/src/ucs/libucs.la \
	$(top_builddir)/src/uct/libuct.la \
	$(top_builddir)/src/ucp/libucp.la

ucx_allgather_SOURCES = \
	ucx_core.c \
	ucx_allgather_common.c \
	ucx_allgather_daemon.c \
	ucx_allgather_client.c \
	ucx_allgather.c
