ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = ndff

AM_CPPFLAGS = @PCAP_INC@
AM_CFLAGS = @PTHREAD_CFLAGS@ @JSON_C_CFLAGS@ @NDPI_CFLAGS@ @MSGPACK_CFLAGS@

LDADD = @JSON_C_LIBS@ @PTHREAD_LIBS@ @PCAP_LIB@ @NDPI_LIBS@ @MSGPACK_LIBS@
AM_LDFLAGS = -static

ndff_SOURCES = ndff.c

init_ddir = $(sysconfdir)/rc.d/init.d
init_d_SCRIPTS = ndffd
CLEANFILES = $(init_d_SCRIPTS)

ndff.o: ndff.c

