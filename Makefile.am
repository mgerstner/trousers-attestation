AM_CXXFLAGS = -std=c++11 -Wall -Werror $(OPENSSL_CFLAGS)

src_tpm_util_SOURCES = src/tpm_session.cxx \
	src/tpm_types.cxx \
	src/tpm_util.cxx
src_tpm_util_LDADD = $(OPENSSL_LIBS)

bin_PROGRAMS = src/tpm_util
