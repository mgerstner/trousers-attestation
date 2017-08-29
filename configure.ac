AC_INIT([tpm2_util],
	[0.1],
	[https://github.com/mgerstner/trousers-attestation/issues],
	[],
	[https://github.com/mgerstner/trousers-attestation])

AC_PROG_CXX
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([TCLAP], [tclap])
PKG_CHECK_MODULES([OPENSSL], [openssl])
AC_CHECK_LIB([tspi], [Tspi_Context_LoadKeyByUUID])

AC_OUTPUT
