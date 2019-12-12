AC_PREREQ([2.63])

AC_INIT([flatpak-sample-authenticator],
        [0.1],
        [https://github.com/flatpak/flatpak-sample-authenticator/issues],
        [flatpak-sample-authenticator],
        [http://flatpak.org/])

GLIB_REQS=2.44

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_STDC
AC_DISABLE_STATIC

LT_PREREQ([2.2.6])
LT_INIT([disable-static])

GETTEXT_PACKAGE=flatpak-sample-authenticator
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE",
                   [The prefix for our gettext translation domains.])

AC_CONFIG_SRCDIR([sample-authenticator.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.13.4 no-define no-dist-gzip dist-xz tar-ustar foreign subdir-objects])
AC_PROG_SED

PKG_PROG_PKG_CONFIG([0.24])

AC_SUBST([GDBUS_CODEGEN], [`$PKG_CONFIG --variable gdbus_codegen gio-2.0`])

AC_ARG_WITH(dbus_service_dir,
        AS_HELP_STRING([--with-dbus-service-dir=PATH],[choose directory for dbus service files, [default=PREFIX/share/dbus-1/services]]),
        with_dbus_service_dir="$withval", with_dbus_service_dir=$datadir/dbus-1/services)
DBUS_SERVICE_DIR=$with_dbus_service_dir
AC_SUBST(DBUS_SERVICE_DIR)

AC_ARG_WITH([systemduserunitdir],
            [AS_HELP_STRING([--with-systemduserunitdir=DIR],
                            [Directory for systemd user service files (default=PREFIX/lib/systemd/user)])],
    [],
    dnl This is deliberately not ${libdir}: systemd units always go in
    dnl .../lib, never .../lib64 or .../lib/x86_64-linux-gnu
    [with_systemduserunitdir='${prefix}/lib/systemd/user'])
AC_SUBST([systemduserunitdir], [$with_systemduserunitdir])

AC_ARG_WITH(flatpak_interfaces_dir,
        AS_HELP_STRING([--with-flatpak-interfaces-dir=PATH],[choose directory for Flatpak interface files, [default=PREFIX/share/dbus-1/interfaces]]),
        [[FLATPAK_INTERFACES_DIR="$withval"]],
        [PKG_CHECK_VAR([FLATPAK_INTERFACES_DIR], [flatpak], [interfaces_dir])])
AC_SUBST(FLATPAK_INTERFACES_DIR)

# Enable silent rules is available
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

if test "x$GCC" = "xyes"; then
  case " $CFLAGS " in
  *[[\ \	]]-Wall[[\ \	]]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac
fi

AX_VALGRIND_CHECK

PKG_PROG_PKG_CONFIG([0.24])

PKG_CHECK_MODULES(BASE, [glib-2.0 >= $GLIB_REQS gio-2.0 gio-unix-2.0 libsoup-2.4 json-glib-1.0])


AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT

echo ""
echo "          flatpak-sample-authenticator"
echo "          ============================"
echo ""
