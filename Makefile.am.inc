libexec_PROGRAMS += \
	flatpak-authenticator \
	$(NULL)

service_in_files += authenticator/flatpak-authenticator.service.in
systemduserunit_DATA += authenticator/flatpak-authenticator.service

service_in_files += authenticator/org.flatpak.Authenticator.service.in
dbus_service_DATA += authenticator/org.flatpak.Authenticator.service

flatpak_authenticator_SOURCES = \
	authenticator/flatpak-authenticator.c	\
	authenticator/flatpak-authenticator-webflow.h	\
	authenticator/flatpak-authenticator-webflow.c	\
	$(NULL)

flatpak_authenticator_LDADD = \
	$(AM_LDADD) \
	$(OSTREE_LIBS) \
	$(SOUP_LIBS) \
	$(JSON_LIBS) \
	$(BASE_LIBS) \
	libflatpak-common.la \
	libflatpak-common-base.la \
	libglnx.la \
	$(NULL)

flatpak_authenticator_CFLAGS = \
	-DFLATPAK_COMPILATION \
	$(AM_CFLAGS) \
	$(OSTREE_CFLAGS) \
	$(BASE_CFLAGS) \
	$(SOUP_CFLAGS) \
	$(JSON_CFLAGS) \
	$(NULL)
