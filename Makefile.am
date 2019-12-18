libexec_PROGRAMS = \
	flatpak-sample-authenticator \
	$(NULL)

%.service: %.service.in config.log
	$(AM_V_GEN) $(SED) -e "s|\@libexecdir\@|$(libexecdir)|" \
		-e "s|\@localstatedir\@|$(localstatedir)|" \
		-e "s|\@extraargs\@||" $< > $@

dbus_servicedir = $(DBUS_SERVICE_DIR)
service_in_files = flatpak-sample-authenticator.service.in
systemduserunit_DATA = flatpak-sample-authenticator.service

service_in_files += org.flatpak.Authenticator.Sample.service.in
dbus_service_DATA = org.flatpak.Authenticator.Sample.service

dbus_built_sources = flatpak-dbus-generated.c flatpak-dbus-generated.h

flatpak-dbus-generated.c: $(FLATPAK_INTERFACES_DIR)/org.freedesktop.Flatpak.Authenticator.xml Makefile
	$(AM_V_GEN) $(GDBUS_CODEGEN)				\
		--interface-prefix org.freedesktop.Flatpak.	\
		--c-namespace Flatpak				\
		--generate-c-code $(builddir)/flatpak-dbus-generated	\
		$(FLATPAK_INTERFACES_DIR)/org.freedesktop.Flatpak.Authenticator.xml  \
		$(NULL)

flatpak-dbus-generated.h: flatpak-dbus-generated.c

flatpak_sample_authenticator_SOURCES = \
	sample-authenticator.c		\
	flatpak-authenticator-webflow.h	\
	flatpak-authenticator-webflow.c	\
	auth-utils.c			\
	auth-utils.h			\
	$(dbus_built_sources)		\
	$(NULL)

flatpak_sample_authenticator_LDADD = \
	$(AM_LDADD) \
	$(BASE_LIBS) \
	$(NULL)

flatpak_sample_authenticator_CFLAGS = \
	$(AM_CFLAGS) \
	$(BASE_CFLAGS) \
	$(NULL)

BUILT_SOURCES = $(dbus_built_sources)
