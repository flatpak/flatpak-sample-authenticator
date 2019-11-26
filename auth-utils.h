/*
 * Copyright © 2019 Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Alexander Larsson <alexl@redhat.com>
 */

#ifndef __AUTH_UTILS_H__
#define __AUTH_UTILS_H__

#include "flatpak-dbus-generated.h"
#include <libsoup/soup.h>

#define FLATPAK_AUTHENTICATOR_OBJECT_PATH "/org/freedesktop/Flatpak/Authenticator"
#define FLATPAK_AUTHENTICATOR_REQUEST_OBJECT_PATH_PREFIX "/org/freedesktop/Flatpak/Authenticator/request/"

#define FLATPAK_REMOTE_CONFIG_AUTHENTICATOR_NAME "xa.authenticator-name"
#define FLATPAK_REMOTE_CONFIG_AUTHENTICATOR_OPTIONS "xa.authenticator-options"

enum {
      FLATPAK_AUTH_RESPONSE_OK,
      FLATPAK_AUTH_RESPONSE_CANCELLED,
      FLATPAK_AUTH_RESPONSE_ERROR,
};

gboolean flatpak_id_has_subref_suffix (const char *id);
SoupSession * flatpak_create_soup_session (const char *user_agent);
gboolean flatpak_fail (GError **error, const char *fmt, ...) G_GNUC_PRINTF (2,3);


#define _GLNX_CONCAT(a, b)  a##b
#define _GLNX_CONCAT_INDIRECT(a, b) _GLNX_CONCAT(a, b)
#define _GLNX_MAKE_ANONYMOUS(a) _GLNX_CONCAT_INDIRECT(a, __COUNTER__)

#define _GLNX_HASH_TABLE_FOREACH_IMPL_KV(guard, ht, it, kt, k, vt, v)          \
    gboolean guard = TRUE;                                                     \
    G_STATIC_ASSERT (sizeof (kt) == sizeof (void*));                           \
    G_STATIC_ASSERT (sizeof (vt) == sizeof (void*));                           \
    for (GHashTableIter it;                                                    \
         guard && ({ g_hash_table_iter_init (&it, ht), TRUE; });               \
         guard = FALSE)                                                        \
            for (kt k; guard; guard = FALSE)                                   \
                for (vt v; g_hash_table_iter_next (&it, (gpointer)&k, (gpointer)&v);)

#define GLNX_HASH_TABLE_FOREACH_KV(ht, kt, k, vt, v) \
    _GLNX_HASH_TABLE_FOREACH_IMPL_KV( \
         _GLNX_MAKE_ANONYMOUS(_glnx_ht_iter_guard_), ht, \
         _GLNX_MAKE_ANONYMOUS(_glnx_ht_iter_it_), kt, k, vt, v)

#define GLNX_HASH_TABLE_FOREACH(ht, kt, k) \
    _GLNX_HASH_TABLE_FOREACH_IMPL_KV( \
         _GLNX_MAKE_ANONYMOUS(_glnx_ht_iter_guard_), ht, \
         _GLNX_MAKE_ANONYMOUS(_glnx_ht_iter_it_), kt, k, \
         gpointer, _GLNX_MAKE_ANONYMOUS(_glnx_ht_iter_v_))

typedef FlatpakAuthenticator AutoFlatpakAuthenticator;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (AutoFlatpakAuthenticator, g_object_unref)

typedef FlatpakAuthenticatorRequest AutoFlatpakAuthenticatorRequest;
G_DEFINE_AUTOPTR_CLEANUP_FUNC (AutoFlatpakAuthenticatorRequest, g_object_unref)

char *                       flatpak_auth_create_request_path       (const char                   *peer,
                                                                     const char                   *token,
                                                                     GError                      **error);
void                         flatpak_auth_request_emit_response     (FlatpakAuthenticatorRequest  *request,
                                                                     const gchar                  *destination_bus_name,
                                                                     guint                         arg_response,
                                                                     GVariant                     *arg_results);
void                         flatpak_auth_request_emit_webflow      (FlatpakAuthenticatorRequest  *request,
                                                                     const gchar                  *destination_bus_name,
                                                                     const char                   *arg_uri);
void                         flatpak_auth_request_emit_webflow_done (FlatpakAuthenticatorRequest  *request,
                                                                     const gchar                  *destination_bus_name);



#endif /* __AUTH_UTILS_H__ */
