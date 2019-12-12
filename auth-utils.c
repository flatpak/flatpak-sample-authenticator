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

#include "config.h"

#include "auth-utils.h"

gboolean
flatpak_id_has_subref_suffix (const char *id)
{
  return
    g_str_has_suffix (id, ".Locale") ||
    g_str_has_suffix (id, ".Debug") ||
    g_str_has_suffix (id, ".Sources");
}

char *
flatpak_auth_create_request_path (const char *peer,
                                  const char *token,
                                  GError **error)
{
  gchar *escaped_peer;
  int i;

  for (i = 0; token[i]; i++)
    {
      if (!g_ascii_isalnum (token[i]) && token[i] != '_')
        {
          flatpak_fail (error, "Invalid token %s", token);
          return NULL;
        }
    }

  escaped_peer = g_strdup (peer + 1);
  for (i = 0; escaped_peer[i]; i++)
    if (escaped_peer[i] == '.')
      escaped_peer[i] = '_';

  return g_strconcat (FLATPAK_AUTHENTICATOR_REQUEST_OBJECT_PATH_PREFIX, escaped_peer, "/", token, NULL);
}

void
flatpak_auth_request_emit_response (FlatpakAuthenticatorRequest *request,
                                    const gchar *destination_bus_name,
                                    guint arg_response,
                                    GVariant *arg_results)
{
  FlatpakAuthenticatorRequestSkeleton *skeleton = FLATPAK_AUTHENTICATOR_REQUEST_SKELETON (request);
  GList *connections, *l;
  g_autoptr(GVariant)  signal_variant = NULL;

  connections = g_dbus_interface_skeleton_get_connections (G_DBUS_INTERFACE_SKELETON (skeleton));
  signal_variant = g_variant_ref_sink (g_variant_new ("(u@a{sv})", arg_response, arg_results));
  for (l = connections; l != NULL; l = l->next)
    {
      GDBusConnection *connection = l->data;
      g_dbus_connection_emit_signal (connection, destination_bus_name,
                                     g_dbus_interface_skeleton_get_object_path (G_DBUS_INTERFACE_SKELETON (skeleton)),
                                     "org.freedesktop.Flatpak.AuthenticatorRequest",
                                     "Response", signal_variant, NULL);
    }
  g_list_free_full (connections, g_object_unref);
}

void
flatpak_auth_request_emit_webflow (FlatpakAuthenticatorRequest *request,
                                   const gchar *destination_bus_name,
                                   const char *arg_uri,
                                   GVariant *options)
{
  FlatpakAuthenticatorRequestSkeleton *skeleton = FLATPAK_AUTHENTICATOR_REQUEST_SKELETON (request);
  GList      *connections, *l;
  g_autoptr(GVariant) signal_variant = NULL;
  g_autoptr(GVariant) default_options = NULL;

  if (options == NULL)
    {
      default_options = g_variant_ref_sink (g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0));
      options = default_options;
    }

  connections = g_dbus_interface_skeleton_get_connections (G_DBUS_INTERFACE_SKELETON (skeleton));

  signal_variant = g_variant_ref_sink (g_variant_new ("(s@a{sv})", arg_uri, options));
  for (l = connections; l != NULL; l = l->next)
    {
      GDBusConnection *connection = l->data;
      g_dbus_connection_emit_signal (connection, destination_bus_name,
                                     g_dbus_interface_skeleton_get_object_path (G_DBUS_INTERFACE_SKELETON (skeleton)),
                                     "org.freedesktop.Flatpak.AuthenticatorRequest", "Webflow",
                                     signal_variant, NULL);
    }
  g_list_free_full (connections, g_object_unref);
}

void
flatpak_auth_request_emit_webflow_done (FlatpakAuthenticatorRequest *request,
                                        const gchar *destination_bus_name,
                                        GVariant *options)
{
  FlatpakAuthenticatorRequestSkeleton *skeleton = FLATPAK_AUTHENTICATOR_REQUEST_SKELETON (request);
  GList      *connections, *l;
  g_autoptr(GVariant) signal_variant = NULL;
  g_autoptr(GVariant) default_options = NULL;

  if (options == NULL)
    {
      default_options = g_variant_ref_sink (g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0));
      options = default_options;
    }

  connections = g_dbus_interface_skeleton_get_connections (G_DBUS_INTERFACE_SKELETON (skeleton));

  signal_variant = g_variant_ref_sink (g_variant_new ("(@a{sv})", options));
  for (l = connections; l != NULL; l = l->next)
    {
      GDBusConnection *connection = l->data;
      g_dbus_connection_emit_signal (connection, destination_bus_name,
                                     g_dbus_interface_skeleton_get_object_path (G_DBUS_INTERFACE_SKELETON (skeleton)),
                                     "org.freedesktop.Flatpak.AuthenticatorRequest", "WebflowDone",
                                     signal_variant, NULL);
    }
  g_list_free_full (connections, g_object_unref);
}

SoupSession *
flatpak_create_soup_session (const char *user_agent)
{
  SoupSession *soup_session;
  const char *http_proxy;

  soup_session = soup_session_new_with_options (SOUP_SESSION_USER_AGENT, user_agent,
                                                SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
                                                SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
                                                SOUP_SESSION_TIMEOUT, 60,
                                                SOUP_SESSION_IDLE_TIMEOUT, 60,
                                                NULL);
  soup_session_remove_feature_by_type (soup_session, SOUP_TYPE_CONTENT_DECODER);
  http_proxy = g_getenv ("http_proxy");
  if (http_proxy)
    {
      g_autoptr(SoupURI) proxy_uri = soup_uri_new (http_proxy);
      if (!proxy_uri)
        g_warning ("Invalid proxy URI '%s'", http_proxy);
      else
        g_object_set (soup_session, SOUP_SESSION_PROXY_URI, proxy_uri, NULL);
    }

  if (g_getenv ("OSTREE_DEBUG_HTTP"))
    soup_session_add_feature (soup_session, (SoupSessionFeature *) soup_logger_new (SOUP_LOGGER_LOG_BODY, 500));

  return soup_session;
}

gboolean
flatpak_fail (GError    **error,
              const char *fmt,
              ...)
{
  if (error == NULL)
    return FALSE;

  va_list args;
  va_start (args, fmt);
  GError *new = g_error_new_valist (G_IO_ERROR, G_IO_ERROR_FAILED, fmt, args);
  va_end (args);
  g_propagate_error (error, g_steal_pointer (&new));
  return FALSE;
}
