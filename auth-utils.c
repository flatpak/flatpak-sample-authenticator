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
