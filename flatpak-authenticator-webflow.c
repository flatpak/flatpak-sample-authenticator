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

#include "flatpak-authenticator-webflow.h"
#include <libsoup/soup.h>

void
webflow_data_unref (WebflowData *data)
{
  data->ref_count--;
  if (data->ref_count == 0)
    {
      g_clear_object (&data->request);
      g_free (data->sender);

      if (data->query)
        g_hash_table_unref (data->query);
      g_clear_error (&data->error);

      g_free (data->state);
      g_clear_object (&data->server);

      g_free (data);
    }
}

WebflowData *
webflow_data_ref (WebflowData *data)
{
  data->ref_count++;
  return data;
}

static WebflowData *
webflow_data_new (FlatpakAuthenticatorRequest *request, const char *sender, WebflowCallback callback)
{
  WebflowData *data = g_new0 (WebflowData, 1);
  GString *state;
  int i;

  data->ref_count = 1;
  data->request = g_object_ref (request);
  data->sender = g_strdup (sender);
  data->callback = callback;

  /* Generate random state */
  state = g_string_new ("");
  for (i = 0; i < 4; i++)
    g_string_append_printf (state, "%0x", g_random_int ());
  data->state = g_string_free (state, FALSE);

  return data;
}

static gboolean
webflow_finished_cb (gpointer user_data)
{
  g_autoptr(WebflowData) data = webflow_data_ref (user_data); /* Keep alive during callback */

  /* Ensure no more callbacks, and circular refs to WebflowData */
  if (data->server)
    soup_server_remove_handler (data->server, NULL);

  if (data->started_webflow)
    {
      flatpak_auth_request_emit_webflow_done (data->request, data->sender, NULL);
      data->started_webflow = FALSE;
    }

  if (data->error)
    g_debug ("Webflow finished with error: %s", data->error->message);
  else
    g_debug ("Webflow finished successfully");

  data->callback (data->request, data->query, data->error);

  return FALSE;
}

static void
queue_webflow_finished_once (WebflowData *data, GHashTable *query, GError *error)
{
  if (data->done)
    return;

  data->done = TRUE;
  if (query)
    data->query = g_hash_table_ref (query);
  if (error)
    data->error = g_error_copy (error);

  g_idle_add_full (G_PRIORITY_DEFAULT_IDLE, webflow_finished_cb, webflow_data_ref (data), (GDestroyNotify)webflow_data_unref);
}

static void
webflow_server_handler (SoupServer *server,
                        SoupMessage *msg,
                        const char *path,
                        GHashTable *query,
                        SoupClientContext *client,
                        gpointer user_data)
{
  WebflowData *data = user_data;
  const char *state = NULL;
  const char *redirect_uri = NULL;
  char *html;

  g_debug ("Webflow server incoming request at %s", path);

  if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_HEAD)
    {
      soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
      return;
    }

  if (strcmp (path, "/done") != 0)
    {
      soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
      return;
    }

  if (query)
    {
      state = g_hash_table_lookup (query, "state");
      redirect_uri = g_hash_table_lookup (query, "redirect_uri");
    }

  if (strcmp (state, data->state) != 0)
    {
      char *html_error = "<html><body>Invalid state</body></html>";

      soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
      soup_message_set_response (msg, "text/html", SOUP_MEMORY_STATIC, html_error, strlen (html_error));
      return;
    }

  html = "<html><body>Webflow done</body></html>";
  soup_message_set_response (msg, "text/html", SOUP_MEMORY_STATIC, html, strlen (html));
  if (redirect_uri)
    soup_message_set_redirect (msg, SOUP_STATUS_FOUND, redirect_uri);
  else
    soup_message_set_status (msg, SOUP_STATUS_OK);

  queue_webflow_finished_once (data, query, NULL);
}

void
webflow_cancel (WebflowData *data)
{
  g_autoptr(GError) error = NULL;

  g_debug ("Cancelling webflow");

  g_set_error (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "User cancelled operation");
  queue_webflow_finished_once (data, NULL, error);
}

WebflowData *
webflow_begin (FlatpakAuthenticatorRequest *request, const char *sender, SoupURI *base_uri, const char *uri, WebflowCallback callback)
{
  g_autoptr(SoupURI) webflow_uri = NULL;
  g_autoptr(SoupURI) redirect_uri = NULL;
  g_autofree char *webflow_uri_s = NULL;
  g_autofree char *redirect_uri_s = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GSList) listening_uris = NULL;
  g_autoptr(WebflowData) data = NULL;

  data = webflow_data_new (request, sender, callback);

  data->server = soup_server_new (SOUP_SERVER_SERVER_HEADER, "flatpak-authenticator ", NULL);
  if (!soup_server_listen_local (data->server, 0, 0, &error))
    {
      queue_webflow_finished_once (data, NULL, error);
      return g_steal_pointer (&data);
    }

  listening_uris = soup_server_get_uris (data->server);
  if (listening_uris == NULL)
    {
      flatpak_fail (&error, "No listening uris");
      queue_webflow_finished_once (data, NULL, error);
      return g_steal_pointer (&data);
    }

  soup_server_add_handler (data->server, NULL, webflow_server_handler, webflow_data_ref (data), (GDestroyNotify)webflow_data_unref);

  redirect_uri = soup_uri_new_with_base (listening_uris->data, "/done");
  redirect_uri_s = soup_uri_to_string (redirect_uri, FALSE);

  webflow_uri = soup_uri_new_with_base (base_uri, uri);
  soup_uri_set_query_from_fields (webflow_uri,
                                  "redirect_uri", redirect_uri_s,
                                  "state", data->state,
                                  NULL);

  webflow_uri_s = soup_uri_to_string (webflow_uri, FALSE);

  g_debug ("Starting webflow [%s]", webflow_uri_s);

  data->started_webflow = TRUE;
  flatpak_auth_request_emit_webflow (request, data->sender, webflow_uri_s, NULL);

  return g_steal_pointer (&data);
}
