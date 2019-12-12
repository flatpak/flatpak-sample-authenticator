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
#include <locale.h>

#include <json-glib/json-glib.h>

#include "flatpak-authenticator-webflow.h"
#include "flatpak-dbus-generated.h"

FlatpakAuthenticator *authenticator;
static GMainLoop *main_loop = NULL;
static guint name_owner_id = 0;
static gboolean no_idle_exit = FALSE;
static SoupSession *http_session = NULL;

#define IDLE_TIMEOUT_SECS 10 * 60

static GHashTable *services;

typedef struct {
  char *remote;
  char *token;
  GDateTime *token_valid_until;
} AuthService;

static void
auth_service_free (AuthService *service)
{
  g_free (service->remote);
  g_free (service->token);
  if (service->token_valid_until)
    g_date_time_unref (service->token_valid_until);
  g_free (service);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (AuthService, auth_service_free);

/* Duplicate this here to avoid requiring json-glib 1.6 for */
static const char *
object_get_string_member_with_default (JsonObject *object,
                                       const char *member_name,
                                       const char *default_value)
{
  JsonNode *node = json_object_get_member (object, member_name);

  if (node == NULL)
    return default_value;

  if (JSON_NODE_HOLDS_NULL (node))
    return default_value;

  if (JSON_NODE_TYPE (node) != JSON_NODE_VALUE)
    return default_value;

  return json_node_get_string (node);
}

static AuthService *
auth_service_new_for_name (const char *name)
{
  AuthService *service;

  service = g_new0 (AuthService, 1);
  service->remote = g_strdup (name);

  return service;
}

static void
auth_service_parse (AuthService *service,
                    GKeyFile *keyfile,
                    const char *group)
{
  service->token = g_key_file_get_string (keyfile, group, "token", NULL);
}

static void
auth_service_unparse (AuthService *service,
                      GKeyFile *keyfile)
{
  g_autofree char *group = g_strdup_printf ("remote \"%s\"", service->remote);

  if (service->token)
    g_key_file_set_string (keyfile, group, "token", service->token);
}

static AuthService *
auth_service_new_for_group (GKeyFile *keyfile, const char *group)
{
  static gsize regex_initialized;
  static GRegex *regex;
  g_autoptr(AuthService) service = NULL;
  g_autoptr(GMatchInfo) match = NULL;
  g_autofree gchar *name = NULL;


  if (g_once_init_enter (&regex_initialized))
    {
      regex = g_regex_new ("^remote \"(.+)\"$", 0, 0, NULL);
      g_assert (regex);
      g_once_init_leave (&regex_initialized, 1);
    }

  /* Sanity check */
  g_return_val_if_fail (g_key_file_has_group (keyfile, group), NULL);

  /* If group name doesn't fit the pattern, fail. */
  if (!g_regex_match (regex, group, 0, &match))
    return NULL;

  name = g_match_info_fetch (match, 1);

  service = auth_service_new_for_name (name);

  auth_service_parse (service, keyfile, group);

  return g_steal_pointer (&service);
}

static char *
get_config_file (void)
{
  return g_build_filename (g_get_user_config_dir (), "flatpak", "auth-services.conf", NULL);
}

static void
load_services (void)
{
  g_autofree char *path = get_config_file ();
  g_autoptr(GError) error = NULL;
  g_autoptr(GKeyFile) keyfile = g_key_file_new ();
  g_auto(GStrv) groups = NULL;
  int i;

  if (!g_key_file_load_from_file (keyfile, path, G_KEY_FILE_NONE, &error))
    {
      if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        {
          g_warning ("Unable to read service data %s: %s", path, error->message);
        }
      g_clear_error (&error);
    }

  services = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify)auth_service_free);

  groups = g_key_file_get_groups (keyfile, NULL);

  for (i = 0; groups[i] != NULL; i++)
    {
      const char *group = groups[i];
      AuthService *service;

      service = auth_service_new_for_group (keyfile, group);
      if (service)
        g_hash_table_insert (services, service->remote, service);
    }
}

static void
save_services (void)
{
  g_autofree char *path = get_config_file ();
  g_autofree char *path_dir = g_path_get_dirname (path);;
  g_autoptr(GError) error = NULL;
  g_autoptr(GKeyFile) keyfile = g_key_file_new ();
  g_autoptr(GList) keys = NULL;
  GList *l;

  keys = g_hash_table_get_keys (services);

  keys = g_list_sort (keys, (GCompareFunc)strcmp);

  for (l = keys; l != NULL; l = l->next)
    {
      const char *remote = l->data;
      AuthService *service = g_hash_table_lookup (services, remote);

      auth_service_unparse (service, keyfile);
    }

  g_mkdir_with_parents (path_dir, 0777);
  if (!g_key_file_save_to_file (keyfile, path, &error))
    {
      g_warning ("Error saving service config: %s", error->message);
      g_clear_error (&error);
    }
}

static AuthService *
lookup_service (const char *remote)
{
  AuthService *service;

  service = g_hash_table_lookup (services, remote);
  if (service == NULL)
    {
      service = auth_service_new_for_name (remote);
      g_hash_table_insert (services, service->remote, service);
    }

  return service;
}

static char *
lookup_service_token (const char *remote)
{
  AuthService *service = lookup_service (remote);

  /* TODO: This should verify expiration of the token before using it */
  return g_strdup (service->token);
}


static void
update_service_token (const char *remote, const char *token)
{
  AuthService *service;

  g_debug ("Updating token for remote %s", remote);

  service = lookup_service (remote);

  g_free (service->token);
  service->token = g_strdup (token);

  save_services ();
}

static void
skeleton_died_cb (gpointer data)
{
  g_debug ("skeleton finalized, exiting");
  g_main_loop_quit (main_loop);
}

static gboolean
unref_skeleton_in_timeout_cb (gpointer user_data)
{
  static gboolean unreffed = FALSE;

  g_debug ("unreffing authenticator main ref");
  if (!unreffed)
    {
      g_object_unref (authenticator);
      unreffed = TRUE;
    }

  return G_SOURCE_REMOVE;
}

static void
unref_skeleton_in_timeout (void)
{
  if (name_owner_id)
    g_bus_unown_name (name_owner_id);
  name_owner_id = 0;

  /* After we've lost the name or idled we drop the main ref on the authenticator
     so that we'll exit when it drops to zero. However, if there are
     outstanding calls these will keep the refcount up during the
     execution of them. We do the unref on a timeout to make sure
     we're completely draining the queue of (stale) requests. */
  g_timeout_add (500, unref_skeleton_in_timeout_cb, NULL);
}

static gboolean
idle_timeout_cb (gpointer user_data)
{
  if (name_owner_id)
    {
      g_debug ("Idle - unowning name");
      unref_skeleton_in_timeout ();
    }
  return G_SOURCE_REMOVE;
}

static void
schedule_idle_callback (void)
{
  static guint idle_timeout_id = 0;

  if (!no_idle_exit)
    {
      if (idle_timeout_id != 0)
        g_source_remove (idle_timeout_id);

      idle_timeout_id = g_timeout_add_seconds (IDLE_TIMEOUT_SECS, idle_timeout_cb, NULL);
    }
}


typedef struct {
  char *sender;
  SoupURI *uri;
  char *token;

  /* args */
  char *remote;
  char **refs;
  gint32 *token_types;
  GVariant *authenticator_options;

  GHashTable *unresolved_tokens; /* HashSet: id */
  GHashTable *resolved_tokens; /* Hash: token str -> GPtrArray of refs */
  GPtrArray *denied_tokens;

  WebflowData *webflow;
} RequestRefTokensData;

static void
request_ref_tokens_data_free (RequestRefTokensData *data)
{
  g_free (data->sender);
  soup_uri_free (data->uri);
  g_free (data->token);
  g_free (data->remote);
  g_strfreev (data->refs);
  g_free (data->token_types);
  if (data->authenticator_options)
    g_variant_unref (data->authenticator_options);

  g_hash_table_unref (data->resolved_tokens);
  g_hash_table_unref (data->unresolved_tokens);
  g_ptr_array_unref (data->denied_tokens);
  if (data->webflow)
    webflow_data_unref (data->webflow);

  g_free (data);
}

static char *
get_id_from_ref (const char *ref)
{
  g_auto(GStrv) parts = g_strsplit (ref, "/", 0);
  char *id;

  if (g_strv_length (parts) != 4)
    return g_strdup ("none"); /* Shouldn't happen, but lets return *something* */

  id = parts[1];
  if (flatpak_id_has_subref_suffix (id))
    *strrchr(id, '.') = 0;

  return g_strdup (id);
}

static void
request_ref_tokens_data_resolve_id (RequestRefTokensData *data,
                                    const char *id,
                                    const char *token)
{
  GPtrArray *refs_for_token;
  int i;

  /* Ensure we have an array for this id */
  refs_for_token = g_hash_table_lookup (data->resolved_tokens, token);
  if (refs_for_token == 0)
    {
      refs_for_token = g_ptr_array_new ();
      g_hash_table_insert (data->resolved_tokens, g_strdup (token), refs_for_token);
    }

  /* Mark all refs with this id with the token */
  for (i = 0; data->refs[i] != NULL; i++)
    {
      const char *ref = data->refs[i];
      g_autofree char *id_for_ref = get_id_from_ref (ref);

      if (strcmp (id, id_for_ref) == 0)
        g_ptr_array_add (refs_for_token, (char *)ref);
    }

  /* Id is now resolved */
  g_hash_table_remove (data->unresolved_tokens, id);
}


static gboolean
handle_request_ref_tokens_close (FlatpakAuthenticatorRequest *object,
                                 GDBusMethodInvocation *invocation,
                                 gpointer           user_data)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (object), "request-data");
  g_debug ("handlling Request.Close %s", data->remote);

  if (data->webflow)
    webflow_cancel (data->webflow);

  return TRUE;
}

static void
request_ref_tokens__success (FlatpakAuthenticatorRequest *request)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  GVariantBuilder tokens;
  GVariantBuilder results;

  g_variant_builder_init (&tokens, G_VARIANT_TYPE ("a{sas}"));

  GLNX_HASH_TABLE_FOREACH_KV (data->resolved_tokens, const char *, required_token, GPtrArray *, for_refs)
    {
      g_ptr_array_add (for_refs, NULL);
      g_variant_builder_add (&tokens, "{s^as}", required_token, for_refs->pdata);
    }

  g_variant_builder_init (&results, G_VARIANT_TYPE ("a{sv}"));
  g_variant_builder_add (&results, "{sv}", "tokens", g_variant_builder_end (&tokens));

  g_debug ("emiting OK response");
  flatpak_auth_request_emit_response (request, data->sender,
                                      FLATPAK_AUTH_RESPONSE_OK,
                                      g_variant_builder_end (&results));
}

static SoupMessage *
create_api_call (SoupURI *base_uri,
                 const char *api_path,
                 const char *token,
                 JsonObject *json)
{
  g_autoptr(SoupMessage) msg = NULL;
  g_autoptr(JsonNode) root = NULL;
  g_autoptr(SoupURI) api_uri = NULL;
  g_autofree char *bearer = NULL;
  char *body;

  root = json_node_alloc ();
  json_node_init_object (root, json);
  body = json_to_string (root, FALSE);

  api_uri = soup_uri_new_with_base (base_uri, api_path);

  msg = soup_message_new_from_uri ("POST", api_uri);
  soup_message_set_request (msg, "application/json", SOUP_MEMORY_TAKE, body, strlen (body));
  bearer = g_strdup_printf ("Bearer %s", token);
  soup_message_headers_append (msg->request_headers, "Authorization", bearer);

  return g_steal_pointer (&msg);
}

static JsonNode *
verify_api_call_json_response (FlatpakAuthenticatorRequest *request,
                               const char *sender,
                               SoupMessage *msg)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(JsonNode) json = NULL;
  GVariantBuilder results;

  if (msg->status_code != 200)
    {
      g_autofree char *err_msg = g_strdup_printf ("API Call failed, service returned status %d", msg->status_code);
      g_variant_builder_init (&results, G_VARIANT_TYPE ("a{sv}"));
      g_variant_builder_add (&results, "{sv}", "error-message", g_variant_new_string (err_msg));
      flatpak_auth_request_emit_response (request, sender,
                                          FLATPAK_AUTH_RESPONSE_ERROR,
                                          g_variant_builder_end (&results));
      return NULL;
    }

  json = json_from_string (msg->response_body->data, &error);
  if (json == NULL || !JSON_NODE_HOLDS_OBJECT (json))
    {
      g_variant_builder_init (&results, G_VARIANT_TYPE ("a{sv}"));
      g_variant_builder_add (&results, "{sv}", "error-message", g_variant_new_string ("Invalid json in service reply"));
      flatpak_auth_request_emit_response (request, sender,
                                          FLATPAK_AUTH_RESPONSE_ERROR,
                                          g_variant_builder_end (&results));
      return NULL;
    }

  return g_steal_pointer (&json);
}

static void request_ref_tokens__get_unresolved_tokens (FlatpakAuthenticatorRequest *request);

static void
request_ref_tokens__purchased_cb (FlatpakAuthenticatorRequest *request,
                                  GHashTable *query,
                                  GError *error)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  GVariantBuilder results;

  g_assert (data->webflow != NULL);
  webflow_data_unref (data->webflow);
  data->webflow = NULL;

  if (error)
    {
      g_variant_builder_init (&results, G_VARIANT_TYPE ("a{sv}"));

      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
          flatpak_authenticator_request_emit_response (request,
                                                       FLATPAK_AUTH_RESPONSE_CANCELLED,
                                                       g_variant_builder_end (&results));
      else
        {
          g_variant_builder_add (&results, "{sv}", "error-message", g_variant_new_string (error->message));
          flatpak_authenticator_request_emit_response (request,
                                                       FLATPAK_AUTH_RESPONSE_ERROR,
                                                       g_variant_builder_end (&results));
        }

      return;
    }

  /* We successfully purchased the first id, remove it and buy the rest */
  g_debug ("Purchased %s", (char *)data->denied_tokens->pdata[0]);
  g_ptr_array_remove_index (data->denied_tokens, 0);

  request_ref_tokens__get_unresolved_tokens (request);
}

static void
request_ref_tokens__begin_purchase_cb (SoupSession *session,
                                       SoupMessage *msg,
                                       gpointer user_data)
{
  g_autoptr(AutoFlatpakAuthenticatorRequest) request = user_data; /* Take back ownership */
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  g_autoptr(JsonNode) json = NULL;
  JsonObject *root;
  const char *start_uri = NULL;

  g_debug ("API: Got begin_purchase response, status code=%d", msg->status_code);

  json = verify_api_call_json_response (request, data->sender, msg);
  if (json == NULL)
    return;

  root = json_node_get_object (json);

  start_uri = object_get_string_member_with_default (root, "start_uri", NULL);
  data->webflow = webflow_begin (request, data->sender, data->uri, start_uri, request_ref_tokens__purchased_cb);
}

static void
request_ref_tokens__check_done (FlatpakAuthenticatorRequest *request)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");

  if (data->denied_tokens->len > 0)
    {
      /* Buy the first one */
      const char *id = g_ptr_array_index (data->denied_tokens, 0);
      g_autoptr(SoupMessage) msg = NULL;
      g_autoptr(JsonObject) json = NULL;

      json = json_object_new ();
      json_object_set_string_member (json, "id", id);

      g_debug ("API: Requesting purchase of id: %s", id);

      msg = create_api_call (data->uri, "api/v1/begin_purchase", data->token, json);

      soup_session_queue_message (http_session, g_steal_pointer (&msg), request_ref_tokens__begin_purchase_cb,
                                  g_object_ref (request));
    }
  else
    request_ref_tokens__success (request);
}


static void
request_ref_tokens__get_tokens_cb (SoupSession *session,
                                   SoupMessage *msg,
                                   gpointer user_data)
{
  g_autoptr(AutoFlatpakAuthenticatorRequest) request = user_data; /* Take back ownership */
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  g_autoptr(JsonNode) json = NULL;
  JsonObject *root;
  int i;

  g_debug ("API: Got tokens response, status code=%d", msg->status_code);

  json = verify_api_call_json_response (request, data->sender, msg);
  if (json == NULL)
    return;

  root = json_node_get_object (json);

  /* Resolve all refs we can */
  if (json_object_has_member (root, "tokens"))
    {
      JsonObject *tokens_dict = json_object_get_object_member (root, "tokens");
      g_autoptr(GList) members  = json_object_get_members (tokens_dict);
      GList *l;

      for (l = members; l != NULL; l = l->next)
        {
          const char *id = l->data;
          const gchar *token = object_get_string_member_with_default (tokens_dict, id, ""); /* "" means no need for token */
          request_ref_tokens_data_resolve_id (data, id, token);
        }
    }

  if (json_object_has_member (root, "denied"))
    {
      JsonArray *denied_array = json_object_get_array_member (root, "denied");
      guint len =  json_array_get_length (denied_array);
      for (i = 0; i < len; i++)
        {
          const gchar *denied_id = json_array_get_string_element (denied_array, i);
          g_ptr_array_add (data->denied_tokens, g_strdup (denied_id));
        }
    }

  request_ref_tokens__check_done (request);
}

static void
request_ref_tokens__get_unresolved_tokens (FlatpakAuthenticatorRequest *request)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  g_autoptr(SoupMessage) msg = NULL;
  JsonArray *ids_array = NULL;
  g_autoptr(JsonObject) json = NULL;
  g_autoptr(GString) ids_str = g_string_new ("");

  if (g_hash_table_size (data->unresolved_tokens) == 0)
    {
      request_ref_tokens__check_done (request);
      return;
    }

  json = json_object_new ();
  ids_array = json_array_new ();
  json_object_set_array_member (json, "ids", ids_array);

  GLNX_HASH_TABLE_FOREACH (data->unresolved_tokens, const char *, id)
    {
      json_array_add_string_element (ids_array, id);
      if (ids_str->len > 0)
        g_string_append (ids_str, ", ");
      g_string_append (ids_str, id);
    }

  g_debug ("API: Requesting tokens for ids: %s", ids_str->str);

  msg = create_api_call (data->uri, "api/v1/get_tokens", data->token, json);
  soup_session_queue_message (http_session, g_steal_pointer (&msg), request_ref_tokens__get_tokens_cb,
                              g_object_ref (request));
}

static void
request_ref_tokens__login_cb (FlatpakAuthenticatorRequest *request,
                              GHashTable *query,
                              GError *error)
{
  RequestRefTokensData *data = g_object_get_data (G_OBJECT (request), "request-data");
  const char *token = NULL;
  GVariantBuilder results;

  g_assert (data->webflow != NULL);
  webflow_data_unref (data->webflow);
  data->webflow = NULL;

  if (error)
    {
      g_variant_builder_init (&results, G_VARIANT_TYPE ("a{sv}"));

      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
          flatpak_authenticator_request_emit_response (request,
                                                       FLATPAK_AUTH_RESPONSE_CANCELLED,
                                                       g_variant_builder_end (&results));
      else
        {
          g_variant_builder_add (&results, "{sv}", "error-message", g_variant_new_string (error->message));
          flatpak_authenticator_request_emit_response (request,
                                                       FLATPAK_AUTH_RESPONSE_ERROR,
                                                       g_variant_builder_end (&results));
        }

      return;
    }

 if (query)
   token = g_hash_table_lookup (query, "token");

  if (token == NULL)
    {
      g_variant_builder_add (&results, "{sv}", "error-message", g_variant_new_string ("No token returned by server"));
      flatpak_authenticator_request_emit_response (request,
                                                   FLATPAK_AUTH_RESPONSE_ERROR,
                                                   g_variant_builder_end (&results));
      return;
    }

  data->token = g_strdup (token);

  g_debug ("Logged in, new token: %s", token);

  /* Save token for later reuse */
  update_service_token (data->remote, data->token);

  request_ref_tokens__get_unresolved_tokens (request);
}

static gboolean
handle_request_ref_tokens (FlatpakAuthenticator *authenticator,
                           GDBusMethodInvocation *invocation,
                           const gchar *arg_handle_token,
                           GVariant *arg_authenticator_options,
                           const gchar *arg_remote,
                           const gchar *arg_remote_uri,
                           GVariant *arg_refs,
                           GVariant *arg_options,
                           const gchar *arg_parent_window)
{
  g_autofree char *request_path = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(AutoFlatpakAuthenticatorRequest) request = NULL;
  RequestRefTokensData *data;
  const char *url = NULL;
  g_autoptr(GPtrArray) refs = NULL;
  gsize n_refs, i;

  g_debug ("handling Authenticator.RequestRefTokens");

  if (!g_variant_lookup (arg_authenticator_options, "url", "&s", &url))
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_INVALID_ARGS,
                                             "No url specified");
      return TRUE;
    }

  request_path = flatpak_auth_create_request_path (g_dbus_method_invocation_get_sender (invocation),
                                                   arg_handle_token, NULL);
  if (request_path == NULL)
    {
      g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
                                             G_DBUS_ERROR_INVALID_ARGS,
                                             "Invalid token");
      return TRUE;
    }

  request = flatpak_authenticator_request_skeleton_new ();
  if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (request),
                                         g_dbus_method_invocation_get_connection (invocation),
                                         request_path,
                                         &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      return TRUE;
    }

  data = g_new0 (RequestRefTokensData, 1);
  data->sender = g_strdup (g_dbus_method_invocation_get_sender (invocation));
  data->uri = soup_uri_new (url);
  data->remote = g_strdup (arg_remote);
  data->authenticator_options = g_variant_ref (arg_authenticator_options);
  data->unresolved_tokens = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  data->resolved_tokens = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_ptr_array_unref);
  data->denied_tokens = g_ptr_array_new_with_free_func (g_free);

  refs = g_ptr_array_new_with_free_func (g_free);
  n_refs = g_variant_n_children (arg_refs);
  data->token_types = g_new0 (gint32, n_refs);
  data->refs = g_new0 (char *, n_refs + 1);
  for (i = 0; i < n_refs; i++)
    {
      const char *ref, *commit;
      g_autoptr(GVariant) ref_data = NULL;
      gint32 token_type;

      g_variant_get_child (arg_refs, i, "(&s&si@a{sv})", &ref, &commit, &token_type, &ref_data);
      data->refs[i] = g_strdup (ref);
      data->token_types[i] = token_type;
    }

  /* Initialize with all ids unresolved */
  for (i = 0; data->refs[i] != NULL; i++)
    {
      const char *ref = data->refs[i];
      g_hash_table_insert (data->unresolved_tokens, get_id_from_ref (ref), GINT_TO_POINTER(1));
    }

  g_object_set_data_full (G_OBJECT (request), "request-data", data, (GDestroyNotify)request_ref_tokens_data_free);

  g_signal_connect (request, "handle-close", G_CALLBACK (handle_request_ref_tokens_close), NULL);

  flatpak_authenticator_complete_request_ref_tokens (authenticator, invocation, request_path);

  data->token = lookup_service_token (data->remote);
  if (data->token == NULL)
    {
      /* No valid token, start with getting one via a webflow */
      data->webflow = webflow_begin (request, data->sender, data->uri, "login", request_ref_tokens__login_cb);
    }
  else
    {
      request_ref_tokens__get_unresolved_tokens (request);
    }

  return TRUE;
}

static gboolean
flatpak_authorize_method_handler (GDBusInterfaceSkeleton *interface,
                                  GDBusMethodInvocation  *invocation,
                                  gpointer                user_data)

{
  /* Ensure we don't idle exit */
  schedule_idle_callback ();

  return TRUE;
}

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
  GError *error = NULL;

  g_debug ("Bus acquired, creating skeleton");

  g_dbus_connection_set_exit_on_close (connection, FALSE);

  authenticator = flatpak_authenticator_skeleton_new ();
  flatpak_authenticator_set_version (authenticator, 0);

  g_object_set_data_full (G_OBJECT (authenticator), "track-alive", GINT_TO_POINTER (42), skeleton_died_cb);

  g_signal_connect (authenticator, "handle-request-ref-tokens", G_CALLBACK (handle_request_ref_tokens), NULL);

  /* This is only used for idle tracking atm */
  g_signal_connect (authenticator, "g-authorize-method",
                    G_CALLBACK (flatpak_authorize_method_handler),
                    NULL);

  if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (authenticator),
                                         connection,
                                         FLATPAK_AUTHENTICATOR_OBJECT_PATH,
                                         &error))
    {
      g_warning ("error: %s", error->message);
      g_error_free (error);
    }
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
  g_debug ("Name acquired");
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
  g_debug ("Name lost");
}


static void
message_handler (const gchar   *log_domain,
                 GLogLevelFlags log_level,
                 const gchar   *message,
                 gpointer       user_data)
{
  /* Make this look like normal console output */
  if (log_level & G_LOG_LEVEL_DEBUG)
    g_printerr ("F: %s\n", message);
  else
    g_printerr ("%s: %s\n", g_get_prgname (), message);
}

int
main (int    argc,
      char **argv)
{
  gboolean replace;
  gboolean opt_verbose;
  GOptionContext *context;
  GDBusConnection *session_bus;
  GBusNameOwnerFlags flags;
  g_autoptr(GError) error = NULL;
  const GOptionEntry options[] = {
    { "replace", 'r', 0, G_OPTION_ARG_NONE, &replace,  "Replace old daemon.", NULL },
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose,  "Enable debug output.", NULL },
    { "no-idle-exit", 0, 0, G_OPTION_ARG_NONE, &no_idle_exit,  "Don't exit when idle.", NULL },
    { NULL }
  };

  setlocale (LC_ALL, "");

  g_setenv ("GIO_USE_VFS", "local", TRUE);

  g_set_prgname (argv[0]);

  g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, message_handler, NULL);

  context = g_option_context_new ("");

  replace = FALSE;
  opt_verbose = FALSE;

  g_option_context_set_summary (context, "Flatpak authenticator");
  g_option_context_add_main_entries (context, options, GETTEXT_PACKAGE);

  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_printerr ("%s: %s", g_get_application_name (), error->message);
      g_printerr ("\n");
      g_printerr ("Try \"%s --help\" for more information.",
                  g_get_prgname ());
      g_printerr ("\n");
      g_option_context_free (context);
      return 1;
    }

  if (opt_verbose)
    g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, message_handler, NULL);

  g_debug ("Started flatpak-authenticator");

  http_session = flatpak_create_soup_session (PACKAGE_STRING);

  load_services ();

  session_bus = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
  if (session_bus == NULL)
    {
      g_printerr ("Can't find bus: %s\n", error->message);
      return 1;
    }

  flags = G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT;
  if (replace)
    flags |= G_BUS_NAME_OWNER_FLAGS_REPLACE;

  name_owner_id = g_bus_own_name (G_BUS_TYPE_SESSION,
                                  "org.flatpak.Authenticator.Sample",
                                  flags,
                                  on_bus_acquired,
                                  on_name_acquired,
                                  on_name_lost,
                                  NULL,
                                  NULL);

  /* Ensure we don't idle exit */
  schedule_idle_callback ();

  main_loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (main_loop);

  save_services ();

  return 0;
}
