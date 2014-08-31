#include "httpd.h"
#define CORE_PRIVATE
#include "http_protocol.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "util_filter.h"
#include "scoreboard.h"
#include "http_log.h"
#include "mod_luaex.h"
#include "private.h"
#include <sys/types.h>


typedef struct
{
  ap_lua_vm_spec spec;
  const char *service;
  apr_hash_t *methods;
} ml_server_conf;

void *ml_create_server(apr_pool_t *p, server_rec *s)
{
  ml_server_conf *conf = (ml_server_conf *)apr_pcalloc(p, sizeof(ml_server_conf));
  conf->methods = apr_hash_make(p);
  return conf;
}

const char *ml_set_server_handle(cmd_parms *cmd, void *_cfg,
                                 const char *name,
                                 const char *file)
{
  server_rec *s = cmd->server;
  ml_server_conf *cfg = (ml_server_conf *)ap_get_module_config(s->module_config,
                        &luaex_module);

  const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err)
  {
    return err;
  }
  cfg->service = name;
  cfg->spec.file = file;
  cfg->spec.scope = AP_LUA_SCOPE_CONN;

  return NULL;
}

const char *ml_set_method_handle(cmd_parms *cmd, void *_cfg,
                                 const char *name,
                                 const char *file,
                                 const char *funcname)
{
  server_rec *s = cmd->server;
  ap_lua_vm_spec *spec = NULL;
  ml_server_conf *cfg = (ml_server_conf *)ap_get_module_config(s->module_config,
                        &luaex_module);

  const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err)
  {
    return err;
  }
  spec = apr_pcalloc(s->process->pool, sizeof(ap_lua_vm_spec));
  spec->file = file;
  spec->scope = AP_LUA_SCOPE_CONN;
  apr_hash_set(cfg->methods, name, APR_HASH_KEY_STRING, spec);
  ap_method_register(s->process->pool, name);
  return NULL;
}

static request_rec *ml_create_request(conn_rec *conn,
                                      server_rec *s,
                                      ml_server_conf *conf)
{
  request_rec *r;
  apr_pool_t *p;

  apr_pool_create(&p, conn ? conn->pool : s->process->pool);
  apr_pool_tag(p, "request");
  r = apr_pcalloc(p, sizeof(request_rec));
  if (conn)
  {
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
  }
  r->pool            = p;
  r->connection      = conn;

  r->server          = conn ? conn->base_server : s;

  r->user            = NULL;
  r->ap_auth_type    = NULL;

  r->allowed_methods = ap_make_method_list(p, 2);

  r->headers_in      = apr_table_make(r->pool, 5);
  r->subprocess_env  = apr_table_make(r->pool, 5);
  r->headers_out     = apr_table_make(r->pool, 5);
  r->err_headers_out = apr_table_make(r->pool, 5);
  r->notes           = apr_table_make(r->pool, 5);

  r->request_config  = ap_create_request_config(r->pool);
  /* Must be set before we run create request hook */
  if (r->connection)
  {
    //ap_run_create_request(r);
  }
  r->proto_output_filters = conn ? conn->output_filters : NULL;
  r->output_filters  = r->proto_output_filters;
  r->proto_input_filters = conn ? conn->input_filters : NULL;
  r->input_filters   = r->proto_input_filters;


  r->per_dir_config  = r->server->lookup_defaults;

  r->assbackwards    = 1;
  r->sent_bodyct     = 0;                      /* bytect isn't for body */

  r->read_length     = 0;
  r->read_body       = REQUEST_NO_BODY;

  r->status          = HTTP_OK;  /* Until further notice */
  r->the_request     = NULL;

  /* Begin by presuming any module can make its own path_info assumptions,
   * until some module interjects and changes the value.
   */
  r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

  r->useragent_addr = conn ? conn->client_addr : NULL;
  r->useragent_ip = conn ? conn->client_ip : NULL;

  r->protocol = apr_pstrdup(r->pool, conf->service);
  r->uri      = apr_pstrdup(r->pool, conf->service);

  return r;
}

AP_LUA_DECLARE(int) ap_lua_init(lua_State *L, apr_pool_t * p);
AP_LUA_DECLARE(void) ap_lua_load_config_lmodule(lua_State *L);

static void lua_open_callback(lua_State *L, apr_pool_t *p, void *ctx)
{
  ap_lua_init(L, p);
  ap_lua_load_apache2_lmodule(L);
  ap_lua_load_request_lmodule(L, p);
  ap_lua_load_config_lmodule(L);
  ap_lua_run_lua_open(L, p);
}

int ml_process_connection(conn_rec *c)
{
  server_rec  *s = c->base_server;
  ml_server_conf *conf = (ml_server_conf *)ap_get_module_config(s->module_config,
                         &luaex_module);
  if (!conf->spec.file)
  {
    return DECLINED;
  }
  else
  {
    module* lua_module = ml_find_module(s, "lua_module");

    apr_socket_t *csd = ap_get_conn_socket(c);
    ap_lua_dir_cfg *dcfg = (ap_lua_dir_cfg *)ap_get_module_config(s->lookup_defaults,
                           lua_module);

    int result = HTTP_BAD_REQUEST;
    lua_State *L = NULL;
    request_rec *r = ml_create_request(c, c->base_server, conf);

    apr_os_sock_t fd;
    int sucessful;
    apr_status_t status = apr_os_sock_get(&fd, csd);
    if (status != APR_SUCCESS)
      return HTTP_INTERNAL_SERVER_ERROR;

    ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_KEEPALIVE, c);
    ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
    apr_socket_timeout_set(csd, c->base_server->keep_alive_timeout);

    conf->spec.pool = c->pool;
    conf->spec.package_cpaths = dcfg->package_cpaths;
    conf->spec.package_paths = dcfg->package_paths;
    conf->spec.cb = &lua_open_callback;

    L = ap_lua_get_lua_state(c->pool, &conf->spec, r);

    if (!L)
    {
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    result = ml_call(L, "handle", "r>b", r, &sucessful);
    c->keepalive = AP_CONN_CLOSE;
    ap_lua_release_state(L, &conf->spec, r);
    if (result)
    {
      printf(lua_tostring(L, -1));
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!sucessful)
    {
      return HTTP_INTERNAL_SERVER_ERROR;
    }
  }

  return OK;
}
