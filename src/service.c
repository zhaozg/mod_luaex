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
} ml_server_conf;

void *ml_create_server(apr_pool_t *p, server_rec *s)
{
    ml_server_conf *conf = (ml_server_conf *)apr_pcalloc(p, sizeof(ml_server_conf));
    return conf;
}

const char *ml_set_server_handle(cmd_parms *cmd, void *_cfg,
    const char *name,
    const char *file)
{
    server_rec *s = cmd->server;
    ml_server_conf *cfg = (ml_server_conf *)ap_get_module_config(s->module_config,
        &luaex_module);

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
        return err;
    }
    cfg->service = name;
    cfg->spec.file = file;
    cfg->spec.scope = AP_LUA_SCOPE_CONN;

    return NULL;
}


static request_rec *ml_create_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;

    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

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

    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;
    return r;
}

static apr_bucket_brigade* get_bb(request_rec* r){
    apr_bucket_brigade *bb=NULL;
    int s = apr_pool_userdata_get(&bb,"bb",r->pool);
    if(s==0){
        if(bb==NULL){
            bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
            apr_pool_userdata_set(bb,"bb",NULL,r->pool);
        }
    }
    return bb;
}

int lua_ap_recv(lua_State *L){
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    apr_off_t bytes = luaL_optint(L, 2, 2048);
    apr_bucket_brigade *bb=get_bb(r);
    int s = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,APR_BLOCK_READ,bytes);

    if(s==0){
        apr_bucket *e;
        int n = 0;
        int eof = 0;
        for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
            e = APR_BUCKET_NEXT(e))
        {
            const char *buf;
            apr_size_t blen;

            if (APR_BUCKET_IS_EOS(e))
                 eof = 1;

            s = apr_bucket_read(e, &buf, &blen, APR_BLOCK_READ);
            if (s != APR_SUCCESS)
                break;

            if (blen == 0)
                continue;

            lua_pushlstring(L, buf, blen);
            n++;
        }
        lua_concat(L,n);
        lua_pushboolean(L,eof);
    }
    if(s)
    {
        lua_pushnil(L);
        lua_pushinteger(L,s);
    }
    apr_brigade_cleanup(bb);

    return 2;
}
int lua_ap_send(lua_State *L){
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    size_t len;
    const char* dat = luaL_checklstring(L,2,&len);
    apr_bucket_brigade *bb=get_bb(r);
    int s = apr_brigade_write(bb,NULL,NULL,dat,len);
    if(s==0){
        apr_bucket* b = NULL;
        s = apr_pool_userdata_get(&b, "bucket_flush", r->connection->pool);
        if(s==0)
        {
            if(b==NULL){
                b = apr_bucket_flush_create(r->connection->bucket_alloc);
                apr_pool_userdata_set(b, "bucket_flush",NULL,r->connection->pool);
            }
            if(b)
                APR_BRIGADE_INSERT_TAIL(bb, b);
            s  = ap_pass_brigade(r->connection->output_filters, bb);
        }
    }
    lua_pushboolean(L,s==0);
    lua_pushinteger(L,s);
    apr_brigade_cleanup(bb);
    return 2;
}
static void ml_ext_filter_module(lua_State *L, apr_pool_t *p) {
    apr_hash_t *dispatch;
    lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
    dispatch = lua_touserdata(L, -1);
    lua_pop(L, 1);
    assert(dispatch);

    /* add function */
    apr_hash_set(dispatch, "recv", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_recv, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "send", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_send, APL_REQ_FUNTYPE_LUACFUN, p));
}

AP_LUA_DECLARE(int) ap_lua_init(lua_State *L, apr_pool_t * p);
AP_LUA_DECLARE(void) ap_lua_load_config_lmodule(lua_State *L);

static void lua_open_callback(lua_State *L, apr_pool_t *p, void *ctx)
{
    ap_lua_init(L, p);
    ap_lua_load_apache2_lmodule(L);
    ap_lua_load_request_lmodule(L, p);
    ap_lua_load_config_lmodule(L);
    ml_ext_filter_module(L,p);
    ap_lua_run_lua_open(L, p);
}

int ml_process_connection(conn_rec *c)
{
    server_rec  *s = c->base_server;
    ml_server_conf *conf = (ml_server_conf *)ap_get_module_config(s->module_config,
        &luaex_module);
    if (!conf->spec.file) {
        return DECLINED;
    } else {
        module* lua_module = ml_find_module(s,"lua_module");

        conn_state_t *cs = c->cs;
        apr_socket_t *csd = ap_get_conn_socket(c);
        ap_lua_dir_cfg *dcfg = (ap_lua_dir_cfg *)ap_get_module_config(s->lookup_defaults,
            lua_module);

        int result = HTTP_BAD_REQUEST;
        lua_State *L = NULL;
        request_rec *r = ml_create_request(c);

        apr_os_sock_t fd;
        int sucessful;
        apr_status_t status = apr_os_sock_get(&fd, csd);
        if(status!=APR_SUCCESS)
            return HTTP_INTERNAL_SERVER_ERROR;

        ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_KEEPALIVE, c);
        ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, NULL);
        apr_socket_timeout_set(csd, c->base_server->keep_alive_timeout);

        conf->spec.pool = c->pool;
        conf->spec.package_cpaths = dcfg->package_cpaths;
        conf->spec.package_paths = dcfg->package_paths;
        conf->spec.cb = &lua_open_callback;
        L = ap_lua_get_lua_state(c->pool,&conf->spec);
        if (!L){
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        result = ml_call(L, "handle", "r>b", r, &sucessful);
        c->keepalive = AP_CONN_CLOSE;
        if(result)
        {
            printf(lua_tostring(L,-1));
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (!sucessful){
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
 
    return OK;
}
