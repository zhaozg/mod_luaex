#ifndef MOD_LUAEX_PRIVATE
#define MOD_LUAEX_PRIVATE

#ifdef  __cplusplus
extern "C" {
#endif


#include <apr_optional.h>
#include <apr_hash.h>
#include <httpd.h>
#include <lua.h>

extern module AP_MODULE_DECLARE_DATA luaex_module;

struct dir_config
{
  apr_table_t        *filter;
  apr_array_header_t *monitor;
  apr_hash_t         *resource; /* hash table for usage->apr_reslist_t */
  lua_State          *L;
};

module* ml_find_module(server_rec*s, const char*m) ;
apr_status_t ml_filter_prefetch(ap_filter_t *f, apr_off_t readbytes);
apr_status_t ml_filter(ap_filter_t *f,
                       apr_bucket_brigade *bb,
                       ap_input_mode_t mode,
                       apr_read_type_e block,
                       apr_off_t readbytes);

void ml_filter_make_context(ap_filter_t *f);
void ml_filter_init_context(ap_filter_t *f);
apr_status_t ml_register_hooks (apr_pool_t *p);

APR_INLINE
static void ml_filter_relocate(ap_filter_t *f)
{
  request_rec *r = f->r;

  if (f != r->input_filters)
  {
    ap_filter_t *top = r->input_filters;
    ap_remove_input_filter(f);
    r->input_filters = f;
    f->next = top;
  }
}

#define MLE_FILTER_NAME "luaex"

/**
 * The Apache2 Module Magic Number for use in the Apache 2.x module structures
 * This gets bumped if changes in th4e API will break third party applications
 * using this apache2 module
 * @see APREQ_MODULE
 */
#define MOD_LUAEX_MMN 20101207

/** @} */

void *ml_create_server(apr_pool_t *p, server_rec *s);
int ml_process_connection(conn_rec *c);
const char *ml_set_server_handle(cmd_parms *cmd, void *_cfg,
                                 const char *name,
                                 const char *file);
const char *ml_set_method_handle(cmd_parms *cmd, void *_cfg,
                                 const char *name,
                                 const char *file,
                                 const char *funcname);

int ml_call(lua_State *L, const char *func, const char *sig, ...) ;

#ifdef __cplusplus
}
#endif

#endif//MOD_LUAEX_PRIVATE
