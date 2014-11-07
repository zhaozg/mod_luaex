#include "mod_luaex.h"
#include <ap_slotmem.h>

#include <mod_session.h>
#include <mod_ssl.h>
#include "lua_request.h"
#include "lua_apr.h"

static APR_OPTIONAL_FN_TYPE(ap_session_get)  *ap_session_get = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_set)  *ap_session_set = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_load) *ap_session_load = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_save) *ap_session_save = NULL;

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https)   *ssl_is_https = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_ext_list)   *ssl_ext_list = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable)   *ssl_proxy_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable)   *ssl_engine_disable = NULL;

static APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *ap_find_loaded_module_symbol = NULL;

apr_status_t ml_retrieve_option_functions (apr_pool_t *p)
{
  ap_session_get = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
  ap_session_set = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
  ap_session_load = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
  ap_session_save = APR_RETRIEVE_OPTIONAL_FN(ap_session_save);

  ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
  ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

  ap_find_loaded_module_symbol = APR_RETRIEVE_OPTIONAL_FN(ap_find_loaded_module_symbol);

  return APR_SUCCESS;
}

module* ml_find_module(server_rec*s, const char*m)
{
  if (ap_find_loaded_module_symbol)
  {
    return ap_find_loaded_module_symbol(s, m);
  }
  return NULL;
}

apr_table_t* ml_check_apr_table(lua_State *L, int index)
{
  req_table_t* t = ap_lua_check_apr_table(L, index);
  if (t)
    return t->t;
  return NULL;
}
void ml_push_apr_table(lua_State *L, apr_table_t *ta, request_rec* r, const char*name, apr_pool_t* pool)
{
  req_table_t* t = apr_pcalloc(r ? r->pool : pool, sizeof(req_table_t));
  t->t = ta;
  t->r = r;
  t->n = name;
  ap_lua_push_apr_table(L, t);
}

/************************************************************************/
/* Session extend API                                                   */
/************************************************************************/
int ml_session_load(lua_State* L)
{
  if (ap_session_load)
  {
    apr_status_t status;
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    session_rec *sess = NULL;
    status = apr_pool_userdata_get((void**)&sess, "ml_session", r->pool);
    if (status == APR_SUCCESS)
    {
      if (sess == NULL)
      {
        status = ap_session_load(r, &sess);
        if (status != APR_SUCCESS)
          return ml_push_status(L, status);
        status = apr_pool_userdata_setn(sess, "ml_session", NULL, r->pool);
        if (status != APR_SUCCESS)
          return ml_push_status(L, status);
      }
      lua_pushboolean(L, sess != NULL);
      return 1;
    }
    return ml_push_status(L, status);
  }
  return 0;
}

int ml_session_save(lua_State* L)
{
  if (ap_session_save)
  {
    apr_status_t status;
    session_rec *sess;
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    status = apr_pool_userdata_get((void**)&sess, "ml_session", r->pool);
    if (status == APR_SUCCESS)
    {
      if (sess != NULL)
      {
        status = ap_session_save(r, sess);
        if (status == APR_SUCCESS)
        {
          lua_pushboolean(L, 1);
          return 1;
        }
        return ml_push_status(L, status);
      }
      lua_pushboolean(L, 0);
      return 1;
    }
    return ml_push_status(L, status);
  }
  return 0;
}

int ml_session_get(lua_State* L)
{
  if (ap_session_get)
  {
    apr_status_t status;
    session_rec *sess;
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    status = apr_pool_userdata_get((void**)&sess, "ml_session", r->pool);
    if (status == APR_SUCCESS)
    {
      const char* key = luaL_checkstring(L, 2);
      const char* val = NULL;
      ap_session_get(r, sess, key, &val);
      if (val)
        lua_pushstring(L, val);
      else
        lua_pushnil(L);
      return 1;
    }
    return ml_push_status(L, status);
  }
  return 0;
}

int ml_session_set(lua_State* L)
{
  if (ap_session_get)
  {
    apr_status_t status;
    session_rec *sess;
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    status = apr_pool_userdata_get((void**)&sess, "ml_session", r->pool);
    if (status == APR_SUCCESS)
    {
      const char* key = luaL_checkstring(L, 2);
      const char* val = luaL_optstring(L, 3, NULL);
      ap_session_set(r, sess, key, val);
      lua_pushstring(L, val);
      return 1;
    }
    return ml_push_status(L, status);
  }
  return 0;
}

/************************************************************************/
/* socache & slotmem extend API                                         */
/************************************************************************/

int ml_list_provider(lua_State*L)
{
  const request_rec* r = CHECK_REQUEST_OBJECT(1);
  const char*group = luaL_checkstring(L, 2);
  const char*version = luaL_optstring(L, 3, "0");
  apr_array_header_t* arr = ap_list_provider_names(r->pool, group, version);

  lua_pushstring(L, apr_array_pstrcat(r->pool, arr, ','));
  return 1;
}

/* slotmem */
int ml_slotmem_lookup(lua_State*L)
{
  const char* provider_name = luaL_checkstring(L, 1);
  const char* provider_group = luaL_optstring(L, 2, AP_SLOTMEM_PROVIDER_GROUP);
  const char* provider_version = luaL_optstring(L, 3, "0");
  ap_slotmem_provider_t *provider = ap_lookup_provider(provider_group, provider_name, provider_version);
  ml_slotmem *mem = NULL;

  if (provider == NULL)
    return 0;

  mem = lua_newuserdata(L, sizeof(ml_slotmem));
  mem->_provider = provider;
  mem->_num = 0;
  mem->_size = 0;
  mem->_type = 0;
  luaL_getmetatable(L, "mod_luaex.slotmem");
  lua_setmetatable(L, -2);
  return 1;
}

int ml_slotmem_create(lua_State*L)
{
  const request_rec* r = CHECK_REQUEST_OBJECT(1);
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(2);
  const char* name = luaL_checkstring(L, 3);
  apr_status_t status;
  sm->_size = luaL_optint(L, 4, sm->_size);
  sm->_num  = luaL_optint(L, 5, sm->_num);
  sm->_type = luaL_optint(L, 6, sm->_type);

  status = sm->_provider->create(&sm->_instance, name, sm->_size + sizeof(int), sm->_num, sm->_type, r->pool);
  return ml_push_status(L, status);
}

int ml_slotmem_attach(lua_State*L)
{
  const request_rec* r = CHECK_REQUEST_OBJECT(1);
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(2);
  const char* name = luaL_checkstring(L, 3);
  apr_status_t status;

  status = sm->_provider->attach(&sm->_instance, name, &sm->_size, &sm->_num, r->pool);
  if (status == APR_SUCCESS) sm->_size -= sizeof(int);
  return ml_push_status(L, status);
}

/* index */
static int ml_smp_get(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  int id = luaL_checkint(L, 2);
  char* buf = malloc(sm->_size);
  apr_status_t status = sm->_provider->get(sm->_instance, id, (unsigned char*)buf, sm->_size);
  if (status == APR_SUCCESS)
  {
    int size = *(int*)buf;
    if (size > 0)
      lua_pushlstring(L, buf + sizeof(int), size);
    else
      lua_pushnil(L);
    free(buf);
    return 1;
  }
  return ml_push_status(L, status);
}

/* newindex */
static int ml_smp_put(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  int id = luaL_checkint(L, 2);
  apr_status_t status;
  if (lua_isnil(L, 3))
  {
    sm->_provider->release(sm->_instance, id);
  }
  else
  {
    int len = lua_objlen(L, 3);
    char* dat = malloc(sm->_size + sizeof(int));
    *(int*)dat = len;
    strncpy(dat + sizeof(int), luaL_checkstring(L, 3), len);
    status = sm->_provider->put(sm->_instance, id, (unsigned char*)dat, len + sizeof(int));
  }
  return ml_push_status(L, status);
}

/* len */
static int ml_smp_len(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  lua_pushinteger(L, sm->_provider->num_slots(sm->_instance));
  return 1;
}

/* unm */
static int ml_smp_free_slots(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  lua_pushinteger(L, sm->_provider->num_free_slots(sm->_instance));
  return 1;
}

/* tostring */
static int ml_smp_tostring(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  lua_pushfstring(L, "%s v%d(%s):%p",
                  AP_SLOTMEM_PROVIDER_GROUP, AP_SLOTMEM_PROVIDER_VERSION,
                  sm->_provider->name,
                  sm->_instance);
  return 1;
}

static  apr_status_t  ml_smp_docall(void* mem, void *data, apr_pool_t *p)
{
  char* buf = mem;
  ml_slotmem *sm = data;
  lua_State *L = (lua_State *)p;
  int len = *(int*)mem;
  int n  = lua_gettop(L);

  lua_pushvalue(L, 1);
  lua_pushlstring(L, buf + sizeof(int), len);
  /*proto:
      1 slotmem
      2.function
      n,end of args.
      n+1 slotmem
      n+2 data
  */
  if (lua_pcall(L, n, 0, 0) == 0)
    return APR_SUCCESS;
  lua_error(L);
  return APR_SUCCESS;
}

/* call */
static int ml_smp_call(lua_State*L)
{
  ml_slotmem* sm = CHECK_SLOTMEM_OBJECT(1);
  if (lua_isstring(L, 2) && strcmp("size", lua_tostring(L, 2)) == 0)
  {
    lua_pushinteger(L, sm->_provider->slot_size(sm->_instance));
    return 1;
  }
  else if (lua_isfunction(L, 2))
  {
    sm->_provider->doall(sm->_instance, ml_smp_docall, sm, (void*)L);
  }
  else
  {
    int id;
    apr_status_t status = sm->_provider->grab(sm->_instance, &id);
    if (status == APR_SUCCESS)
    {
      lua_pushinteger(L, id);
      return 1;
    }
    return ml_push_status(L, status);
  }
  return 0;
}

static luaL_Reg sm_provider_mtab[] =
{
  {"__tostring",  ml_smp_tostring},
  {"__newindex",  ml_smp_put},
  {"__index",   ml_smp_get},
  {"__len",       ml_smp_len},
  {"__call",      ml_smp_call},
  {"__unm",       ml_smp_free_slots},
  {NULL,      NULL}
};

/* socache */
/* newindex */
static int ml_sop_store(lua_State*L)
{
  ml_socache *c = CHECK_SOCACHE_OBJECT(1);
  size_t kl = 0, dl = 0;
  char* key = (char*)luaL_checklstring(L, 2, &kl);
  char* dat = NULL;
  int n = lua_gettop(L);
  apr_status_t rv = 0;
  if (lua_isnil(L, 3))
  {
    rv = c->_provider->remove(c->_instance, c->_server, key, kl, c->_pool);
  }
  else
  {
    dat = (char* )luaL_checklstring(L, 3, &dl);
    rv = c->_provider->store(c->_instance, c->_server, key, kl, c->_timeout + apr_time_now(), dat, dl, c->_pool);
  }
  return ml_push_status(L, rv);
}

/* index */
static int ml_sop_retrieve(lua_State*L)
{
  ml_socache *c = CHECK_SOCACHE_OBJECT(1);
  size_t kl = 0, dl = c->_maxdatalen;
  const char* key = luaL_checklstring(L, 2, &kl);
  apr_status_t rv;
  unsigned char* dat = malloc(dl);
  rv = c->_provider->retrieve(c->_instance, c->_server, key, kl, dat, (unsigned int*)&dl, c->_pool);
  if (rv == APR_SUCCESS)
  {
    //c->_provider->store(c->_instance,c->_server,key,kl,c->_timeout+apr_time_now(),dat,dl,c->_pool);
    lua_pushlstring(L, dat, dl);
    free(dat);
  }
  else
    lua_pushnil(L);
  return 1;
}

static int ml_sop_tostring(lua_State*L)
{
  ml_socache *c = CHECK_SOCACHE_OBJECT(1);
  lua_pushfstring(L, "socache %s(%p):%p", c->_provider->name, c->_provider, c->_instance);
  return 1;
}

static apr_status_t ml_provider_next(ap_socache_instance_t *instance,
                                     server_rec *s,
                                     void *userctx,
                                     const unsigned char *id,
                                     unsigned int idlen,
                                     const unsigned char *data,
                                     unsigned int datalen,
                                     apr_pool_t *pool)
{
  lua_State* L = (lua_State*)userctx;
  lua_pushlstring(L, id, idlen);
  lua_pushlstring(L, data, datalen);
  lua_settable(L, -2);
  return APR_SUCCESS;
}

static int ml_so_provider_table(lua_State*L)
{
  ml_socache *c = CHECK_SOCACHE_OBJECT(1);
  lua_newtable(L);
  if (c->_provider->iterate(c->_instance, c->_server, L, ml_provider_next, c->_pool) == APR_SUCCESS)
  {
    return 1;
  }

  return 0;
}


static luaL_Reg so_provider_mtab[] =
{
  {"__tostring",  ml_sop_tostring},
  {"__newindex",  ml_sop_store},
  {"__index",   ml_sop_retrieve},
  {"__call",      ml_so_provider_table},
  {NULL,      NULL}
};

void (*status)(ap_socache_instance_t *instance, request_rec *r, int flags);

int ml_socache_lookup(lua_State*L)
{
  const request_rec* r = CHECK_REQUEST_OBJECT(1);
  server_rec *s = r->server;
  apr_pool_t *pool = s->process->pool; //store provider in pool
  const char *provider_id = luaL_checkstring(L, 2);
  apr_time_t timeout  = luaL_optint(L, 3, 30 * 60);
  const char *provider_name = luaL_optstring(L, 4, AP_SOCACHE_DEFAULT_PROVIDER);
  const char *provider_arg  = luaL_optstring(L, 5, NULL);
  ml_socache *c = NULL;
  apr_status_t status = APR_SUCCESS;
  char socache_key[128];
  struct ap_socache_hints hints = {0};
  hints.avg_id_len = 64;
  hints.avg_obj_size = 1024;
  hints.expiry_interval = timeout;

  apr_snprintf(socache_key, 128, "%s_%s_%s", provider_id, provider_name, AP_SOCACHE_PROVIDER_GROUP);

  status = apr_pool_userdata_get((void**)&c, socache_key, pool);
  if ( status == APR_SUCCESS )
  {
    if (c == NULL)
    {
      const char* err;
      c = lua_newuserdata(L, sizeof(ml_socache));
      c->_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, provider_name, AP_SOCACHE_PROVIDER_VERSION);
      err = c->_provider->create(&c->_instance, provider_arg, pool, pool);
      if (err)
      {
        luaL_error(L, err);
      }
      c->_provider->init(c->_instance, provider_id, &hints, s, pool);
      c->_server = s;
      c->_timeout = timeout * APR_USEC_PER_SEC;
      c->_maxdatalen = 1024;
      apr_pool_userdata_set(c, socache_key, apr_pool_cleanup_null, pool);
    }
    c->_pool = r->pool;
    lua_boxpointer(L, c);
    luaL_getmetatable(L, "mod_luaex.socache");
    lua_setmetatable(L, -2);
  }
  else
  {
    char err[APR_PATH_MAX];
    apr_strerror(status, err, APR_PATH_MAX);
    luaL_error(L, err);
  }

  return 1;
}

/************************************************************************/
/* DBD extend API                                                       */
/************************************************************************/


int ml_luaopen_extends(lua_State *L)
{
  luaL_newmetatable(L, "mod_luaex.socache");
  luaL_register(L, NULL, so_provider_mtab);
  luaL_newmetatable(L, "mod_luaex.slotmem");
  luaL_register(L, NULL, sm_provider_mtab);
  return 1;
}
