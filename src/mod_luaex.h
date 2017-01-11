#ifndef _MOD_LUAEX_H
#define _MOD_LUAEX_H

# ifdef WIN32
#  define LUA_APR_IMPORT __declspec(dllimport)
# else
#  define LUA_APR_IMPORT extern
# endif

#include "mod_lua.h"

/* Lua utilities interface */
typedef struct lua_State lua_State;
typedef struct
{
  const char *name;
  int val;
} ml_constants;

void ml_define_constants(lua_State *L, const  ml_constants tab[]);
int ml_call(lua_State *L, const char *func, const char *sig, ...);
int ml_isudata(lua_State *L, int ud, const char *tname);
void *ml_check_object(lua_State *L, int index, const char*metaname);
int  ml_push_object(lua_State*L, const void* data, const char*metaname);

#define setstr(key,value)\
  lua_pushstring(L,key);\
  if (value)  lua_pushstring(L,value); else lua_pushnil(L);\
  lua_settable(L,-3)

#define setnum(key,value)\
  lua_pushstring(L,key);\
  lua_pushnumber(L,(double)value);\
  lua_settable(L,-3)

#define setnum2(key,value)\
  lua_pushnumber(L,key);\
  lua_pushnumber(L,(double)value);\
  lua_settable(L,-3)

#define setnum3(key,value)\
  lua_pushnumber(L,key);\
  lua_pushstring(L,value);\
  lua_settable(L,-3)

/* compat with mod_lua */
req_fun_t *ml_makefun(const void *fun, int type, apr_pool_t *pool);

/* apache module section */
#include <http_main.h>
#include <util_script.h>
#include <mpm_common.h>
#include <mod_so.h>

#define ML_POST_BUFFER_SIZE   (128 * 1024 * 1024)

extern module AP_MODULE_DECLARE_DATA luaex_module;
extern APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *ap_find_module;

struct dir_config
{
  apr_hash_t         *resource; /* hash table for usage->apr_reslist_t */
  lua_State          *L;
};

module* ml_find_module(server_rec*s, const char*m);

int ml_apache2_extends(lua_State*L);
void ml_ext_request_lmodule(lua_State *L, apr_pool_t *p);

apr_status_t ml_register_hooks(apr_pool_t *p);
apr_status_t ml_retrieve_option_functions(apr_pool_t *p);
int ml_push_status(lua_State*L, apr_status_t status);

#define CHECK_REQUEST_OBJECT(x)  ml_check_object(L, x,"Apache2.Request")
#define CHECK_CONNECTION_OBJECT(x)  ml_check_object(L, x,"Apache2.Connection")
#define CHECK_SERVER_OBJECT(x)  ml_check_object(L, x,"Apache2.Server")

/* extends section */
#include <ap_provider.h>
#include <ap_slotmem.h>
#include <ap_socache.h>


#define PROVIDER  "provider"
#define SOCACHE   "socache"

typedef struct ml_slotmem_t
{
  ap_slotmem_provider_t   *_provider;
  ap_slotmem_instance_t   *_instance;
  apr_size_t              _size;
  unsigned int            _num;
  ap_slotmem_type_t       _type;
} ml_slotmem;

typedef struct ml_socache_t
{
  ap_socache_provider_t* _provider;
  ap_socache_instance_t* _instance;
  server_rec       * _server;
  apr_pool_t       * _pool;
  apr_time_t       _timeout;

  int _maxdatalen;
} ml_socache;

int ml_luaopen_extends(lua_State*L);

int ml_socache_lookup(lua_State*L);

int ml_slotmem_lookup(lua_State*L);
int ml_slotmem_create(lua_State*L);
int ml_slotmem_attach(lua_State*L);

int ml_session_load(lua_State* L);
int ml_session_save(lua_State* L);
int ml_session_get(lua_State* L);
int ml_session_set(lua_State* L);

int ml_list_provider(lua_State*L);

int ml_reslist_acquire(lua_State*L);
int ml_reslist_release(lua_State*L);
int ml_reslist_invalidate(lua_State*L);

#define CHECK_SESSION_OBJECT(x) ml_check_object(L, x, "mod_luaex.session")
#define CHECK_SOCACHE_OBJECT(x) ((ml_socache*)luaL_checkudata(L, x, "mod_luaex.socache"))
#define CHECK_SLOTMEM_OBJECT(x) ((ml_slotmem*)luaL_checkudata(L, x, "mod_luaex.slotmem"))

#endif
