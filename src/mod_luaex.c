#include "mod_luaex.h"

#include <mod_so.h>

#if AP_SERVER_MAJORVERSION_NUMBER!=2
#error Sorry, Only support Apache2
#endif

void *ml_check_object(lua_State *L, int index, const char*metaname)
{
  luaL_checkudata(L, index, metaname);
  return lua_unboxpointer(L, index);
}

int  ml_push_object(lua_State*L, const void* data, const char*metaname)
{
  lua_boxpointer(L, (void*)data);
  luaL_getmetatable(L, metaname);
  lua_setmetatable(L, -2);
  return 1;
}

int ml_push_status(lua_State*L, apr_status_t status)
{
  char err[APR_PATH_MAX];
  if (status == APR_SUCCESS)
  {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushnil(L);
  lua_pushinteger(L, status);
  apr_strerror(status, err, APR_PATH_MAX);
  lua_pushstring(L, err);
  return 3;
}

int ml_isudata (lua_State *L, int ud, const char *tname)
{
  void *p = lua_touserdata(L, ud);
  if (p != NULL)    /* value is a userdata? */
  {
    if (lua_getmetatable(L, ud))    /* does it have a metatable? */
    {
      lua_getfield(L, LUA_REGISTRYINDEX, tname);  /* get correct metatable */
      if (lua_rawequal(L, -1, -2))    /* does it have the correct mt? */
      {
        lua_pop(L, 2);  /* remove both metatables */
        return 1;
      }
    }
  }
  return 0;  /* to avoid warnings */
}

/*
  sig define call lua function protocol
  lua function
  function hello(name, a, b)
    return a+b, "hello "..name
  end
  lb_call_va(L,"hello","sii>is",name,1,2,&i,&s)
  before > are args, support
    i : int,  number
    d : double, number
    s : char* with zero end, string
    S : char* follow by buffer size, string
    p : lightuser, userdata
    f : cfunction, function
    b : int, boolean
    z : void*, nil
    r : request_rec
  after > are return value, support
      i : int,  number
      d : double, number
      s : char* with zero end, string
      S : char* follow by buffer size, string
      p : lightuser, userdata
      b : int, boolean
*/
int ml_call_varg(lua_State *L, const char *func, const char *sig, va_list vl)
{
  int status;
  int narg, nres;   /* number of arguments and results */
  int size;

  lua_getglobal(L, func);  /* get function */

  /* push arguments */
  narg = 0;
  while (*sig)      /* push arguments */
  {
    switch (*sig++)
    {
    case 'd':  /* double argument */
      lua_pushnumber(L, va_arg(vl, double));
      break;
    case 'i':  /* int argument */
      lua_pushinteger(L, va_arg(vl, int));
      break;
    case 's':  /* string argument */
      lua_pushstring(L, va_arg(vl, char *));
      break;
    case 'S':
    {
      const char* bs = va_arg(vl, char *);
      lua_pushlstring(L, bs, va_arg(vl, int));
    }
    break;
    case 'b':
      lua_pushboolean(L, va_arg(vl, int));
      break;
    case 'p':
      lua_pushlightuserdata(L, va_arg(vl, void*));
      break;
    case 'f':
      lua_pushcfunction(L, (lua_CFunction)va_arg(vl, void*));
      break;
    case 'r':
      ml_push_object(L, va_arg(vl, void*), "Apache2.Request");
      break;
    case 'z':
      va_arg(vl, void*);
      lua_pushnil(L);
      break;
    case '>':
      goto endwhile;
    default:
      luaL_error(L, "invalid option (%c)", *(sig - 1));
    }
    narg++;
    luaL_checkstack(L, 1, "too many arguments");
  }
endwhile:

  /* do the call */
  nres = strlen(sig);  /* number of expected results */
  status = lua_pcall(L, narg, nres, 0);
  if (status == 0)
  {
    /* retrieve results */
    nres = -nres;     /* stack index of first result */
    while (*sig)      /* get results */
    {
      switch (*sig++)
      {
      case 'd':  /* double result */
        *va_arg(vl, double *) = luaL_checknumber(L, nres);
        break;
      case 'i':  /* int result */
        *va_arg(vl, int *) = (int)luaL_checkinteger(L, nres);
        break;
      case 's':  /* string result */
        *va_arg(vl, const char **) = luaL_checkstring(L, nres);
        break;
      case 'S':
        size = 0;
        *va_arg(vl, const char **) = luaL_checklstring(L, nres, (size_t*)&size);
        *va_arg(vl, int *) = size;
        break;
      case 'b':  /* boolean result */
        *va_arg(vl, int *) = (int)lua_toboolean(L, nres);
        break;
      case 'p':
        if (!lua_islightuserdata(L, nres) && !lua_isnil(L, nres))
          luaL_error(L, "wrong result type, expect for pointer");
        *va_arg(vl, void **) = (void*)lua_topointer(L, nres);
        break;
      default:
        luaL_error(L, "invalid option (%c)", *(sig - 1));
      }
      nres++;
    }
  }
  else
  {
    /* do the call */
    printf("***mod_luaex: %s Error %s\n", func, lua_tostring(L, -1));
    luaL_dostring(L, "debug.traceback(2)");
    /* luaL_error(L, "error running function `%s': %s", func, lua_tostring(L, -1)); */
  }

  return status;
}
int ml_call(lua_State *L, const char *func, const char *sig, ...)
{
  int status;
  va_list vl;
  va_start(vl, sig);
  status = ml_call_varg(L, func, sig, vl);
  va_end(vl);
  return status;
}

/* ml_handler                                                          */
static int ml_load_chunk(lua_State *L, const char* script, const char* title)
{
  int status = 0;
  lua_getfield(L, LUA_REGISTRYINDEX, script);

  status = luaL_loadfile(L, script);
  if ((!lua_isfunction(L, -1) && !lua_iscfunction(L, -1)) || lua_pcall(L, 0, 0, 0))
  {
    printf("***mod_luaex: %s Error %s\n", script, lua_tostring(L, -1));
    luaL_dostring(L, "debug.traceback(1)");
    status = LUA_ERRERR;
  }
  return status;
}

//////////////////////////////////////////////////////////////////////////
#ifdef HAVE_LUA_APR_BIND
apr_pool_t *lua_apr_pool_register(lua_State *L, apr_pool_t *new_pool);
int luaopen_apr_core(lua_State *L);
#endif
static apr_status_t ml_pool_register(lua_State *L, apr_pool_t*pool )
{
#ifdef HAVE_LUA_APR_BIND
  lua_apr_pool_register(L, pool);
#endif
  return OK;
}

static apr_status_t ml_lua_request(lua_State *L, request_rec *r)
{
  return ml_pool_register(L, r->pool);
};

static apr_status_t ml_lua_open(lua_State *L, apr_pool_t *p)
{
  ml_pool_register(L, p);
  ml_apache2_extends(L);

  // Get package.preload so we can store builtins in it.
  lua_getglobal(L, "package");
  lua_getfield(L, -1, "preload");
  lua_remove(L, -2); // Remove package
#ifdef HAVE_LUA_APR_BIND
  lua_pushcfunction(L, luaopen_apr_core);
  lua_setfield(L, -2, "apr.core");
#endif
  lua_pop(L, 1);

  ml_luaopen_extends(L) ;
  ml_ext_request_lmodule(L, p);
  return OK;
};

apr_status_t ml_register_hooks (apr_pool_t *p)
{
  ap_find_module = APR_RETRIEVE_OPTIONAL_FN(ap_find_loaded_module_symbol);
  APR_OPTIONAL_HOOK(ap_lua, lua_request,  ml_lua_request, NULL, NULL, APR_HOOK_MIDDLE);
  APR_OPTIONAL_HOOK(ap_lua, lua_open,     ml_lua_open,    NULL, NULL, APR_HOOK_MIDDLE);
  ml_retrieve_option_functions(p);

  return 0;
}

/* apache modules */

/* extend apache2 modules */
static const ml_constants status_tabs[] =
{
  { "HTTP_BAD_REQUEST",           HTTP_BAD_REQUEST },
  { "HTTP_UNAUTHORIZED",          HTTP_UNAUTHORIZED },
  { "HTTP_FORBIDDEN",             HTTP_FORBIDDEN },
  { "HTTP_NOT_FOUND",             HTTP_NOT_FOUND },
  { "HTTP_METHOD_NOT_ALLOWED",    HTTP_METHOD_NOT_ALLOWED },
  { "HTTP_INTERNAL_SERVER_ERROR", HTTP_INTERNAL_SERVER_ERROR },
  { "AP_FILTER_ERROR",            AP_FILTER_ERROR },

  { NULL, 0 }
};

void ml_define_constants(lua_State *L, const  ml_constants tab[])
{
  int i;
  for (i = 0; tab[i].name != NULL; i++)
  {
    lua_pushstring(L, tab[i].name);
    lua_pushnumber(L, tab[i].val);
    lua_settable(L, -3);
  }
}

/************************************************************************/
/* lua extends api not need any apache2 objects parameter               */
/************************************************************************/
static int lua_ap_module_info(lua_State *L)
{
  const char* moduleName = luaL_checkstring(L, 1);
  module* mod = ap_find_linked_module(moduleName);
  if (mod)
  {
    const command_rec *cmd;
    lua_newtable(L);
    lua_pushstring(L, "commands");
    lua_newtable(L);
    for (cmd = mod->cmds; cmd->name; ++cmd)
    {
      lua_pushstring(L, cmd->name);
      lua_pushstring(L, cmd->errmsg);
      lua_settable(L, -3);
    }
    lua_settable(L, -3);
    return 1;
  }
  return 0;
}

static int lua_ap_loaded_modules(lua_State *L)
{
  int i;
  lua_newtable(L);
  for (i = 0; ap_loaded_modules[i] && ap_loaded_modules[i]->name; i++)
  {
    lua_pushinteger(L, i + 1);
    lua_pushstring(L, ap_loaded_modules[i]->name);
    lua_settable(L, -3);
  }
  return 1;
}

static int lua_ap_server_info(lua_State *L)
{
  lua_newtable(L);

  lua_pushstring(L, "server_executable");
  lua_pushstring(L, ap_server_argv0);
  lua_settable(L, -3);

  lua_pushstring(L, "server_root");  /** ap_runtime_dir_relative() instead. */
  lua_pushstring(L, ap_server_root);
  lua_settable(L, -3);

  lua_pushstring(L, "runtime_dir");
  lua_pushstring(L, ap_runtime_dir);
  lua_settable(L, -3);

  lua_pushstring(L, "scoreboard_fname");
  lua_pushstring(L, ap_scoreboard_fname);
  lua_settable(L, -3);

  lua_pushstring(L, "server_mpm");
  lua_pushstring(L, ap_show_mpm());
  lua_settable(L, -3);

  lua_pushstring(L, "server_conf");
  ap_lua_push_server(L, ap_server_conf);
  lua_settable(L, -3);

  return 1;
}

/**
* ap_strcmp_match (const char *str, const char *expected)
* Determine if a string matches a patterm containing the wildcards '?' or '*'
* @param str The string to check
* @param expected The pattern to match against
* @return 1 if the two strings match, 0 otherwise
*/
static int lua_ap_strcmp_match(lua_State *L)
{
  int returnValue;
  const char* str = luaL_checkstring(L, 1);
  const char* expected = luaL_checkstring(L, 2);
  int ignoreCase = 0;

  if (lua_isboolean(L, 3))
    ignoreCase = lua_toboolean(L, 3);

  if (!ignoreCase)
    returnValue = ap_strcmp_match(str, expected);
  else
    returnValue = ap_strcasecmp_match(str, expected);
  lua_pushboolean(L, (!returnValue)); /* Somehow, this doesn't match the docs */
  return 1;
}

/**
* ap_exists_config_define (const char *name)
* Check for a definition from the server command line
* @param name The define to check for
* @return 1 if defined, 0 otherwise
*/
static int lua_ap_exists_config_define(lua_State *L)
{
  const char* name = luaL_checkstring(L, 1);
  lua_pushboolean(L, ap_exists_config_define(name));
  return 1;
}

static int lua_ap_method_register(lua_State *L)
{
  server_rec *s = (server_rec *)CHECK_SERVER_OBJECT(1);
  const char* method = luaL_checkstring(L, 2);
  int m = ap_method_register(s->process->pool, method);
  lua_pushinteger(L, m);
  return 1;
}

req_table_t *ap_lua_check_apr_table(lua_State *L, int index)
{
  req_table_t* t;
  luaL_checkudata(L, index, "Apr.Table");
  t = lua_unboxpointer(L, index);
  return t;
}

static int lua_ap_table_unset(lua_State *L)
{
  req_table_t* t = ap_lua_check_apr_table(L, 1);
  const char* key = luaL_checkstring(L, 2);
  apr_table_unset(t->t, key);
  return 0;
}

static int table_getm_do(void *v, const char *key, const char *val)
{
  lua_State *L = (lua_State *)v;
  lua_pushstring(L, val);
  return 1;
}

static int lua_ap_table_getm(lua_State *L)
{
  req_table_t* t = ap_lua_check_apr_table(L, 1);
  const char* key = luaL_checkstring(L, 2);
  int n = lua_gettop(L);
  apr_table_do(table_getm_do, L, t->t, key, NULL);
  return lua_gettop(L) - n;
}

static int lua_ap_table_add(lua_State *L) {
  req_table_t* t = ap_lua_check_apr_table(L, 1);
  const char* key = luaL_checkstring(L, 2);
  const char* val = luaL_checkstring(L, 3);

  apr_table_add(t->t, key, val);
  return 0;
}

/*** register apache2 apis ***/
int ml_apache2_extends(lua_State*L)
{
  int limit = 0;

  lua_getglobal(L, "apache2");  /*get apache2 table*/

  lua_pushnumber(L, (lua_Number)getpid());
  lua_setfield(L, -2, "pid");

  lua_pushcfunction(L, lua_ap_table_unset);
  lua_setfield(L, -2, "table_unset");

  lua_pushcfunction(L, lua_ap_table_getm);
  lua_setfield(L, -2, "table_getm");

  lua_pushcfunction(L, lua_ap_table_add);
  lua_setfield(L, -2, "table_add");

  lua_pushcfunction(L, lua_ap_module_info);
  lua_setfield(L, -2, "module_info");

  lua_pushcfunction(L, lua_ap_loaded_modules);
  lua_setfield(L, -2, "loaded_modules");

  lua_pushcfunction(L, lua_ap_strcmp_match);
  lua_setfield(L, -2, "strcmp_match");

  lua_pushcfunction(L, lua_ap_exists_config_define);
  lua_setfield(L, -2, "exists_config_define");

  lua_pushcfunction(L, lua_ap_method_register);
  lua_setfield(L, -2, "method_register");

  ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &limit);
  lua_pushinteger(L, limit);
  lua_setfield(L, -2, "scoreboard_thread_limit");

  ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &limit);
  lua_pushinteger(L, limit);
  lua_setfield(L, -2, "scoreboard_process_limit");

  ml_define_constants(L, status_tabs);

  lua_pop(L, 1); /*pop apache2 table */

  return 0;
}

/* module config and command */
static void *apreq_create_dir_config(apr_pool_t *p, char *d)
{
  /* d == OR_ALL */
  struct dir_config *dc = apr_palloc(p, sizeof * dc);

  dc->resource = NULL;
  dc->L = NULL;
  return dc;
}

const char *luaex_cmd_Reslist(cmd_parms *cmd,
                              void *dcfg,
                              const char *resource, const char *script);

static const command_rec apreq_cmds[] =
{
  AP_INIT_TAKE2("Luaex_Reslist", luaex_cmd_Reslist, NULL, OR_ALL,
  "Luaex Resource List management"
  "Luaex_Reslist ResourceName LuaScript"
  "(`@PATH --LuaScript handle Script FilePath', `lua handle script content')"
  "constructor and destructor function must be exist in LuaScript"
  "min, smax, hmax are option value, default is 0, 16, 16"),
  { NULL }
};

static void register_hooks(apr_pool_t *p)
{
  ml_register_hooks(p);
}

module AP_MODULE_DECLARE_DATA luaex_module =
{
  STANDARD20_MODULE_STUFF,
  apreq_create_dir_config,
  NULL,
  NULL,
  NULL,
  apreq_cmds,
  register_hooks,
};
