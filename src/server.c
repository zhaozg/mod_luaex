#include "mod_luaex.h"

#include "mod_dbd.h"
#include <mod_so.h>
#include <lua_apr.h>

#include "private.h"

#include <ap_mpm.h>
#include <scoreboard.h>

#ifdef WIN32
#include <process.h>
#endif


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

void ml_define_constants (lua_State *L, const  ml_constants tab[])
{
  int i;
  for (i = 0; tab[i].name != NULL; i++)
  {
    lua_pushstring (L, tab[i].name);
    lua_pushnumber (L, tab[i].val);
    lua_settable (L, -3);
  }
}

/************************************************************************/
/* lua extends api not need any apache2 objects paramater               */
/************************************************************************/
static int ml_table_remove(lua_State*L)
{
  apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
  const char* key = luaL_checkstring(L, 2);
  apr_table_unset(t, key);
  return 0;
}


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
static int lua_ap_strcmp_match (lua_State *L)
{

  int returnValue;
  const char* str = luaL_checkstring(L, 1);
  const char* expected = luaL_checkstring(L, 2);
  int ignoreCase = 0;

  if ( lua_isboolean( L, 3 ) )
    ignoreCase =  lua_toboolean( L, 3 );

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
static int lua_ap_exists_config_define (lua_State *L)
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

/*** register apache2 apis ***/
int ml_apache2_extends(lua_State*L)
{
  int limit = 0;

  lua_getglobal(L, "apache2");  /*get apache2 table*/

  lua_pushnumber (L, (lua_Number)getpid ());
  lua_setfield(L, -2, "pid");

  lua_pushcfunction(L, ml_table_remove);
  lua_setfield(L, -2, "remove");

  lua_pushcfunction(L, lua_ap_module_info);
  lua_setfield(L, -2, "module_info");

  lua_pushcfunction(L, lua_ap_loaded_modules);
  lua_setfield(L, -2, "loaded_modules");

  lua_pushcfunction(L, lua_ap_strcmp_match);
  lua_setfield(L, -2, "strcmp_match");

  lua_pushcfunction(L, lua_ap_exists_config_define);
  lua_setfield(L, -2, "exists_config_define");

  lua_pushcfunction (L, lua_ap_method_register);
  lua_setfield(L, -2, "method_register");

  ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &limit);
  lua_pushinteger(L, limit);
  lua_setfield(L, -2, "scoreboard_thread_limit");

  ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &limit);
  lua_pushinteger(L, limit);
  lua_setfield(L, -2, "scoreboard_process_limit");

  ml_define_constants (L, status_tabs);

  lua_pop(L, 1); /*pop apache2 table */

  return 0;
}
