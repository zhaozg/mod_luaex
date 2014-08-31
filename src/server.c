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
  { "OK",                         OK },
  { "DECLINED",                   DECLINED },
  { "HTTP_BAD_REQUEST",           HTTP_BAD_REQUEST },
  { "HTTP_UNAUTHORIZED",          HTTP_UNAUTHORIZED },
  { "HTTP_FORBIDDEN",             HTTP_FORBIDDEN },
  { "HTTP_NOT_FOUND",             HTTP_NOT_FOUND },
  { "HTTP_METHOD_NOT_ALLOWED",    HTTP_METHOD_NOT_ALLOWED },
  { "HTTP_INTERNAL_SERVER_ERROR", HTTP_INTERNAL_SERVER_ERROR },
  { "HTTP_MOVED_TEMPORARILY",     HTTP_MOVED_TEMPORARILY },
  { "AP_FILTER_ERROR",            AP_FILTER_ERROR },

  {"EBADARG",   APR_EBADARG},

  {"ERROR_GENERAL",   APREQ_ERROR_GENERAL},
  {"ERROR_TAINTED",   APREQ_ERROR_TAINTED},
  {"ERROR_INTERRUPT",    APREQ_ERROR_INTERRUPT},

  {"ERROR_BADDATA",   APREQ_ERROR_BADDATA},
  {"ERROR_BADCHAR",    APREQ_ERROR_BADCHAR},
  {"ERROR_BADSEQ",  APREQ_ERROR_BADSEQ},
  {"ERROR_BADATTR",    APREQ_ERROR_BADATTR},
  {"ERROR_BADHEADER",   APREQ_ERROR_BADHEADER},
  {"ERROR_BADUTF8", APREQ_ERROR_BADUTF8},

  {"ERROR_NODATA",    APREQ_ERROR_NODATA},
  {"ERROR_NOTOKEN",   APREQ_ERROR_NOTOKEN},
  {"ERROR_NOATTR",    APREQ_ERROR_NOATTR},
  {"ERROR_NOHEADER",  APREQ_ERROR_NOHEADER},
  {"ERROR_NOPARSER",    APREQ_ERROR_NOPARSER},

  {"ERROR_MISMATCH",    APREQ_ERROR_MISMATCH},
  {"ERROR_OVERLIMIT",   APREQ_ERROR_OVERLIMIT},
  {"ERROR_UNDERLIMIT",    APREQ_ERROR_UNDERLIMIT},
  {"ERROR_NOTEMPTY",    APREQ_ERROR_NOTEMPTY},

  {"CHARSET_ASCII",    APREQ_CHARSET_ASCII},
  {"CHARSET_LATIN1",   APREQ_CHARSET_LATIN1}, /* ISO-8859-1   */
  {"CHARSET_CP1252",  APREQ_CHARSET_CP1252}, /* Windows-1252 */
  {"CHARSET_UTF8",    APREQ_CHARSET_UTF8},

  {"JOIN_AS_IS",  APREQ_JOIN_AS_IS},      /**< Join the strings without modification */
  {"JOIN_ENCODE", APREQ_JOIN_ENCODE},     /**< Url-encode the strings before joining them */
  {"JONE_DECODE", APREQ_JOIN_DECODE},     /**< Url-decode the strings before joining them */
  {"JONE_QUOTE",  APREQ_JOIN_QUOTE},       /**< Quote the strings, backslashing existing quote marks. */

  {"MATCH_FULL",    APREQ_MATCH_FULL},       /**< Full match only. */
  {"MATCH_PARTIAL", APREQ_MATCH_PARTIAL},     /**< Partial matches are ok. */
  {"OVERLAP_TABLES_SET",    APR_OVERLAP_TABLES_SET},       /**< Full match only. */
  {"OVERLAP_TABLES_MERGE",  APR_OVERLAP_TABLES_MERGE},     /**< Partial matches are ok. */


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


/*scoreboard api*/

static int lua_ap_scoreboard_process(lua_State *L)
{
  int i = luaL_checkint(L, 1);
  process_score* ps_record = ap_get_scoreboard_process(i);
  if (ps_record)
  {
    lua_newtable(L);

    lua_pushstring(L, "connections");
    lua_pushnumber(L, ps_record->connections);
    lua_settable(L, -3);

    lua_pushstring(L, "keepalive");
    lua_pushnumber(L, ps_record->keep_alive);
    lua_settable(L, -3);

    lua_pushstring(L, "lingering_close");
    lua_pushnumber(L, ps_record->lingering_close);
    lua_settable(L, -3);

    lua_pushstring(L, "pid");
    lua_pushnumber(L, ps_record->pid);
    lua_settable(L, -3);

    lua_pushstring(L, "suspended");
    lua_pushnumber(L, ps_record->suspended);
    lua_settable(L, -3);

    lua_pushstring(L, "write_completion");
    lua_pushnumber(L, ps_record->write_completion);
    lua_settable(L, -3);

    lua_pushstring(L, "not_accepting");
    lua_pushnumber(L, ps_record->not_accepting);
    lua_settable(L, -3);

    lua_pushstring(L, "quiescing");
    lua_pushnumber(L, ps_record->quiescing);
    lua_settable(L, -3);

    return 1;
  }
  return 0;
}

static int lua_ap_scoreboard_worker(lua_State *L)
{
  int i = luaL_checkint(L, 1); /*child num*/
  int j = luaL_checkint(L, 2); /*thread num*/
  worker_score* ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
  if (ws_record)
  {
    lua_newtable(L);

    lua_pushstring(L, "access_count");
    lua_pushnumber(L, ws_record->access_count);
    lua_settable(L, -3);

    lua_pushstring(L, "bytes_served");
    lua_pushnumber(L, (lua_Number)ws_record->bytes_served);
    lua_settable(L, -3);

    lua_pushstring(L, "client");
    lua_pushstring(L, ws_record->client);
    lua_settable(L, -3);

    lua_pushstring(L, "conn_bytes");
    lua_pushnumber(L, (lua_Number)ws_record->conn_bytes);
    lua_settable(L, -3);

    lua_pushstring(L, "conn_count");
    lua_pushnumber(L, ws_record->conn_count);
    lua_settable(L, -3);

    lua_pushstring(L, "generation");
    lua_pushnumber(L, ws_record->generation);
    lua_settable(L, -3);

    lua_pushstring(L, "last_used");
    lua_pushnumber(L, (lua_Number)ws_record->last_used);
    lua_settable(L, -3);

    lua_pushstring(L, "pid");
    lua_pushnumber(L, ws_record->pid);
    lua_settable(L, -3);

    lua_pushstring(L, "request");
    lua_pushstring(L, ws_record->request);
    lua_settable(L, -3);

    lua_pushstring(L, "start_time");
    lua_pushnumber(L, (lua_Number)ws_record->start_time);
    lua_settable(L, -3);

    lua_pushstring(L, "status");
    lua_pushnumber(L, ws_record->status);
    lua_settable(L, -3);

    lua_pushstring(L, "stop_time");
    lua_pushnumber(L, (lua_Number)ws_record->stop_time);
    lua_settable(L, -3);

#if APR_HAS_THREADS
    lua_pushstring(L, "tid");
    lua_pushinteger(L, (lua_Integer)ws_record->tid);
    lua_settable(L, -3);
#endif

    lua_pushstring(L, "vhost");
    lua_pushstring(L, ws_record->vhost);
    lua_settable(L, -3);

    return 1;
  }
  return 0;
}

static int lua_ap_restarted_time(lua_State *L)
{
  lua_pushnumber(L, (lua_Number)ap_scoreboard_image->global->restart_time);
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

  lua_pushcfunction (L, lua_ap_restarted_time);
  lua_setfield(L, -2, "restarted_time");

  lua_pushcfunction (L, lua_ap_scoreboard_process);
  lua_setfield(L, -2, "scoreboard_process");

  lua_pushcfunction (L, lua_ap_scoreboard_worker);
  lua_setfield(L, -2, "scoreboard_worker");

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
