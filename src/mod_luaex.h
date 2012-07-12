#ifndef _MOD_LUAEX_H
#define _MOD_LUAEX_H

/* Apache headers */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "util_script.h"
#include "util_filter.h"

/* ARP headers */
#include "apr.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "apr_rmm.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_queue.h"
#include "apr_strings.h"
#include "apr_env.h"
#include "apr_thread_mutex.h"
#include "apr_thread_cond.h"
#include "apr_memcache.h"

#include "apr_optional.h"
#include "apr_hooks.h"
#include "apr_optional_hooks.h"

/* lua headers */
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "mod_lua.h"

#include <assert.h>
#include <stdarg.h>
#include <math.h>

/* The #ifdef macros are only defined AFTER including the above
* therefore we cannot include these system files at the top  :-(
*/
#if APR_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for STDIN_FILENO et.al., at least on FreeBSD */
#endif

/*
* Provide reasonable default for some defines
*/
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#ifndef PFALSE
#define PFALSE ((void *)FALSE)
#endif
#ifndef PTRUE
#define PTRUE ((void *)TRUE)
#endif
#ifndef UNSET
#define UNSET (-1)
#endif
#ifndef NUL
#define NUL '\0'
#endif
#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

#define APR_SHM_MAXSIZE (64 * 1024 * 1024)
#define MOD_LUA_STRING_VERSION  "mod_lua/1.0"

typedef enum {
	STORAGE_SCMODE_UNSET = UNSET,
	STORAGE_SCMODE_NONE  = 0,
	STORAGE_SCMODE_SHMHT = 1,
	STORAGE_SCMODE_SHMCB = 2,
} storage_scmode_t;

/*
* Define the STORAGE mutex modes
*/
typedef enum {
	STORAGE_MUTEXMODE_UNSET  = UNSET,
	STORAGE_MUTEXMODE_NONE   = 0,
	STORAGE_MUTEXMODE_USED   = 1
} storage_mutexmode_t;

#define MAX_HANDLERS 16



#ifndef BOOL
#define BOOL unsigned int
#endif
#ifndef UCHAR
#define UCHAR unsigned char
#endif

/*  API glue structures  */


#define VHOST(r) (r->server)

typedef struct {
	const char *name;
	int val;
} ml_constants;

void ml_define_constants (lua_State *L, const  ml_constants tab[]);

//output filter
#define ML_OUTPUT_FILTER_KEY4LUA	"luavm4outputfilter"

//socache
#define PROVIDER	"provider"
#define SOCACHE		"socache"

#define OBJECT(name)  name"_object"
#define LIBNAME(name) name

void *ml_check_object(lua_State *L, int index, const char*metaname);
int  ml_push_object(lua_State*L,const void* data, const char*metaname);
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


apr_status_t lua_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);
apr_status_t ml_register_hooks (apr_pool_t *p);

/************************************************************************/
/*                                                                      */
/************************************************************************/

#include <apr_dbd.h>
#include "mod_dbd.h"
#include "mod_luaex.h"

#include <ap_provider.h>
#include <ap_slotmem.h>
#include <ap_socache.h>

#ifndef STORAGE_CACHE_TIMEOUT
#define STORAGE_CACHE_TIMEOUT  600
#endif

/************************************************************************/
/*                                                                      */
/************************************************************************/


#include "apreq.h"
#include "apreq_module.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_memcache.h"
#include "ap_provider.h"

#include "ap_socache.h"

#define APACHE_LIBNAME     "ap"
#define POST_BUFFER_SIZE   (64 * 1024)

typedef struct ml_slotmem_t{
    ap_slotmem_provider_t   *_provider;
    ap_slotmem_instance_t   *_instance;
    apr_size_t              _size;
    unsigned int            _num;
    ap_slotmem_type_t       _type;
}ml_slotmem;

typedef struct ml_socache_t{
    ap_socache_provider_t* _provider;
    ap_socache_instance_t* _instance;
    server_rec			 * _server;
    apr_pool_t			 * _pool;
    apr_time_t			 _timeout;

    int	_maxdatalen;
}ml_socache;

typedef struct {
    ap_dbd_t *dbd;
    server_rec *s;
}ml_dbd;

apreq_handle_t* ml_r2apreq(lua_State*L,int n);

#define CHECK_REQUEST_OBJECT(x)  ml_check_object(L, x,"Apache2.Request")
#define CHECK_CONNECTION_OBJECT(x)  ml_check_object(L, x,"Apache2.Connection")
#define CHECK_SERVER_OBJECT(x)  ml_check_object(L, x,"Apache2.Server")
#define CHECK_APRTABLE_OBJECT(x)  ap_lua_check_apr_table(L, x)

#define CHECK_SESSION_OBJECT(x) ml_check_object(L, x, "mod_luaex.session")
#define CHECK_SOCACHE_OBJECT(x) ((ml_socache*)luaL_checkudata(L, x, "mod_luaex.socache"))
#define CHECK_SLOTMEM_OBJECT(x) ((ml_slotmem*)luaL_checkudata(L, x, "mod_luaex.slotmem"))
#define CHECK_DBD_OBJECT(x) ((ml_dbd*)luaL_checkudata(L,x,"mod_luaex.dbd"))

#define CHECK_BUCKETBRIGADE_OBJECT(x)  ((apr_bucket_brigade *) ml_check_object(L, x,"mod_luaex.bucketbrigade"))
#define CHECK_BUCKET_OBJECT(x)  ((apr_bucket *) ml_check_object(L, x,"mod_luaex.bucket"))

#define PUSH_BUCKETBRIGADE_OBJECT(x) ml_push_object(L, x, "mod_luaex.bucketbrigade")
#define PUSH_BUCKET_OBJECT(x) ml_push_object(L, x, "mod_luaex.bucket")

#define CHECK_APREQ_OBJECT(x)  ml_r2apreq(L, x)
#define CHECK_COOKIE_OBJECT(x) ((apreq_cookie_t*) ml_check_object(L, x,"mod_luaex.cookie"))
#define CHECK_PARAM_OBJECT(x)  ((apreq_param_t *) ml_check_object(L, x,"mod_luaex.param"))

#define PUSH_COOKIE_OBJECT(x)   ml_push_object(L, x, "mod_luaex.cookie")
#define PUSH_PARAM_OBJECT(x)    ml_push_object(L, x, "mod_luaex.param")

AP_LUA_DECLARE(apr_table_t*) ap_lua_check_apr_table(lua_State *L, int index);
AP_LUA_DECLARE(void) ap_lua_push_apr_table(lua_State *L, apr_table_t *t);

int ml_ext_apr_table(lua_State*L);
int ml_luaopen_apreq(lua_State *L,apr_pool_t *p);
int ml_luaopen_buckets(lua_State *L);
int ml_luaopen_extends(lua_State*L);

apr_status_t ml_retrieve_option_functions (apr_pool_t *p);
int ml_push_status(lua_State*L, apr_status_t status);
int ml_isudata (lua_State *L, int ud, const char *tname);

int ml_socache_lookup(lua_State*L);

int ml_slotmem_lookup(lua_State*L);
int ml_slotmem_create(lua_State*L);
int ml_slotmem_attach(lua_State*L);

apr_status_t ml_session_extends (apr_pool_t *p);
int ml_session_load(lua_State* L);
int ml_session_save(lua_State* L);
int ml_session_get(lua_State* L);
int ml_session_set(lua_State* L);

int ml_ssl_is_https (lua_State *L);
int ml_ssl_var_lookup(lua_State* L);

int ml_list_provider(lua_State*L);

int ml_dbd_acquire(lua_State *L);
int ml_dbdriver_prepare(lua_State *L) ;

#ifdef ML_HAVE_RESLIST
int ml_reslist_acquire(lua_State*L);
int ml_reslist_release(lua_State*L);
int ml_reslist_invalidate(lua_State*L);
#endif

#endif

