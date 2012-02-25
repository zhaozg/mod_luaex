#include <apr_reslist.h>
#include <lua.h>
#include <httpd.h>
#include "mod_luaex.h"
#include "private.h"

#ifdef ML_HAVE_RESLIST

typedef struct {
	const char* name;
	lua_State* L;
	int constructor_ref;
	int destructor_ref;
}reslist_cb_t;

int ml_call(lua_State *L, const char *func, const char *sig, ...);
static apr_status_t ml_apr_reslist_constructor(void **resource, void *params,
												apr_pool_t *pool)
{
	reslist_cb_t*cb = params;
	lua_State*L = cb->L;
	int err;
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->constructor_ref);
	err = lua_pcall(L, 0, 1, 0);
	if (err==LUA_ERRRUN)
		luaL_error(L, "a runtime error. %s", lua_tostring(L,-1));
	if (err==LUA_ERRMEM)
		luaL_error(L, "memory allocation error. %s", lua_tostring(L,-1));
	if (err==LUA_ERRERR)
		luaL_error(L, "error while running the error handler function. %s", lua_tostring(L,-1));
	if (err)
		luaL_error(L, "unknown error(%d:%s) for load: %s. ", err, lua_tostring(L,-1),cb->name);

	luaL_checkudata(L,-1, cb->name);
	*resource = *(void**)lua_touserdata(L,-1);
	lua_pushnil(L);
	lua_setmetatable(L,-2);

	return APR_SUCCESS;
}

static apr_status_t ml_apr_reslist_destructor(void *resource, void *params,
											   apr_pool_t *pool)
{
	reslist_cb_t*cb = params;
	lua_State*L = cb->L;
	int err;
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->destructor_ref);
	*(void**)lua_newuserdata(L,sizeof(void*)) = resource;
	luaL_getmetatable(L,cb->name);
	lua_setmetatable(L,-2);
	err = lua_pcall(L, 1, 1, 0);
	if (err==LUA_ERRRUN)
		luaL_error(L, "a runtime error. %s", lua_tostring(L,-1));
	if (err==LUA_ERRMEM)
		luaL_error(L, "memory allocation error. %s", lua_tostring(L,-1));
	if (err==LUA_ERRERR)
		luaL_error(L, "error while running the error handler function. %s", lua_tostring(L,-1));
	if (err)
		luaL_error(L, "unknown error(%d:%s) for load: %s. ", err, lua_tostring(L,-1),cb->name);

	return APR_SUCCESS;
}

int ml_reslist_acquire(lua_State*L)
{
	request_rec* r = CHECK_REQUEST_OBJECT(1);
	size_t l;
	const char* o = luaL_checklstring(L, 2, &l);
	struct dir_config *d = ap_get_module_config(r->per_dir_config, &luaex_module);
	apr_reslist_t *reslist = apr_hash_get(d->resource, o, l);
	void *resource;

	apr_status_t status = apr_reslist_acquire(reslist, &resource);
	if(status || resource==NULL)
	{
		lua_pushnil(L);
		lua_pushnumber(L,status);
		return 2;
	}
	*(void**)lua_newuserdata(L,sizeof(void*)) = resource;
	luaL_getmetatable(L,o);
	if(lua_istable(L,-1))
	{
		 lua_getfield(L,-1,"__gc");
		 if(lua_isfunction(L,-1))
		 {
			 lua_pushnil(L);
			 lua_setfield(L,-3,"__gc");
		 }
		 lua_pop(L,1);
	}
	lua_setmetatable(L,-2);
	return 1;
}

int ml_reslist_release(lua_State*L)
{
	request_rec* r = CHECK_REQUEST_OBJECT(1);
	size_t l;
	const char* o = luaL_checklstring(L, 2, &l);
	void* resource = *(void**)lua_touserdata(L,3);

	struct dir_config *d = ap_get_module_config(r->per_dir_config, &luaex_module);
	apr_reslist_t *reslist = apr_hash_get(d->resource, o, l);

	apr_status_t status = apr_reslist_release(reslist,resource);
	lua_pushboolean(L, status==APR_SUCCESS);
	return 1;
}

int ml_reslist_invalidate(lua_State*L)
{
	request_rec* r = CHECK_REQUEST_OBJECT(1);
	size_t l;
	const char* o = luaL_checklstring(L, 2, &l);
	void* resource = lua_touserdata(L,3);
	struct dir_config *d = ap_get_module_config(r->per_dir_config, &luaex_module);
	apr_reslist_t *reslist = apr_hash_get(d->resource, o, l);

	apr_status_t status = apr_reslist_invalidate(reslist,resource);
	lua_pushboolean(L, status==APR_SUCCESS);
	return 1;
}

const char *luaex_cmd_Reslist(cmd_parms *cmd,
							  void *dcfg,
							  const char *resource,const char *script)
{
	struct dir_config *conf = dcfg;
	const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
	module* lua_module = ml_find_module(cmd->server,"lua_module");

	if (err != NULL)
		return err;

	if (conf->resource == NULL) {
		conf->resource = apr_hash_make(cmd->pool);
	}
	if (conf->L == NULL) {
		conf->L = luaL_newstate();
#ifdef AP_ENABLE_LUAJIT
		luaopen_jit(conf->L);
#endif
		luaL_openlibs(conf->L);
	}


	if (apr_hash_get(conf->resource,resource, strlen(resource))==NULL)
	{
		lua_State *L = conf->L;
		int err = luaL_loadfile(L, script);
		if (err==LUA_ERRFILE)
			return apr_psprintf(cmd->pool, "cannot open/read: %s. ", script);
		if (err==LUA_ERRSYNTAX)
			return apr_psprintf(cmd->pool, "syntax error during pre-compilation for: %s. ", script);
		if (err==LUA_ERRMEM)
			return apr_psprintf(cmd->pool, "memory allocation error for load: %s. ", script);
		if (err)
			return apr_psprintf(cmd->pool, "unknown error)(%d) for load: %s. ", err, script);

		err = lua_pcall(L, 0, LUA_MULTRET, 0);
		if (err==LUA_ERRRUN)
			return apr_psprintf(cmd->pool, "a runtime error. %s", lua_tostring(L,-1));
		if (err==LUA_ERRMEM)
			return apr_psprintf(cmd->pool, "memory allocation error. %s", lua_tostring(L,-1));
		if (err==LUA_ERRERR)
			return apr_psprintf(cmd->pool, "error while running the error handler function. %s", lua_tostring(L,-1));
		if (err)
			return apr_psprintf(cmd->pool, "unknown error(%d:%s) for load: %s. ", err, lua_tostring(L,-1), script);

		{
			int min, smax, hmax, ttl;
			apr_reslist_t* reslist;
			reslist_cb_t* cb =apr_palloc(cmd->pool, sizeof(reslist_cb_t));

			luaL_getmetatable(L,resource);
			if(lua_isnil(L,-1))
				return apr_psprintf(cmd->pool, "%s not support %s object(metatable)", script,resource);
			cb->name = resource;
			lua_pop(L,1);

			if(!lua_istable(L,-1))
				return apr_psprintf(cmd->pool, "%s not return a table which makes a reslist for %s", script,resource);

			cb->L = conf->L;
			lua_getfield(L,-1, "constructor");
			if (!lua_isfunction(L,-1))
				return apr_psprintf(cmd->pool, "%s not have a table field(constructor) function", script);
			cb->constructor_ref = luaL_ref(L, LUA_REGISTRYINDEX);

			lua_getfield(L,-1, "destructor");
			if (!lua_isfunction(L,-1))
				return apr_psprintf(cmd->pool, "%s not have a table field(destructor) function", script);
			cb->destructor_ref = luaL_ref(L, LUA_REGISTRYINDEX);

			lua_getfield(L,-1,"min");
			min = luaL_optint(L, -1, 0);
			lua_pop(L,1);

			lua_getfield(L,-1,"smax");
			smax = luaL_optint(L, -1, 16);
			lua_pop(L,1);		

			lua_getfield(L,-1,"hmax");
			hmax = luaL_optint(L, -1, 16);
			lua_pop(L,1);		

			lua_getfield(L,-1,"ttl");
			ttl = luaL_optint(L, -1, 0);
			lua_pop(L,1);

			if(apr_reslist_create(&reslist,min, smax, hmax,ttl, ml_apr_reslist_constructor, ml_apr_reslist_destructor, cb,cmd->pool)
				==APR_SUCCESS)
			{
				apr_hash_set(conf->resource,resource, strlen(resource), reslist);
			}else
				return "apr_reslist_create failed";
		}
	}

	if (conf->resource == NULL) 
		return "Out of memory";

	return NULL;
}

#endif
