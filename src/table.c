#include "mod_luaex.h"
#include <lua_apr.h>

/************************************************************************/
/* table object                                                         */
/************************************************************************/

static int table_len(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    const apr_array_header_t* arr = apr_table_elts(t);
    lua_pushinteger(L, arr->nelts);
    return 1;
}

static int table_clear(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    apr_table_clear((apr_table_t *)t);
    return 0;
}

static int table_get(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    const char* key = luaL_checkstring(L,2);
    const char* val = apr_table_get(t,key);

    if(val)
        lua_pushstring(L,val);
    else
        lua_pushnil(L);
    return 1;
}

static int table_set(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    const char* key = luaL_checkstring(L,2);
    if (lua_isnil(L,3)) 
    {
        apr_table_unset((apr_table_t *)t, key);
    }else
    {
        const char* val = luaL_checkstring(L,3);
        apr_table_set((apr_table_t *)t, key, val);
    }
    return 0;
}

static int table_overlay(lua_State*L)
{
    const apr_table_t *t1 = CHECK_APRTABLE_OBJECT(1);
    const apr_table_t *t2 = CHECK_APRTABLE_OBJECT(2);

    apr_table_t *t = apr_table_copy(apr_table_elts(t1)->pool,t1);

    t = apr_table_overlay(apr_table_elts(t)->pool, t, t2);
    ap_lua_push_apr_table(L,t);
    return 1;
}

static int table_compress(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    unsigned flags = luaL_checkint(L,2);
    apr_table_compress((apr_table_t*)t,flags);

    return 0;
}

static int table_overlap(lua_State*L)
{
    const apr_table_t *t1 = CHECK_APRTABLE_OBJECT(1);
    const apr_table_t *t2 = CHECK_APRTABLE_OBJECT(2);
    unsigned flags = luaL_checkint(L,3);

    apr_table_overlap((apr_table_t*)t1,t2,flags);

    return 0;
}

static int table_next(lua_State*L)
{
    const apr_array_header_t* a = (const apr_array_header_t*)lua_topointer(L,lua_upvalueindex(1));
    const apr_table_entry_t *elts = (const apr_table_entry_t *) a->elts;
    int i = lua_tointeger(L,lua_upvalueindex(2));
    if (i<a->nelts)
    {
        lua_pushstring(L,elts[i].key);
        lua_pushstring(L,elts[i].val);

        lua_pushinteger(L,i+1);
        lua_replace(L,lua_upvalueindex(2));
        return 2;
    }
    return 0;
}

static int table_iter(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    const apr_array_header_t* arr = apr_table_elts(t);

    lua_pushlightuserdata(L,(void*)arr);
    lua_pushinteger(L,0);
    lua_pushcclosure(L,table_next,2);
    return 1;
}
static int table_tostring(lua_State*L)
{
    const apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
    lua_pushfstring(L,"apr_table(%p)",t);
    return 1;
}

static luaL_reg table_mlibs[] = {
    {"__tostring",		table_tostring},
/*
    {"__index",         table_get},
    {"__newindex",      table_set},
*/
    {"__concat",		table_overlay},
    {"__len",			table_len},
    {"__unm",			table_compress},
    {"__pairs",			table_iter},

    {NULL,          NULL}
};



int ml_ext_apr_table(lua_State*L) {
    luaL_getmetatable(L, "Apr.Table");
    if (lua_istable(L,-1)) {
        luaL_reg *reg = table_mlibs;
        while(reg->name) {
            lua_pushstring(L,reg->name);
            lua_pushcfunction(L,reg->func);
            lua_rawset(L,-3);
            reg = reg + 1;
        }
    }
    lua_pop(L,1);
    return 0;
};
