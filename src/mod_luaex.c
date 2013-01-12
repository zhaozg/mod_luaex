#include "mod_luaex.h"

#include "mod_dbd.h"
#include <mod_so.h>
#include <lua_apr.h>

#include "private.h"


#if AP_SERVER_MAJORVERSION_NUMBER!=2
#error Sorry, Only support Apache2
#endif


void pstack_dump(lua_State *L,const char *msg)
{
	int i;
	int top = lua_gettop(L);

	printf("Lua Stack Dump: [%s]\n", msg);

	for (i = 1; i <= top; i++) {
		int t = lua_type(L, i);
		switch (t) {
	case LUA_TSTRING:{
		printf("%d:  '%s'\n", i, lua_tostring(L, i));
		break;
			 }
	case LUA_TUSERDATA:{
		printf("%d:  userdata\n", i);
		break;
			   }
	case LUA_TLIGHTUSERDATA:{
		printf("%d:  lightuserdata\n",
			i);
		break;
				}
	case LUA_TNIL:{
		printf("%d:  NIL\n", i);
		break;
		      }
	case LUA_TNONE:{
		printf("%d:  None\n", i);
		break;
		       }
	case LUA_TBOOLEAN:{
		printf("%d:  %s\n", i, lua_toboolean(L,
			i) ? "true" :
			"false");
		break;
			  }
	case LUA_TNUMBER:{
		printf("%d:  %g\n", i, lua_tonumber(L, i));
		break;
			 }
	case LUA_TTABLE:{
		printf("%d:  <table>\n", i);
		break;
			}
	case LUA_TTHREAD:{
		printf("%d:  <thread>\n", i);
		break;
			 }
	case LUA_TFUNCTION:{
		printf("%d:  <function>\n", i);
		break;
			   }
	default:{
		printf("%d:  unknown: [%s]\n", i, lua_typename(L, i));
		break;
		}
		}
	}
}
/************************************************************************/
/*                                                                      */
/************************************************************************/

void *ml_check_object(lua_State *L, int index, const char*metaname) {
    luaL_checkudata(L, index, metaname);
    return lua_unboxpointer(L, index);
}

int  ml_push_object(lua_State*L,const void* data, const char*metaname) {
    lua_boxpointer(L, data);
    luaL_getmetatable(L,metaname);
    lua_setmetatable(L, -2);
    return 1;
}


int ml_push_status(lua_State*L, apr_status_t status) {
    char err[APR_PATH_MAX];
    if(status==APR_SUCCESS) {
        lua_pushboolean(L,1);
        return 1;
    }
    lua_pushnil(L);
    lua_pushinteger(L, status);
    apr_strerror(status,err, APR_PATH_MAX);
    lua_pushstring(L, err);
    return 3;
}

int ml_isudata (lua_State *L, int ud, const char *tname) {
    void *p = lua_touserdata(L, ud);
    if (p != NULL) {  /* value is a userdata? */
        if (lua_getmetatable(L, ud)) {  /* does it have a metatable? */
            lua_getfield(L, LUA_REGISTRYINDEX, tname);  /* get correct metatable */
            if (lua_rawequal(L, -1, -2)) {  /* does it have the correct mt? */
                lua_pop(L, 2);  /* remove both metatables */
                return 1;
            }
        }
    }
    return 0;  /* to avoid warnings */
}

/**************************************************/



//call lua function
/************************************************************************/
/* 我们使用C的vararg来封装对Lua函数的调用。我们的封装后的函数（call_lua_va）*/
/* 接受被调用的函数明作为第一个参数，第二参数是一个描述参数和结果类型的 */
/* 字符串，最后是一个保存返回结果的变量指针的列表                       */
/************************************************************************/
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
    while (*sig) {    /* push arguments */
        switch (*sig++) {
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
             lua_pushlstring(L,bs,va_arg(vl, int));
         }
         break;
     case 'b':
         lua_pushboolean(L,va_arg(vl,int));
         break;
     case 'p':
         lua_pushlightuserdata(L,va_arg(vl,void*));
         break;
     case 'f':
         lua_pushcfunction(L, (lua_CFunction)va_arg(vl,void*));
         break;
     case 'r':
         ml_push_object(L, va_arg(vl,void*), "Apache2.Request");
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
    } endwhile:

    /* do the call */
    nres = strlen(sig);  /* number of expected results */
    status = lua_pcall(L, narg, nres, 0);
    if (status == 0) 
    {
        /* retrieve results */
        nres = -nres;     /* stack index of first result */
        while (*sig) {    /* get results */
            switch (*sig++) {
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
                    *va_arg(vl, const char **) = luaL_checklstring(L,nres,&size);
                    *va_arg(vl, int *) = size;
                    break;
                case 'b':  /* boolean result */
                    *va_arg(vl, int *) = (int)lua_toboolean(L, nres);
                    break;
                case 'p':
                    if (!lua_islightuserdata(L,nres) && !lua_isnil(L, nres))
                        luaL_error(L, "wrong result type, expect for pointer");
                    *va_arg(vl, void **) = (void*)lua_topointer(L, nres);
                    break;
                default:
                    luaL_error(L, "invalid option (%c)", *(sig - 1));
            }
            nres++;
        }
    } else {
        /* do the call */
        printf("***mod_luaex: %s Error %s\n",func,lua_tostring(L, -1));
        luaL_dostring(L,"debug.traceback(2)");
        /* luaL_error(L, "error running function `%s': %s", func, lua_tostring(L, -1)); */
    }

    return status;
}
int ml_call(lua_State *L, const char *func, const char *sig, ...) {
    int status;
    va_list vl;
    va_start(vl, sig);
    status = ml_call_varg(L, func, sig, vl);
    va_end(vl);
    return status;
}
/************************************************************************/
/* ml_handler                                                          */
/************************************************************************/

static int ml_load_chunk(lua_State *L, const char* script, const char* title)
{
    int status = 0;
    lua_getfield(L,LUA_REGISTRYINDEX,script);

    status = luaL_loadfile(L, script);
    if((!lua_isfunction(L,-1)&&!lua_iscfunction(L,-1))||lua_pcall(L,0,0,0))
    {
        printf("***mod_luaex: %s Error %s\n",script,lua_tostring(L, -1));
        luaL_dostring(L,"debug.traceback(1)");
        status = LUA_ERRERR;
    }
    return status;
}

int call_lua_output_handle(lua_State *L, 
                           const char* script,
                           ap_filter_t *f, 
                           apr_bucket_brigade *bb,
                           apr_bucket* eos)
{
	int status = 0;
	request_rec *r = f->r;
	const char* data = 0;
	int len = 0;
	apr_bucket *b;

	if(eos) {
		if ((status = apr_brigade_pflatten(bb, (char **)&data, &len, r->pool)) == APR_SUCCESS && len>=0) { 
			status = ml_load_chunk(L,script,f->frec->name);
            if (status==0)
            {
				apr_brigade_cleanup(bb);

				status = ml_call(L, f->frec->name, "rS>S", r, data, len, (char **)&data, &len);
				b = apr_bucket_transient_create(data, len,apr_bucket_alloc_create(f->c->pool));
				APR_BRIGADE_INSERT_TAIL(bb, b);
				APR_BRIGADE_INSERT_TAIL(bb, eos);
            }            
		}
	}
    ap_remove_output_filter(f);
	return status;
}


// ======================================
/*
*  the table of configuration directives we provide
*/
typedef struct
{
	apr_bucket_brigade *tmpBucket;
	lua_State *L;
} lua_filter_ctx;

AP_LUA_DECLARE(int) ap_lua_init(lua_State *L, apr_pool_t * p);
AP_LUA_DECLARE(void) ap_lua_load_config_lmodule(lua_State *L);

static void lua_open_callback(lua_State *L, apr_pool_t *p, void *ctx)
{
	ap_lua_init(L, p);
	ap_lua_load_apache2_lmodule(L);
	ap_lua_load_request_lmodule(L, p);
	ap_lua_load_config_lmodule(L);
}

apr_status_t lua_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	request_rec *r = f->r;
	conn_rec *c = f->c;
	lua_filter_ctx *ctx = NULL; 
	lua_State   *L = NULL;
	apr_status_t rv;
	struct dir_config *d = ap_get_module_config(r->per_dir_config, &luaex_module);
	const char* script = apr_table_get(d->filter,f->frec->name);
	char *data;
	apr_size_t len;

	int i=1;

	if(!f->ctx)
	{
		if(script==NULL)
		{
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		if(apr_table_get(d->filter,f->frec->name)==NULL || apr_pool_userdata_get((void**)&L,ML_OUTPUT_FILTER_KEY4LUA, r->pool) || L==NULL)
		{
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		f->ctx = apr_palloc(r->pool, sizeof(lua_filter_ctx));
		ctx = f->ctx;
		ctx->L = lua_newthread(L);
		ctx->tmpBucket = apr_brigade_create(r->pool, c->bucket_alloc);
		L = ctx->L;
		r->chunked = 1;
		/*
		if (apr_table_get(r->headers_out, "Content-Length"))
		{
			apr_table_unset(r->headers_out, "Content-Length");
			if(!ap_find_last_token(r->pool,
				apr_table_get(r->headers_out,
				"Transfer-Encoding"),
				"chunked"))
				apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");

			r->proto_num = HTTP_VERSION(1,1);
			r->chunked = 1;
        }*/

		rv = ml_load_chunk(L,script,f->frec->name);
		lua_settop(L,0);
		if (rv==0)
		{
			lua_getglobal(L, f->frec->name);
			if(!lua_isfunction(L,-1))
			{
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02329)
					"lua: Unable to find function %s in %s",
					f->frec->name,
					script);
				return APR_EGENERAL;
			}

			ap_lua_run_lua_request(L, r);
			printf("A%d TOP=%d\n",i,lua_gettop(L)); i++;

			rv = lua_resume(L, 1);
			if(rv==0)
			{
				ap_remove_output_filter(f);
				return ap_pass_brigade(f->next, bb);
			}

			if (rv != LUA_YIELD) {
				if(rv==LUA_ERRRUN)
					printf(lua_tostring(L,-1));
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		} else{
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02329)
				"lua: Unable to load %s",
				script);
			printf("%s\n",lua_tostring(L,-1));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	ctx = f->ctx;
	L = ctx->L;

	rv = apr_brigade_pflatten(bb,&data,&len,r->pool);
	if(rv==0){
		/* Push the bucket onto the Lua stack as a global var */
		lua_getglobal(L, f->frec->name);
		lua_pushlstring(L, data, len);
		/* If Lua yielded, it means we have something to pass on */
		printf("A%d TOP=%d\n",i,lua_gettop(L)); i++;
		rv = lua_resume(L, 1);

		if (rv == LUA_YIELD) {
			size_t olen;
			const char* output = lua_tolstring(L, 1, &olen);
			lua_pop(L,1);

			if(olen>0){
				apr_bucket *pbktOut = apr_bucket_heap_create(output, olen, NULL, c->bucket_alloc);
				APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktOut);
				rv = ap_pass_brigade(f->next, ctx->tmpBucket);
				apr_brigade_cleanup(ctx->tmpBucket);
				if (rv != APR_SUCCESS) {
					return rv;
				}
			}
		}
		else {
			ap_remove_output_filter(f);
			apr_brigade_cleanup(bb);
			apr_brigade_cleanup(ctx->tmpBucket);
			if(rv==LUA_ERRRUN)
				printf("%s\n%s",r->uri,lua_tostring(L,-1));
			return HTTP_INTERNAL_SERVER_ERROR;
		}


        /* If we've safely reached the end, do a final call to Lua to allow for any 
        finishing moves by the script, such as appending a tail. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
			lua_getglobal(L, f->frec->name);
			lua_pushnil(L);

			printf("A%d TOP=%d LAST\n",i,lua_gettop(L)); i++;
			fflush(stdout);

			if (lua_resume(L, 1) == LUA_YIELD) {
				apr_bucket *pbktOut;
				size_t olen;
				const char* output = lua_tolstring(L, 1, &olen);
				if(olen>0){
					pbktOut = apr_bucket_heap_create(output, olen, NULL, c->bucket_alloc);
					APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktOut);
				}
			}
			APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, apr_bucket_eos_create(c->bucket_alloc));
			apr_brigade_cleanup(bb);
			rv = ap_pass_brigade(f->next, ctx->tmpBucket);
			apr_brigade_cleanup(ctx->tmpBucket);
			return rv;
        }
	}


/*
#if AP_SERVER_MAJORVERSION_NUMBER==2 && AP_SERVER_MINORVERSION_NUMBER==0
    APR_BRIGADE_FOREACH(b, bb) {
#elif AP_SERVER_MAJORVERSION_NUMBER==2
	for (b = APR_BRIGADE_FIRST(bb);
		b != APR_BRIGADE_SENTINEL(bb);
		b = APR_BUCKET_NEXT(b))
	{
#else
#error "Only Support Apache 2.0x or 2.xx
#endif
	}
*/

    return APR_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////

APREQ_DECLARE(apreq_handle_t *) apreq_handle_apache2(request_rec *r);
apreq_handle_t* ml_r2apreq(lua_State*L,int n){
    apr_status_t s;
    request_rec *r = CHECK_REQUEST_OBJECT(n);
    apreq_handle_t* h=NULL;
    s = apr_pool_userdata_get((void**)&h,"apreq_handle_t*",r->pool);
    if(s==OK){
	    if(h==NULL)
	    {
		    h  = apreq_handle_apache2(r);
		    apr_pool_userdata_set(h,
			    "apreq_handle_t*",
			    apr_pool_cleanup_null,
			    r->pool);
	    }
    }
    return h;
};

apr_pool_t *lua_apr_pool_register(lua_State *L, apr_pool_t *new_pool);
static apr_status_t ml_pool_register(lua_State *L, apr_pool_t*pool ) {
    lua_apr_pool_register(L,pool);
    return OK;
}

static apr_status_t ml_lua_request(lua_State *L, request_rec *r) {
    return ml_pool_register(L, r->pool);
};


#ifdef LUA_APR_DECLARE_STATIC
int luaopen_apr_core(lua_State *L);
#endif

static apr_status_t ml_lua_open(lua_State *L, apr_pool_t *p)
{
	ml_pool_register(L, p);
	ml_apache2_extends(L);

#ifdef LUA_APR_DECLARE_STATIC
	luaopen_apr_core(L);
	lua_setglobal(L,"apr.core");
#endif
	ml_luaopen_buckets(L);
	ml_luaopen_apreq(L,p);
	ml_luaopen_extends(L) ;
	ml_ext_apr_table(L);
	ml_ext_request_lmodule(L, p);
	return OK;
};

apr_status_t ml_register_hooks (apr_pool_t *p){
	ap_find_module = APR_RETRIEVE_OPTIONAL_FN(ap_find_loaded_module_symbol);
	ml_retrieve_option_functions (p);
	APR_OPTIONAL_HOOK(ap_lua, lua_request,  ml_lua_request, NULL,NULL,APR_HOOK_MIDDLE);
	APR_OPTIONAL_HOOK(ap_lua, lua_open,     ml_lua_open,    NULL,NULL,APR_HOOK_MIDDLE);
	return 0;
}
