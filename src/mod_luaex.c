#include "mod_luaex.h"

#include "mod_dbd.h"
#include <mod_so.h>
#include <lua_apr.h>

#include "private.h"

#ifdef WIN32
#include <process.h>
#endif

#if AP_SERVER_MAJORVERSION_NUMBER!=2
#error Sorry, Only support Apache2
#endif

static APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *ap_find_module = NULL;

/************************************************************************/
/*                                                                      */
/************************************************************************/

static const ml_constants status_tabs[] = {
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

    {"JOIN_AS_IS",	APREQ_JOIN_AS_IS},      /**< Join the strings without modification */
    {"JOIN_ENCODE", APREQ_JOIN_ENCODE},     /**< Url-encode the strings before joining them */
    {"JONE_DECODE", APREQ_JOIN_DECODE},     /**< Url-decode the strings before joining them */
    {"JONE_QUOTE",  APREQ_JOIN_QUOTE},       /**< Quote the strings, backslashing existing quote marks. */

    {"MATCH_FULL",    APREQ_MATCH_FULL},       /**< Full match only. */
    {"MATCH_PARTIAL", APREQ_MATCH_PARTIAL},     /**< Partial matches are ok. */
    {"OVERLAP_TABLES_SET",    APR_OVERLAP_TABLES_SET},       /**< Full match only. */
    {"OVERLAP_TABLES_MERGE",  APR_OVERLAP_TABLES_MERGE},     /**< Partial matches are ok. */


    { NULL, 0 }
};

static 
void ml_define_constants (lua_State *L, const  ml_constants tab[]) {
    int i;
    for (i = 0; tab[i].name != NULL; i++) {
        lua_pushstring (L, tab[i].name);
        lua_pushnumber (L, tab[i].val);
        lua_settable (L, -3);
    }
}

void *ml_check_object(lua_State *L, int index, const char*metaname) {
    luaL_checkudata(L, index, metaname);
    return lua_unboxpointer(L, index);
}

int  ml_push_object(lua_State*L, void* data, const char*metaname) {
    lua_boxpointer(L, data);
    luaL_getmetatable(L,metaname);
    lua_setmetatable(L, -2);
    return 1;
}


int ml_push_status(lua_State*L, apr_status_t status) {
    char err[MAX_PATH];
    if(status==APR_SUCCESS) {
        lua_pushboolean(L,1);
        return 1;
    }
    lua_pushnil(L);
    lua_pushinteger(L, status);
    apr_strerror(status,err, MAX_PATH);
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

/************************************************************************/
/*                                                                      */
/************************************************************************/


//////////////////////////////////////////////////////////////////////////

static int req_header_only (request_rec *r) {
    return r->header_only;
}


static int req_get_remote_logname (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushstring (L, ap_get_remote_logname(r));
    return 1;
}

static int req_auth_name (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushstring (L, ap_auth_name(r));
    return 1;
}

static int req_get_basic_auth_pw(lua_State *L) {
    request_rec *req = CHECK_REQUEST_OBJECT(1);
    const char *pw;

    if (! ap_get_basic_auth_pw(req, &pw))
        lua_pushstring(L, pw);
    else 
        lua_pushnil(L);

    return 1;
}

/**
* Lookup the remote client's DNS name or IP address
* @param conn The current connection
* @param dir_config The directory config vector from the request
* @param type The type of lookup to perform.  One of:
* <pre>
*     REMOTE_HOST returns the hostname, or NULL if the hostname
*                 lookup fails.  It will force a DNS lookup according to the
*                 HostnameLookups setting.
*     REMOTE_NAME returns the hostname, or the dotted quad if the
*                 hostname lookup fails.  It will force a DNS lookup according
*                 to the HostnameLookups setting.
*     REMOTE_NOLOOKUP is like REMOTE_NAME except that a DNS lookup is
*                     never forced.
*     REMOTE_DOUBLE_REV will always force a DNS lookup, and also force
*                   a double reverse lookup, regardless of the HostnameLookups
*                   setting.  The result is the (double reverse checked) 
*                   hostname, or NULL if any of the lookups fail.
* </pre>
* @param str_is_ip unless NULL is passed, this will be set to non-zero on output when an IP address 
*        string is returned
* @return The remote hostname
* @deffunc const char *ap_get_remote_host(conn_rec *conn, void *dir_config, int type, int *str_is_ip)
*/

static int req_get_remote_host(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int type = (int)luaL_optnumber(L,2,REMOTE_NOLOOKUP);
    int str_is_ip;

    lua_pushstring (L, ap_get_remote_host (r->connection, r->per_dir_config, type , &str_is_ip));
    lua_pushnumber(L,str_is_ip);
    return 2;
}

static int req_meets_conditions(lua_State*L ) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    lua_pushnumber(L,ap_meets_conditions(r));
    return 1;
}

static int req_get_server_port (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushnumber (L, ap_get_server_port(r));
    return 1;
}
//////////////////////////////////////////////////////////////////////////
static int req_add_common_vars(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    ap_add_common_vars(r);
    return 0;
}


static int req_allow_methods(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int reset = luaL_checkint(L,2);
    const char* method = luaL_optstring(L,3,NULL);
    int nargs = lua_gettop(L);
    int i;

    ap_allow_methods(r, (reset == REPLACE_ALLOW), method, NULL);

    for(i=4; i<=nargs; i++)
    {
        ap_allow_methods(r, MERGE_ALLOW, luaL_checkstring(L, i), NULL);
    }

    return 0;
}


static int req_construct_url(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char* uri = luaL_checkstring(L,2);

    lua_pushstring(L,ap_construct_url(r->pool, uri,r));
    return 1;
}

static int req_internal_redirect(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char *new_uri = luaL_checkstring(L, 2);

    ap_internal_redirect(new_uri, r);
    return 0;
}


static int req_set_content_length(lua_State*L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int len = luaL_checkint(L,2);

    ap_set_content_length(r, len);

    return 0;
}

static int req_set_etag(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    ap_set_etag(r);

    return 0;
}

static int req_set_last_modified(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    ap_set_last_modified(r);

    return 0;
}

static int req_update_mtime(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int mtime = luaL_checkint(L,2);

    ap_update_mtime(r, apr_time_from_sec(mtime));

    return 0;
}

/************************************************************************/
/* Apache Handle Process and Output                                     */
/************************************************************************/

static int req_sendfile(lua_State* L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char *fname = luaL_checkstring(L,2);
    apr_size_t offset = luaL_optlong(L,3,0);
    apr_size_t len = luaL_optlong(L,4,-1);

    apr_file_t *fd;
    apr_size_t nbytes;
    apr_status_t status;
    apr_finfo_t finfo;

    status=apr_stat(&finfo, fname, APR_FINFO_SIZE, r->pool);
    if (status != APR_SUCCESS) {
        ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Could not stat file for reading %s", fname);
        lua_pushnil(L);
        lua_pushstring(L,"Could not stat file for reading");
        return 2;
    }

    status=apr_file_open(&fd, fname, APR_READ, APR_OS_DEFAULT, r->pool);
    if (status != APR_SUCCESS) {
        ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Could not open file for reading %s", fname);
        lua_pushnil(L);
        lua_pushstring(L,"Could not open file for reading");
        return 2;
    }                         

    if (len==-1) 
        len=(apr_size_t)finfo.size;

    status = ap_send_fd(fd, r, offset,  len, &nbytes);
    apr_file_close(fd);

    if (status != APR_SUCCESS) 
    {
        ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Write failed, client closed connection.");
        lua_pushnil(L);
        lua_pushstring(L,"Write failed, client closed connection.");
        return 2;
    }

    lua_pushnumber(L, nbytes);
    return 1;
}

static int pushresult (lua_State *L, int i, const char *filename) {
    if (i) {
        lua_pushboolean(L, 1);
        return 1;
    }
    else {
        int err = apr_get_os_error();
        char errbuf[MAX_STRING_LEN];

        lua_pushnil(L);
        lua_pushnumber(L, err);
        if (filename)
            lua_pushfstring(L, "%s: %s", filename, 	apr_strerror(err,errbuf,MAX_STRING_LEN));
        else
            lua_pushfstring(L, "%s", apr_strerror(err,errbuf,MAX_STRING_LEN));

        return 3;
    }
}

static int req_rflush (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    return pushresult(L, ap_rflush(r)>=0, NULL);
}

static int read_chars (lua_State *L, request_rec* r, size_t n) {
    size_t len;
    char tmpbuf[HUGE_STRING_LEN];

    len = HUGE_STRING_LEN;  /* try to read that much each time */

    if (len > n)  len = n; 

    if ( (len = ap_get_client_block(r, tmpbuf, len))> 0) {
        lua_pushlstring(L,tmpbuf,len);
        return 1;
    }else
        ap_discard_request_body(r);

    return 0;
}

typedef struct {
	apr_table_t *vars;
	apr_table_t *unsetenv;
} env_dir_config_rec;

static int req_add_cgi_vars (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	module* env_module = NULL;
	env_dir_config_rec *sconf = NULL; 
	
	if(ap_find_module) {
		env_module = ap_find_module(r->server,"env_module");
		sconf = ap_get_module_config(r->per_dir_config, env_module);
		if (sconf && sconf->vars && apr_table_elts(sconf->vars)->nelts) {
			r->subprocess_env = apr_table_overlay(r->pool, r->subprocess_env, sconf->vars);
		}
	}

	ap_add_common_vars(r);
	ap_add_cgi_vars(r);

	if(lua_isstring(L,2))
	{
		lua_pushstring(L, apr_table_get(r->subprocess_env, lua_tostring(L,2)));
	}else{
		ap_lua_push_apr_table(L, r->subprocess_env);
	}
	return 1;
}

static int req_read (lua_State *L) {
    int nargs = lua_gettop(L) ;
    int success;
    int n = 1;

    request_rec *r = CHECK_REQUEST_OBJECT(1);
#if 0
    if (r->remaining ==0 ) {
        lua_pushnil(L);  /* push nil instead */
        return 1;
    }
#endif
    if (nargs == 1) {  /* no arguments? FIXIT */
        return success = read_chars(L, r, (size_t)~0);
    }

    luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
    success = 1;

    for (n=2; n<=nargs && success; n++) {
        if (lua_type(L, n) == LUA_TNUMBER) {
            size_t l = (size_t)lua_tonumber(L, n);
            success = read_chars(L, r, l);
        } else  {
            const char *p = luaL_checkstring(L, n);
            luaL_argcheck(L, p && p[0] == '*' && p[1] == 'a', n, "invalid option");
            success = read_chars(L,r, (size_t)~0);  /* read MAX_SIZE_T chars */
        }
    }

    return n-2;
}

/*
** Binding to ap_setup_client_block.
** Uses the request_rec defined as an upvalue.
** Receives a Lua string: "REQUEST_NO_BODY", "REQUEST_CHUNKED_ERROR" or
**	"REQUEST_CHUNKED_DECHUNK".
** It returns the status code.
*/
/* FIXME */
static int req_setup_client_block (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    const char *s = luaL_checklstring (L, 2, 0);
    if (strcmp (s, "REQUEST_NO_BODY") == 0)
        lua_pushnumber (L, ap_setup_client_block (r, REQUEST_NO_BODY));
    else if (strcmp (s, "REQUEST_CHUNKED_ERROR") == 0)
        lua_pushnumber (L, ap_setup_client_block (r, REQUEST_CHUNKED_ERROR));
    else if (strcmp (s, "REQUEST_CHUNKED_DECHUNK") == 0)
        lua_pushnumber (L, ap_setup_client_block (r, REQUEST_CHUNKED_DECHUNK));
    else
        lua_pushnil (L);
    return 1;
}

/*
* Binding to ap_should_client_block.
* Uses the request_rec defined as an upvalue.
* Returns the status code.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Esta funcao nao deve ser chamada mais de uma vez.
O que fazer para evitar isto?
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/
static int req_should_client_block (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushnumber (L, ap_should_client_block (r));
    return 1;
}

/*
** Binding to ap_get_client_block.
** Uses the request_rec defined as an upvalue.
** Receives a number of bytes to read.
** Returns a string or nil if EOS.
*/
static int req_get_client_block (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    char buffer[POST_BUFFER_SIZE+1];
    int bytesleft = luaL_optint (L, 2, POST_BUFFER_SIZE);
    int status, n;
    int count = 0;
    if (bytesleft < 0) {
        luaL_error (L, "block size must be positive");
        return 0;
    }
    while (bytesleft) {
        n = (bytesleft > POST_BUFFER_SIZE) ? POST_BUFFER_SIZE : bytesleft;
        status = ap_get_client_block (r, buffer, n);
        if (status == 0) { /* end-of-body */
            if (r->remaining > 0)
                continue; /* still has something to read */
            else
                break; /* end-of-stream */
        } else if (status == -1) { /* error or premature chunk end */
            lua_pushnil (L);
            lua_pushstring (L, "error getting client block");
            return 2;
        } else {
            bytesleft -= status;
            lua_pushlstring (L, buffer, status);
            count++;
        }
    }
    /* is this necessary? */
    if (count)
        lua_concat (L, count);
    else
        lua_pushnil (L);
    return 1;
}

/*
** Consulting remaining field of request_rec.
** Uses the request_rec defined as an upvalue.
** Return a Lua number.
*/
static int req_remaining (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushnumber (L, (lua_Number)r->remaining);
    return 1;
}

/*
** Binding to ap_discard_request_body.
** Uses the request_rec defined as an upvalue.
** Returns a status code.
*/
static int req_discard_request_body (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    lua_pushnumber (L, ap_discard_request_body (r));
    return 1;
}

static int req_add_output_filter(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char* filter = luaL_checkstring(L,2);

    ap_filter_t * f = ap_add_output_filter(filter,NULL,r,r->connection);
    lua_pushboolean(L,f!=NULL);
    return 1;
}

/**************************************************/
static req_fun_t *makefun(const void *fun, int type, apr_pool_t *pool)
{
	req_fun_t *rft = apr_palloc(pool, sizeof(req_fun_t));
	rft->fun = fun;
	rft->type = type;
	return rft;
}

static request_rec *ap_lua_check_request_rec(lua_State *L, int index)
{
	request_rec *r;
	luaL_checkudata(L, index, "Apache2.Request");
	r = (request_rec *) lua_unboxpointer(L, index);
	return r;
}

static int req_print (lua_State *L) {
    int i = 0;
    int status = 1;
    int n = lua_gettop(L);
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    size_t l;
    const char *s;

    for (i=2; i<=n && status; i++) {
        s = luaL_checklstring(L, i, &l);
        status =  (ap_rwrite(s, l, r)==(int)l) ? 1 : 0;
    }
    return pushresult(L, status, r->filename);
}

static int req_server(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    ap_lua_push_server(L, r->server);
    return 1;
}

static int req_connection(lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    ap_lua_push_connection(L, r->connection);
    return 1;
}


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
				b = apr_bucket_transient_create(data, len,apr_bucket_alloc_create(r->pool));
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

apr_status_t lua_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	request_rec *r = f->r;
	conn_rec *c = f->c;
	apr_bucket_brigade *bbb = f->ctx;
	apr_bucket *b, *eos_bucket=NULL ;
    lua_State   *L = NULL;
	apr_status_t rv;


    struct dir_config *d = ap_get_module_config(r->per_dir_config, &luaex_module);

	if(apr_table_get(d->filter,f->frec->name)==NULL || apr_pool_userdata_get(&L,LUA_APR_POOL_KEY, r->pool) || L==NULL)
	{
		ap_remove_output_filter(f);
		return ap_pass_brigade(f->next, bb);
	}

	if(!bbb)
	{
		f->ctx = apr_brigade_create(c->pool, c->bucket_alloc);
		bbb = f->ctx;
	}

	
    /* Interate through the available data. Stop if there is an EOS */
#if AP_SERVER_MAJORVERSION_NUMBER==2 && AP_SERVER_MINORVERSION_NUMBER==0
    APR_BRIGADE_FOREACH(b, bb) {
#elif AP_SERVER_MAJORVERSION_NUMBER==2 
	for (b = APR_BRIGADE_FIRST(bb);
		b != APR_BRIGADE_SENTINEL(bb);
		b = APR_BUCKET_NEXT(b))
	{
#else
#error "Only Support Apache 2.0x or 2.2x
#endif
		if (APR_BUCKET_IS_EOS(b)) {
			APR_BUCKET_REMOVE(b);
			eos_bucket = b;
			break;
		}
	}
		
	ap_save_brigade(f, &bbb, &bb, r->pool);
	if (!eos_bucket) {
		return APR_SUCCESS;
	}

	if((rv=call_lua_output_handle(L,apr_table_get(d->filter,f->frec->name),f,bbb,eos_bucket))==0)
	{
		rv = ap_pass_brigade(f->next, bbb);
		if (rv == APR_SUCCESS
			|| r->status != HTTP_OK
			|| c->aborted) 
		{
			return r->status;
		}else
		{
			/* no way to know what type of error occurred */
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
				"lua_output_filter: ap_pass_brigade returned %i",
				rv);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}else
	{
        rv = ap_pass_brigade(f->next, bbb);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
			"lua_output_filter: call_lua_output_handle returned %i",
			rv);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

    return APR_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////

APREQ_DECLARE(apreq_handle_t *) apreq_handle_apache2(request_rec *r);
int req_apreq(lua_State*L){
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    apreq_handle_t* h  = apreq_handle_apache2(r);
    return ml_push_object(L, h, "mod_luaex.apreq");
};

apr_pool_t *lua_apr_pool_register(lua_State *L, apr_pool_t *new_pool);
static apr_status_t ml_pool_register(lua_State *L, apr_pool_t*pool ) {
    lua_apr_pool_register(L,pool);
    return OK;
}

static apr_status_t ml_lua_request(lua_State *L, request_rec *r) {
    return ml_pool_register(L, r->pool);
};


static int req_args(lua_State *L)
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	if(lua_gettop(L)==2)
		r->args = apr_pstrdup(r->pool,luaL_checkstring(L,2));
	lua_pushstring (L, r->args);
	return 1;
}

static int req_parsebody(lua_State *L)
{
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    apreq_handle_t* req = apreq_handle_apache2(r);
    apr_status_t s = ap_discard_request_body(r);

    if(s==APR_SUCCESS)
    {
        apr_table_t *body;
        s = apreq_body(req, &body);
        if(s==APR_SUCCESS)
        {
            ap_lua_push_apr_table(L,body);
        }
    }
    if(s)
    {
        char msg[APR_PATH_MAX];
        lua_pushnil(L);
        lua_pushstring(L,apreq_strerror(s,msg,APR_PATH_MAX));
        return 2;
    }
    return 1;
}

void ml_ext_request_lmodule(lua_State *L, apr_pool_t *p) {
	apr_hash_t *dispatch;
	lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
	dispatch = lua_touserdata(L, -1);
	lua_pop(L, 1);
	assert(dispatch);

	/* add field */
	apr_hash_set(dispatch, "header_only", APR_HASH_KEY_STRING, makefun(&req_header_only, APL_REQ_FUNTYPE_BOOLEAN, p));

	apr_hash_set(dispatch, "args", APR_HASH_KEY_STRING, makefun(&req_args, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "parsebody", APR_HASH_KEY_STRING, makefun(&req_parsebody, APL_REQ_FUNTYPE_LUACFUN, p));

	/* add function */
	apr_hash_set(dispatch, "print", APR_HASH_KEY_STRING, makefun(&req_print, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "add_cgi_vars", APR_HASH_KEY_STRING, makefun(&req_add_cgi_vars, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "get_remote_host", APR_HASH_KEY_STRING, makefun(&req_get_remote_host, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_remote_logname", APR_HASH_KEY_STRING, makefun(&req_get_remote_logname, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "server", APR_HASH_KEY_STRING, makefun(&req_server, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "connection", APR_HASH_KEY_STRING, makefun(&req_connection, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "apreq", APR_HASH_KEY_STRING, makefun(&req_apreq, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "read", APR_HASH_KEY_STRING, makefun(&req_read, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "rflush", APR_HASH_KEY_STRING, makefun(&req_rflush, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "remaining", APR_HASH_KEY_STRING, makefun(&req_remaining, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_client_block", APR_HASH_KEY_STRING, makefun(&req_get_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "setup_client_block", APR_HASH_KEY_STRING, makefun(&req_setup_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "should_client_block", APR_HASH_KEY_STRING, makefun(&req_should_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "discard_request_body", APR_HASH_KEY_STRING, makefun(&req_discard_request_body, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "add_output_filter", APR_HASH_KEY_STRING, makefun(&req_add_output_filter, APL_REQ_FUNTYPE_LUACFUN, p));

	/* extends apache modules API */
	apr_hash_set(dispatch, "list_provider", APR_HASH_KEY_STRING, makefun(&ml_list_provider, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "socache_lookup", APR_HASH_KEY_STRING, makefun(&ml_socache_lookup, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_get", APR_HASH_KEY_STRING, makefun(&ml_session_get, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_set", APR_HASH_KEY_STRING, makefun(&ml_session_set, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_load", APR_HASH_KEY_STRING, makefun(&ml_session_load, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_save", APR_HASH_KEY_STRING, makefun(&ml_session_save, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_create", APR_HASH_KEY_STRING, makefun(&ml_slotmem_create, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_attach", APR_HASH_KEY_STRING, makefun(&ml_slotmem_attach, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_lookup", APR_HASH_KEY_STRING, makefun(&ml_slotmem_lookup, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "ssl_var_lookup", APR_HASH_KEY_STRING, makefun(&ml_ssl_var_lookup, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "ssl_is_https", APR_HASH_KEY_STRING, makefun(&ml_ssl_is_https, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "dbd_acquire", APR_HASH_KEY_STRING, makefun(&ml_dbd_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "dbd_prepare", APR_HASH_KEY_STRING, makefun(&ml_dbdriver_prepare, APL_REQ_FUNTYPE_LUACFUN, p));

#ifdef ML_HAVE_RESLIST
	apr_hash_set(dispatch, "reslist_acquire", APR_HASH_KEY_STRING, makefun(&ml_reslist_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_release", APR_HASH_KEY_STRING, makefun(&ml_reslist_release, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_invalidate", APR_HASH_KEY_STRING, makefun(&ml_reslist_invalidate, APL_REQ_FUNTYPE_LUACFUN, p));
#endif

}

static int ml_table_remove(lua_State*L)
{
	apr_table_t *t = CHECK_APRTABLE_OBJECT(1);
	const char* key = luaL_checkstring(L,2);
	apr_table_unset(t, key);
	return 0;
}
#ifdef LUA_APR_DECLARE_STATIC
int luaopen_apr_core(lua_State *L);
#endif

static apr_status_t ml_lua_open(lua_State *L, apr_pool_t *p)
{
	ml_pool_register(L, p);

	lua_getglobal(L, "apache2");

#if !defined(getpid)
#if defined(_getpid)
#define getpid _getpid
#endif
#endif
	lua_pushnumber (L, (lua_Number)getpid ());
	lua_setfield(L, -2, "pid");

	lua_pushcfunction(L, ml_table_remove);
	lua_setfield(L, -2, "remove");

    ml_define_constants (L, status_tabs);
	lua_pop(L,1);

#ifdef LUA_APR_DECLARE_STATIC
    luaopen_apr_core(L);
    lua_setglobal(L,"apr.core");
#endif
    ml_luaopen_buckets(L);
    ml_luaopen_apreq(L);
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
