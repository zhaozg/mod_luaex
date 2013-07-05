#include "mod_luaex.h"
#include "mod_lua.h"
APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *ap_find_module = NULL;

/************************************************************************/
/*                                                                      */
/************************************************************************/

static int req_header_only (request_rec *r) {
	return r->header_only;
}

static int lua_ap_escapehtml (lua_State *L) {
	const char *escaped;
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *plain = lua_tostring(L, 2);
	int toasc = luaL_optint(L, 3, 0);
	escaped = ap_escape_html2(r->pool, plain, toasc);
	lua_pushstring(L, escaped);
	return 1;
}

static int req_get_remote_logname (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);

	lua_pushstring (L, ap_get_remote_logname(r));
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

static int lua_ap_allowoverrides(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	char options[128];
	int opts = ap_allow_overrides(r);
	sprintf(options, "%s %s %s %s %s %s", (opts&OR_NONE) ? "None" : "", (opts&OR_LIMIT) ? "Limit" : "", (opts&OR_OPTIONS) ? "Options" : "", (opts&OR_FILEINFO) ? "FileInfo" : "", (opts&OR_AUTHCFG) ? "AuthCfg" : "", (opts&OR_INDEXES) ? "Indexes" : "" );
	lua_pushstring(L, options);
	return 1;
}

//////////////////////////////////////////////////////////////////////////

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

static int req_internal_redirect(lua_State* L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *new_uri = luaL_optstring(L, 2, r->uri);

	ap_internal_redirect(new_uri, r);
	return 0;
}

static int req_internal_redirect_handle(lua_State* L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *new_uri = luaL_optstring(L, 2, r->uri);

	ap_internal_redirect_handler(new_uri, r);
	return 0;
}


static int req_redirect(lua_State* L){
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *new_uri = luaL_checkstring(L, 2);
	int status = luaL_optint(L,3,302);

	apr_table_set(r->headers_out,"Location", new_uri);
	r->status = status;
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
	lua_Integer mtime = luaL_optinteger(L, 2, 0);
	if(mtime){
		ap_update_mtime(r, apr_time_from_sec(mtime));
	}
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
static int req_meets(lua_State*L )
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	apr_time_t mtime = luaL_checkint(L, 2);
	int len = luaL_checkint(L, 3);
	int status;
	if(mtime) 
		ap_update_mtime(r, mtime*APR_USEC_PER_SEC);
	ap_set_last_modified(r);
	ap_set_etag(r);
	ap_set_accept_ranges(r);
	apr_table_setn(r->headers_out, "Content-Length", apr_itoa(r->pool,len));
	status = ap_meets_conditions(r);
	if(status==0){
		lua_pushnil(L);
	}else
		lua_pushinteger(L, status);
	
	return 1;
}
static int req_sendfile(lua_State* L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *fname = luaL_checkstring(L,2);
	apr_size_t offset = luaL_optlong(L,3,0);
	apr_size_t len = luaL_optlong(L,4,-1);

	apr_status_t status;

	status=apr_stat(&r->finfo, fname, APR_FINFO_SIZE|APR_FINFO_MTIME|APR_FINFO_TYPE, r->pool);
	if (status != APR_SUCCESS || r->finfo.filetype!=APR_REG) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Could not stat file for reading %s", fname);
		lua_pushnil(L);
		lua_pushstring(L,"Could not stat file for reading");
		return 2;
	}
	if (len==-1) 
		len=(apr_size_t)r->finfo.size;
	ap_update_mtime(r, r->finfo.mtime);
	ap_set_last_modified(r);
	ap_set_etag(r);
	ap_set_accept_ranges(r);
	ap_set_content_length(r,len);

	status = ap_meets_conditions(r);
	if(status==OK){
		apr_file_t *fd;
		status=apr_file_open(&fd, fname, APR_READ, APR_OS_DEFAULT, r->pool);
		if (status != APR_SUCCESS) {
			ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Could not open file for reading %s", fname);
			lua_pushnil(L);
			lua_pushstring(L,"Could not open file for reading");
			return 2;
		}                         
		r->status = HTTP_OK;
		status = ap_send_fd(fd, r, offset,  len, &len);
		apr_file_close(fd);

		if (status != APR_SUCCESS) 
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, status, r, "Write failed, client closed connection.");
			lua_pushnil(L);
			lua_pushstring(L,"Write failed, client closed connection.");
			return 2;
		}
	}else
		r->status = status;
	lua_pushinteger(L, r->status);
	lua_pushinteger(L, len);
	return 2;
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
** Binding to ap_discard_request_body.
** Uses the request_rec defined as an upvalue.
** Returns a status code.
*/
static int req_discard_request_body (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);

	lua_pushnumber (L, ap_discard_request_body (r));
	return 1;
}

/* FIXME: zhaozg */
static int req_add_output_filter(lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* filter = luaL_checkstring(L,2);

	ap_filter_t * f = ap_add_output_filter(filter,NULL,r,r->connection);
	apr_pool_userdata_set(L,ML_OUTPUT_FILTER_KEY4LUA, apr_pool_cleanup_null, r->pool);
	lua_pushboolean(L,f!=NULL);
	return 1;
}

/** 
 * ap_add_version_component (apr_pool_t *pconf, const char *component)
 * Add a component to the server description and banner strings
 * @param pconf The pool to allocate the component from
 * @param component The string to add
  */
static int lua_ap_add_version_component (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char* component = luaL_checkstring(L, 2);
    ap_add_version_component(r->server->process->pconf, component);
    return 0;
}


/** 
 * ap_satisfies (request_rec *r)
 * How the requires lines must be met.
 * @param r The current request
 * @return How the requirements must be met.  One of:
 * <pre>
 *      SATISFY_ANY    -- any of the requirements must be met.
 *      SATISFY_ALL    -- all of the requirements must be met.
 *      SATISFY_NOSPEC -- There are no applicable satisfy lines
 * </pre>
  */
static int lua_ap_satisfies (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);

    int returnValue = ap_satisfies(r);
    if (returnValue == SATISFY_ANY) lua_pushstring(L, "SATISFY_ANY");
    if (returnValue == SATISFY_ALL) lua_pushstring(L, "SATISFY_ALL");
    if (returnValue == SATISFY_NOSPEC) lua_pushstring(L, "SATISFY_NOSPEC");
    return 1;
}


static int lua_ap_get_limit_req_body(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	lua_pushinteger(L, (lua_Integer)ap_get_limit_req_body(r));
	return 1;
}

static int lua_ap_request_has_body(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	lua_pushboolean(L, ap_request_has_body(r));
	return 1;
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

static int lua_ap_add_output_filter(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* filterName = luaL_checkstring(L, 2);
	ap_filter_rec_t *filter = ap_get_output_filter_handle(filterName);
	if (filter) {
		ap_add_output_filter_handle(filter, NULL, r, r->connection);
		lua_pushboolean(L, 1);
	}
	else {
		lua_pushboolean(L, 0);
	}
	return 1;
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

static int req_mime_types(lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	apr_pool_t *p = r->connection->base_server->process->pool;
	const char* resource_name = luaL_checkstring(L, 2);
	int set = lua_isnoneornil(L, 3) ? 0 : lua_toboolean(L, 3);
	apr_hash_t *mimes = NULL;
	apr_status_t rc = apr_pool_userdata_get((void**)&mimes, "mod_luaex", p);
	const char* fn, *ext, *fntmp;
	const char* type = NULL;

	if (rc==APR_SUCCESS && mimes){
		if ((fn = ap_strrchr_c(resource_name, '/')) == NULL) {
			fn = resource_name;
		}
		else {
			++fn;
		}
		/* Always drop the path leading up to the file name.
		 */


		/* The exception list keeps track of those filename components that
		 * are not associated with extensions indicating metadata.
		 * The base name is always the first exception (i.e., "txt.html" has
		 * a basename of "txt" even though it might look like an extension).
		 * Leading dots are considered to be part of the base name (a file named
		 * ".png" is likely not a png file but just a hidden file called png).
		 */
		fntmp = fn;
		while (*fntmp == '.')
			fntmp++;
		fntmp = ap_strchr_c(fntmp, '.');
		if (fntmp) {
			fn = fntmp + 1;
			ext = apr_pstrdup(r->pool, fn);
		}
		else {
			ext = apr_pstrdup(r->pool, fn);
			fn += strlen(fn);
		}

		if (set && (type = apr_hash_get(mimes, ext, APR_HASH_KEY_STRING)) != NULL) {
				ap_set_content_type(r, (char*) type);
		}
	}
	if (type)
		lua_pushstring(L, type);
	else
		lua_pushnil(L);

	return 1;
}

req_fun_t *ml_makefun(const void *fun, int type, apr_pool_t *pool)
{
	req_fun_t *rft = apr_palloc(pool, sizeof(req_fun_t));
	rft->fun = fun;
	rft->type = type;
	return rft;
}

void ml_ext_request_lmodule(lua_State *L, apr_pool_t *p) {
	apr_hash_t *dispatch;
	lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
	dispatch = lua_touserdata(L, -1);
	lua_pop(L, 1);
	assert(dispatch);

	/* add field */
	apr_hash_set(dispatch, "header_only", APR_HASH_KEY_STRING, ml_makefun(&req_header_only, APL_REQ_FUNTYPE_BOOLEAN, p));

	/* add function */
	apr_hash_set(dispatch, "escapehtml", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_escapehtml, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "allowoverrides", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_allowoverrides, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "add_version_component", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_add_version_component, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "request_has_body", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_request_has_body, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_limit_req_body", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_get_limit_req_body, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "get_basic_auth_pw", APR_HASH_KEY_STRING, ml_makefun(&req_get_basic_auth_pw, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "meets_conditions", APR_HASH_KEY_STRING, ml_makefun(&req_meets_conditions, APL_REQ_FUNTYPE_LUACFUN, p));
	
	apr_hash_set(dispatch, "print", APR_HASH_KEY_STRING, ml_makefun(&req_print, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "add_cgi_vars", APR_HASH_KEY_STRING, ml_makefun(&req_add_cgi_vars, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "internal_redirect", APR_HASH_KEY_STRING, ml_makefun(&req_internal_redirect, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "internal_redirect_handle", APR_HASH_KEY_STRING, ml_makefun(&req_internal_redirect_handle, APL_REQ_FUNTYPE_LUACFUN, p));
	
	apr_hash_set(dispatch, "redirect", APR_HASH_KEY_STRING, ml_makefun(&req_redirect, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "sendfile", APR_HASH_KEY_STRING, ml_makefun(&req_sendfile, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "meets",    APR_HASH_KEY_STRING, ml_makefun(&req_meets,    APL_REQ_FUNTYPE_LUACFUN, p));
	
	apr_hash_set(dispatch, "get_remote_host", APR_HASH_KEY_STRING, ml_makefun(&req_get_remote_host, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_remote_logname", APR_HASH_KEY_STRING, ml_makefun(&req_get_remote_logname, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_server_port", APR_HASH_KEY_STRING, ml_makefun(&req_get_server_port, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "allow_methods", APR_HASH_KEY_STRING, ml_makefun(&req_allow_methods, APL_REQ_FUNTYPE_LUACFUN, p));
	

	apr_hash_set(dispatch, "server", APR_HASH_KEY_STRING, ml_makefun(&req_server, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "connection", APR_HASH_KEY_STRING, ml_makefun(&req_connection, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "set_content_length", APR_HASH_KEY_STRING, ml_makefun(&req_set_content_length, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "set_etag", APR_HASH_KEY_STRING, ml_makefun(&req_set_etag, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "set_last_modified", APR_HASH_KEY_STRING, ml_makefun(&req_set_last_modified, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "update_mtime", APR_HASH_KEY_STRING, ml_makefun(&req_update_mtime, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "mime_types", APR_HASH_KEY_STRING, ml_makefun(&req_mime_types, APL_REQ_FUNTYPE_LUACFUN, p));
	
	apr_hash_set(dispatch, "read", APR_HASH_KEY_STRING, ml_makefun(&req_read, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "rflush", APR_HASH_KEY_STRING, ml_makefun(&req_rflush, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_client_block", APR_HASH_KEY_STRING, ml_makefun(&req_get_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "setup_client_block", APR_HASH_KEY_STRING, ml_makefun(&req_setup_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "should_client_block", APR_HASH_KEY_STRING, ml_makefun(&req_should_client_block, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "discard_request_body", APR_HASH_KEY_STRING, ml_makefun(&req_discard_request_body, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "add_output_filter", APR_HASH_KEY_STRING, ml_makefun(&req_add_output_filter, APL_REQ_FUNTYPE_LUACFUN, p));

	/* extends apache modules API */
	apr_hash_set(dispatch, "list_provider", APR_HASH_KEY_STRING, ml_makefun(&ml_list_provider, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "socache_lookup", APR_HASH_KEY_STRING, ml_makefun(&ml_socache_lookup, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_get", APR_HASH_KEY_STRING, ml_makefun(&ml_session_get, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_set", APR_HASH_KEY_STRING, ml_makefun(&ml_session_set, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_load", APR_HASH_KEY_STRING, ml_makefun(&ml_session_load, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "session_save", APR_HASH_KEY_STRING, ml_makefun(&ml_session_save, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_create", APR_HASH_KEY_STRING, ml_makefun(&ml_slotmem_create, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_attach", APR_HASH_KEY_STRING, ml_makefun(&ml_slotmem_attach, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "slotmem_lookup", APR_HASH_KEY_STRING, ml_makefun(&ml_slotmem_lookup, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "dbd_acquire", APR_HASH_KEY_STRING, ml_makefun(&ml_dbd_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "dbd_prepare", APR_HASH_KEY_STRING, ml_makefun(&ml_dbdriver_prepare, APL_REQ_FUNTYPE_LUACFUN, p));

#ifdef ML_HAVE_RESLIST
	apr_hash_set(dispatch, "reslist_acquire", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_release", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_release, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_invalidate", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_invalidate, APL_REQ_FUNTYPE_LUACFUN, p));
#endif

}
