#include "mod_luaex.h"

APR_OPTIONAL_FN_TYPE(ap_find_loaded_module_symbol) *ap_find_module = NULL;

/************************************************************************/
/*                                                                      */
/************************************************************************/

static int req_header_only (request_rec *r) {
	return r->header_only;
}


static int lua_ap_unescape (lua_State *L) {
	size_t x,y;
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *escaped = luaL_checklstring(L, 2, &x);
	char *plain = apr_pstrdup(r->pool, escaped);
	strncpy(plain, escaped, x);
	y = ap_unescape_urlencoded(plain);
	lua_pushstring(L, plain);
	return 1;
}


static int lua_ap_escape (lua_State *L) {
	size_t x;
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *plain = luaL_checklstring(L, 2, &x);
	char *escaped = ap_escape_urlencoded(r->pool, plain);
	lua_pushstring(L, escaped);
	return 1;
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



static int lua_ap_sendfile(lua_State *L)
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char  *filename = luaL_checkstring(L, 2);

	struct apr_finfo_t  fileinfo;
	
	if (apr_stat(&fileinfo,filename,APR_FINFO_SIZE,r->pool) == -1)
		lua_pushboolean(L, 0);
	else {
		if (r) {

			/*~~~~~~~~~~~~~~~~~~*/
			apr_size_t      sent;
			apr_status_t    rc;
			apr_file_t      *file;
			/*~~~~~~~~~~~~~~~~~~*/

			rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT,
				r->pool);
			if (rc == APR_SUCCESS) {
				ap_send_fd(file, r, 0, (apr_size_t)fileinfo.size, &sent);
				apr_file_close(file);
				lua_pushinteger(L, sent);
			}
			else
				lua_pushboolean(L, 0);
		}
		else
			lua_pushboolean(L, 0);
	}

	return (1);
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


static int lua_ap_expr(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *expr = luaL_checkstring(L, 2);
	int x = 0;
	const char *err;
	ap_expr_info_t res = {0};

	res.filename = NULL;
	res.flags = 0;
	res.line_number = 0;
	res.module_index = 0;

	err = ap_expr_parse(r->pool, r->pool, &res, expr, NULL);
	if (!err) {
		x = ap_expr_exec(r, &res, &err);
		lua_pushboolean(L, x);
		if (x < 0) {
			lua_pushstring(L, err);
			return 2;
		}
		return 1;
	}
	else {
		lua_pushboolean(L, 0);
		lua_pushstring(L, err);
		return 2;
	}
	lua_pushboolean(L, 0);
	return 1;
}


static int lua_ap_expr_extract(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *pattern = luaL_checkstring(L, 2);
	const char *source = luaL_checkstring(L, 3);
	int x = 0;
	const char *err=NULL;
	ap_regex_t regex;
	ap_regmatch_t matches[10];

	if (ap_regcomp(&regex, pattern,0)) {
		return 0;
	}


	if (!err) {
		int i;
		x = ap_regexec(&regex, source, 10, matches, 0);
		if (x < 0) {
			lua_pushstring(L, err);
			return 1;
		}
		lua_newtable(L);
		for (i=0;i<10;i++) {
			lua_pushinteger(L, i);
			if (matches[i].rm_so >= 0 && matches[i].rm_eo >= 0) {
				lua_pushstring(L,apr_pstrndup(r->pool, source+matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so));
			}
			else {
				lua_pushnil(L);
			}
			lua_settable(L, -3);

		}
		return 1;
	}
	return 0;
}


static int lua_ap_getenv(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *env = luaL_checkstring(L, 2);
	const apr_array_header_t    *fields = apr_table_elts(r->subprocess_env);
	int                         i;
	apr_table_entry_t   *e = 0;
	char *value = 0;
	
	e = (apr_table_entry_t *) fields->elts;
	for (i = 0; i < fields->nelts; i++) {
		if (!strcmp(env, e[i].key)) {
			lua_pushstring(L, e[i].val);
			return 1;
		}
	}
	apr_env_get(&value, env, r->pool);
	if (value) lua_pushstring(L, value);
	return 1;
}

static int lua_ap_setenv(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char *key = luaL_checkstring(L, 2);
	const char *val = luaL_checkstring(L, 3);
	apr_table_add(r->subprocess_env, key, val);
	apr_env_set(key, val, r->pool);
	return 0;
}



static int lua_ap_options(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	char options[128];
	int opts;
	/*~~~~~~~~~~~~~~~~~~*/
	opts = ap_allow_options(r);
	sprintf(options, "%s %s %s %s %s %s", (opts&OPT_INDEXES) ? "Indexes" : "", (opts&OPT_INCLUDES) ? "Includes" : "", (opts&OPT_SYM_LINKS) ? "FollowSymLinks" : "", (opts&OPT_EXECCGI) ? "ExecCGI" : "", (opts&OPT_MULTI) ? "MultiViews" : "", (opts&OPT_ALL) == OPT_ALL ? "All" : "" );
	lua_pushstring(L, options);
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
	apr_pool_userdata_set(L,ML_OUTPUT_FILTER_KEY4LUA, apr_pool_cleanup_null, r->pool);
	lua_pushboolean(L,f!=NULL);
	return 1;
}



/** 
 * ap_auth_type (request_rec *r) */
static int lua_ap_auth_type (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char * returnValue = ap_auth_type(r);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_some_auth_required (request_rec *r)
 * Can be used within any handler to determine if any authentication
 * is required for the current request
 * @param r The current request
 * @return 1 if authentication is required, 0 otherwise
  */
static int lua_ap_some_auth_required (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int returnValue = ap_some_auth_required(r);
    lua_pushboolean(L, returnValue);
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
 * ap_context_prefix (request_rec *r)
 * Get the context_prefix for a request. The context_prefix URI prefix
 * maps to the context_document_root on disk.
 * @param r The request
  */
static int lua_ap_context_prefix (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char * returnValue = ap_context_prefix(r);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_set_context_info (request_rec *r, const char *prefix,
                                     const char *document_root) Set context_prefix and context_document_root for a request.
 * @param r The request
 * @param prefix the URI prefix, without trailing slash
 * @param document_root the corresponding directory on disk, without trailing
 * slash
 * @note If one of prefix of document_root is NULL, the corrsponding
 * property will not be changed.
  */
static int lua_ap_set_context_info (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char* prefix = luaL_checkstring(L, 2);
    const char* document_root = luaL_checkstring(L, 3);
    ap_set_context_info(r, prefix, document_root);
    return 0;
}


/** 
 * ap_os_escape_path (apr_pool_t *p, const char *path, int partial)
 * convert an OS path to a URL in an OS dependant way.
 * @param p The pool to allocate from
 * @param path The path to convert
 * @param partial if set, assume that the path will be appended to something
 *        with a '/' in it (and thus does not prefix "./")
 * @return The converted URL
  */
static int lua_ap_os_escape_path (lua_State *L) {

    char * returnValue;
    request_rec *r = CHECK_REQUEST_OBJECT(1);

    const char* path = luaL_checkstring(L,2);
    int partial = 0;
    if ( lua_isboolean( L, 3 ) ) 
	    partial =  lua_toboolean( L, 3 );
    returnValue = ap_os_escape_path(r->pool, path, partial);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_escape_logitem (apr_pool_t *p, const char *str)
 * Escape a string for logging
 * @param p The pool to allocate from
 * @param str The string to escape
 * @return The escaped string
  */
static int lua_ap_escape_logitem (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    const char* str = luaL_checkstring(L, 2);

    char *returnValue = ap_escape_logitem(r->pool, str);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_set_keepalive (request_rec *r)
 * Set the keepalive status for this request
 * @param r The current request
 * @return 1 if keepalive can be set, 0 otherwise
  */
static int lua_ap_set_keepalive (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int returnValue = ap_set_keepalive(r);
    lua_pushboolean(L, returnValue);
    return 1;
}

/** 
 * ap_make_etag (request_rec *r, int force_weak)
 * Construct an entity tag from the resource information.  If it's a real
 * file, build in some of the file characteristics.
 * @param r The current request
 * @param force_weak Force the entity tag to be weak - it could be modified
 *                   again in as short an interval.
 * @return The entity tag
  */
static int lua_ap_make_etag (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    char * returnValue;
    int force_weak;
    luaL_checktype(L, 2, LUA_TBOOLEAN);
    force_weak = luaL_optint(L, 2, 0);
    returnValue = ap_make_etag(r, force_weak);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_send_interim_response (request_rec *r, int send_headers)
 * Send an interim (HTTP 1xx) response immediately.
 * @param r The request
 * @param send_headers Whether to send&clear headers in r->headers_out
  */
static int lua_ap_send_interim_response (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int send_headers;
    if ( lua_isboolean( L, 2 ) ) send_headers =  lua_toboolean( L, 2 );
    ap_send_interim_response(r, send_headers);
    return 0;
}


/** 
 * ap_get_server_name (request_rec *r)
 * Get the current server name from the request
 * @param r The current request
 * @return the server name
  */
static int lua_ap_get_server_name (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);

    const char * returnValue = ap_get_server_name(r);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_custom_response (request_rec *r, int status, const char *string)
 * Install a custom response handler for a given status
 * @param r The current request
 * @param status The status for which the custom response should be used
 * @param string The custom response.  This can be a static string, a file
 *               or a URL
  */
static int lua_ap_custom_response (lua_State *L) {
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    int status = luaL_checkint(L, 2);
    const char* string = luaL_checkstring(L, 3);
    ap_custom_response(r, status, string);
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



static int lua_ap_run_sub_req (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);

	request_rec *new_r;
	const char* uri = luaL_checkstring(L, 2);
	new_r = ap_sub_req_lookup_uri(uri, r, NULL);
	ap_parse_uri(new_r, uri);
	new_r->header_only = 1;
	new_r-> status = 0;
	new_r->handler = "default-handler";
	ap_run_type_checker(new_r);
	ap_run_translate_name(new_r);
	ap_run_map_to_storage(new_r);
	ap_run_fixups(new_r);
	//ap_run_handler(new_r);


	lua_newtable(L);

	lua_pushstring(L, "status");
	lua_pushinteger(L, new_r->status);
	lua_settable(L, -3);

	lua_pushstring(L, "hostname");
	lua_pushstring(L, new_r->hostname);
	lua_settable(L, -3);

	lua_pushstring(L, "uri");
	lua_pushstring(L, new_r->uri);
	lua_settable(L, -3);

	return 1;
}




/** 
 * ap_auth_name (request_rec *r)
 * Return the current Authorization realm
 * @param r The current request
 * @return The current authorization realm
  */
static int lua_ap_auth_name (lua_State *L) {
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char * returnValue = ap_auth_name(r);

    lua_pushstring(L, returnValue);
    return 1;
}


static int lua_ap_get_limit_req_body(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	lua_pushinteger(L, ap_get_limit_req_body(r));
	return 1;
}


static int lua_ap_request_has_body(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	lua_pushboolean(L, ap_request_has_body(r));
	return 1;
}


static int lua_ap_is_initial_req(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	lua_pushboolean(L, ap_is_initial_req(r));
	return 1;
}

static int lua_ap_runtime_dir_relative(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char*file = luaL_optstring(L, 2, ".");
	lua_pushstring(L, ap_runtime_dir_relative(r->pool, file));
	return 1;
}

static int lua_ap_set_document_root(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* root = luaL_checkstring(L, 2);
	ap_set_document_root(r, root);
	return 0;
}

static int lua_ap_stat(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* filename = luaL_checkstring(L, 2);
	apr_finfo_t file_info;
	apr_stat(&file_info, filename, APR_FINFO_NORM, r->pool);
	lua_newtable(L);

	lua_pushstring(L, "mtime");
	lua_pushinteger(L, file_info.mtime);
	lua_settable(L, -3);

	lua_pushstring(L, "atime");
	lua_pushinteger(L, file_info.atime);
	lua_settable(L, -3);

	lua_pushstring(L, "ctime");
	lua_pushinteger(L, file_info.ctime);
	lua_settable(L, -3);

	lua_pushstring(L, "size");
	lua_pushinteger(L, file_info.size);
	lua_settable(L, -3);

	lua_pushstring(L, "filetype");
	lua_pushinteger(L, file_info.filetype);
	lua_settable(L, -3);

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


static int lua_ap_add_input_filter(lua_State *L) 
{
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* filterName = luaL_checkstring(L, 2);
	ap_filter_rec_t *filter = ap_get_input_filter_handle(filterName);
	if (filter) {
		ap_add_input_filter_handle(filter, NULL, r, r->connection);
		lua_pushboolean(L, 1);
	}
	else {
		lua_pushboolean(L, 0);
	}
	return 1;
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
	apr_hash_set(dispatch, "escape", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_escape, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "unescape", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_unescape, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "escapehtml", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_escapehtml, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "expr", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_expr, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "regex", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_expr_extract, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "setenv", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_setenv, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "getenv", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_getenv, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "options", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_options, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "allowoverrides", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_allowoverrides, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "auth_type", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_auth_type, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "auth_name", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_auth_name, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "custom_response", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_custom_response, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_server_name", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_get_server_name, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "send_interim_response", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_send_interim_response, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "make_etag", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_make_etag, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "set_keepalive", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_set_keepalive, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "escape_logitem", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_escape_logitem, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "os_escape_path", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_os_escape_path, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "set_context_info", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_set_context_info, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "context_prefix", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_context_prefix, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "add_version_component", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_add_version_component, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "some_auth_required", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_some_auth_required, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "stat", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_stat, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "set_document_root", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_set_document_root, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "runtime_dir_relative", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_runtime_dir_relative, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "is_initial_req", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_is_initial_req, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "request_has_body", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_request_has_body, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_limit_req_body", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_get_limit_req_body, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "print", APR_HASH_KEY_STRING, ml_makefun(&req_print, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "add_cgi_vars", APR_HASH_KEY_STRING, ml_makefun(&req_add_cgi_vars, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "internal_redirect", APR_HASH_KEY_STRING, ml_makefun(&req_internal_redirect, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "redirect", APR_HASH_KEY_STRING, ml_makefun(&req_redirect, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "sendfile", APR_HASH_KEY_STRING, ml_makefun(&lua_ap_sendfile, APL_REQ_FUNTYPE_LUACFUN, p));


	apr_hash_set(dispatch, "get_remote_host", APR_HASH_KEY_STRING, ml_makefun(&req_get_remote_host, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "get_remote_logname", APR_HASH_KEY_STRING, ml_makefun(&req_get_remote_logname, APL_REQ_FUNTYPE_LUACFUN, p));

	apr_hash_set(dispatch, "server", APR_HASH_KEY_STRING, ml_makefun(&req_server, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "connection", APR_HASH_KEY_STRING, ml_makefun(&req_connection, APL_REQ_FUNTYPE_LUACFUN, p));
	

	apr_hash_set(dispatch, "read", APR_HASH_KEY_STRING, ml_makefun(&req_read, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "rflush", APR_HASH_KEY_STRING, ml_makefun(&req_rflush, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "remaining", APR_HASH_KEY_STRING, ml_makefun(&req_remaining, APL_REQ_FUNTYPE_LUACFUN, p));
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

	apr_hash_set(dispatch, "ssl_var_lookup", APR_HASH_KEY_STRING, ml_makefun(&ml_ssl_var_lookup, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "ssl_is_https", APR_HASH_KEY_STRING, ml_makefun(&ml_ssl_is_https, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "dbd_acquire", APR_HASH_KEY_STRING, ml_makefun(&ml_dbd_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "dbd_prepare", APR_HASH_KEY_STRING, ml_makefun(&ml_dbdriver_prepare, APL_REQ_FUNTYPE_LUACFUN, p));

#ifdef ML_HAVE_RESLIST
	apr_hash_set(dispatch, "reslist_acquire", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_release", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_release, APL_REQ_FUNTYPE_LUACFUN, p));
	apr_hash_set(dispatch, "reslist_invalidate", APR_HASH_KEY_STRING, ml_makefun(&ml_reslist_invalidate, APL_REQ_FUNTYPE_LUACFUN, p));
#endif

}
