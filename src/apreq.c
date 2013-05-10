
#include "mod_luaex.h"
#include "apr_strings.h"
#include "apreq.h"
#include "apreq_module.h"
#include "apreq_util.h"

#include "private.h"
#include <lua_apr.h>
/************************************************************************/
/* apreq util                                                                     */
/************************************************************************/
static int ap2req_pushvalue(lua_State *L, const apreq_value_t *val) {
	lua_newtable(L);
	lua_pushlstring(L,val->name,val->nlen);
	lua_pushlstring(L,val->data,val->dlen);
	lua_settable(L,-3);
	return 1;
}

static int ap2req_push_status(lua_State*L, apr_status_t status) {
    char errbuf[256], *str;

    if (status==APR_SUCCESS)
    {
        lua_pushboolean(L,1);
        return 1;
    }
    lua_pushnil(L);
    str = apreq_strerror(status, errbuf, sizeof(errbuf));
    lua_pushstring (L, str);
    lua_pushinteger(L, status);
    return 3;
}

//////////////////////////////////////////////////////////////////////////
//Global function
//////////////////////////////////////////////////////////////////////////

/* return version_string,major_version,minor_version,patch_version,is_dev */

int ap2req_strerror (lua_State *L) {
	char errbuf[256], *str;
	apr_status_t err = luaL_checkint(L, 1);

	str = apreq_strerror(err, errbuf, sizeof(errbuf));
	lua_pushstring (L, str);
	return 1;
}

int ap2req_atoi64f(lua_State*L) {
	const char* s = luaL_checkstring(L,1);
	lua_Number f = (lua_Number)apreq_atoi64f(s);
	lua_pushnumber(L,f);
	return 1;
}

int ap2req_atoi64t(lua_State*L) {
	const char* s = luaL_checkstring(L,1);
	apr_int64_t t = apreq_atoi64t(s);
	lua_pushinteger(L,(apr_int32_t)t);
	return 1;
}

/* string */
int ap2req_charset_divine(lua_State*L)
{
	apr_size_t  slen;
	apreq_charset_t charset;
	const char* src = luaL_checklstring(L,1,&slen);
	slen = luaL_optlong(L,2, slen);
	
	charset = apreq_charset_divine  (src, slen);
	lua_pushinteger(L,charset);
	return 1;
}

int ap2req_cp1252_to_utf8(lua_State*L) {
	apr_size_t slen, size;
	char* buf;
	const char* src = luaL_checklstring(L,1,&slen);
	slen = luaL_optlong(L,2, slen);

	buf = malloc(3*slen);

	size =  apreq_cp1252_to_utf8  (buf,  src , slen);
	lua_pushlstring(L,buf,size);
	free(buf);
	lua_pushinteger(L,size);
	return 2;
}

int ap2req_decode(lua_State*L) {
	apr_size_t  dlen, slen;
	char* buf;
	apr_status_t rc;
	const char* src = luaL_checklstring(L,1,&slen);
	slen = luaL_optlong(L,2, slen);

	buf = malloc(2*slen);

	rc = apreq_decode  (
		buf,  
		&dlen,  
		src,  
		slen 
		);
	if(rc==APR_SUCCESS)
	{
		lua_pushlstring(L,buf,dlen);
		free(buf);
	}else
		lua_pushnil(L);
	lua_pushinteger(L,dlen);
	lua_pushinteger(L,rc);
	return 3;
}

int ap2req_encode(lua_State*L) {
	apr_size_t  dlen, slen;
	char* buf;
	const char* src = luaL_checklstring(L,1,&slen);
	slen = luaL_optlong(L,2, slen);

	buf = malloc(2*slen);

	dlen = apreq_encode  (
		buf,  
		src,  
		slen 
		) ;
	lua_pushlstring(L,buf,dlen);
	free(buf);
	lua_pushinteger(L,dlen);
	return 2;
}

//FIXME: use update request pointer
int ap2req_escape(lua_State*L) {
	apr_size_t slen;
	request_rec *r = CHECK_REQUEST_OBJECT(1);
	const char* src = luaL_checklstring(L,2,&slen);

	lua_pushstring(L,apreq_escape(r->pool, src, slen));
	return 1;
}

int ap2req_header_attribute(lua_State*L) {
	const char* hdr = luaL_checkstring(L,1);
	apr_size_t nlen, vlen;
	apr_status_t rc;
	const char* val;
	const char* name = luaL_checklstring(L,2,&nlen);
	nlen = luaL_optlong(L,3,nlen);

	rc = apreq_header_attribute(hdr,name,nlen,&val,&vlen);
	if(rc==APR_SUCCESS)
	{
		lua_pushlstring(L,val,vlen);
		lua_pushinteger(L,vlen);
		return 2;
	}
	return ap2req_push_status(L, rc);
}

int ap2req_index(lua_State*L) {
	apr_size_t hlen, nlen, vlen;
	const char* hdr = luaL_checklstring(L,1, &hlen);
	const char* name = luaL_checklstring(L,2,&nlen);
	apr_uint32_t type = luaL_checklong(L,3);
	hlen = luaL_optlong(L,4,hlen);
	nlen = luaL_optlong(L,5,nlen);

	vlen = apreq_index(hdr,hlen,name,nlen,type);
	lua_pushinteger(L,vlen);
	return 1;
}


int ap2req_quote(lua_State*L)
{
	apr_size_t slen,dlen;
	const char* src = luaL_checklstring(L,1, &slen);
	char* buf;
	slen = luaL_optlong(L,2,slen);
	
	buf = malloc(2*(slen+10));
	dlen = apreq_quote(buf,src, slen);

	lua_pushlstring(L,buf,dlen);
	free(buf);
	return 1;
}

int ap2req_quote_once(lua_State*L) {
	apr_size_t slen,dlen;
	const char* src = luaL_checklstring(L,1, &slen);
	char* buf;
	slen = luaL_optlong(L,2,slen);

	buf = malloc(2*slen);
	dlen = apreq_quote_once(buf,src, slen);

	lua_pushlstring(L,buf,dlen);
	free(buf);
	return 1;
}

int ap2req_unescape(lua_State*L) {
	apr_size_t slen,dlen;
	char* src = (char*)luaL_checklstring(L,1, &slen);
	slen = luaL_optlong(L,2,slen);

	dlen = apreq_unescape(src);  

	lua_pushlstring(L, src,dlen);
	return 1;
}

int ap2req_module_status_is_error(lua_State *L) {
	apr_status_t rc = luaL_checkint(L,1);

	unsigned status = apreq_module_status_is_error  (rc);
	lua_pushboolean(L, status);
	return 1;
}


/************************************************************************/
/*  cookie object                                                       */
/************************************************************************/

/*
  input
     1 cookie object
	 2 apreq handle objec
  output
     string as cookie

int apreq_cookie_serialize  (  const apreq_cookie_t *  c,  char *  buf,  apr_size_t  len )   

Same functionality as apreq_cookie_as_string. Stores the string representation in buf, using up to len bytes in buf as storage. The return value has the same semantics as that of apr_snprintf, including the special behavior for a "len = 0" argument.
 Parameters:
	 c  cookie.  
	 buf  storage location for the result.  
	 len  size of buf's storage area. 
*/

static int cookie_as_string(lua_State*L) {
	const apreq_cookie_t *c = CHECK_COOKIE_OBJECT(1);
	char buf[4096];
	int len = 4096;
	len = apreq_cookie_serialize(c,buf,len);
	lua_pushlstring(L,buf,len);
	return 1;
}

static int cookie_index(lua_State*L) {
	apreq_cookie_t *c =(apreq_cookie_t*) CHECK_COOKIE_OBJECT(1);
	const char*key = luaL_checkstring(L,2);

	if(lua_gettop(L)==2)
	{
		if(strcmp(key,"path")==0)
			lua_pushstring(L,c->path);
		else if(strcmp(key,"domain")==0)
			lua_pushstring(L,c->domain);
		else if(strcmp(key,"port")==0)
			lua_pushstring(L,c->port);

		else if(strcmp(key,"version")==0)
			lua_pushinteger(L,apreq_cookie_version(c));
		else if(strcmp(key,"expires")==0)
		{
			char expires[APR_RFC822_DATE_LEN];
			apr_rfc822_date(expires, c->max_age);
			lua_pushstring(L, expires);
			lua_pushinteger(L, (lua_Integer)c->max_age);
			return 2;
		}
		else if(strcmp(key,"secure")==0)
		{
			lua_pushboolean(L, apreq_cookie_is_secure(c));
		}
		else if(strcmp(key,"tainted")==0)
		{
			lua_pushboolean(L, apreq_cookie_is_tainted(c));
		}

		else if(strcmp(key,"comment")==0)
			lua_pushstring(L,c->comment);
		else if(strcmp(key,"commentURL")==0)
			lua_pushstring(L,c->commentURL);
		else if(strcmp(key,"max_age")==0)
			lua_pushinteger(L,(lua_Integer)c->max_age);
		else if(strcmp(key,"flags")==0)
			lua_pushinteger(L,c->flags);
		else if(strcmp(key,"value")==0)
			ap2req_pushvalue(L,&c->v);
		else if(strcmp(key,"name")==0)
			lua_pushlstring(L,c->v.name,c->v.nlen);
		else if(strcmp(key,"data")==0)
			lua_pushlstring(L,c->v.data,c->v.dlen);
		else
			lua_pushnil(L);
		return 1;
	}else
	{
		if(strcmp(key,"path")==0)
		{
			c->path = (char*)luaL_optstring(L,3,NULL);
		}
		else if(strcmp(key,"domain")==0)
		{
			c->domain = (char*)luaL_optstring(L,3,NULL);
		}
		else if(strcmp(key,"port")==0)
			c->port = (char*)luaL_optstring(L,3,NULL);
		else if(strcmp(key,"comment")==0)
		{
			c->comment = (char*)luaL_optstring(L,3,NULL);
		}
		else if(strcmp(key,"commentURL")==0)
		{
			c->commentURL = (char*)luaL_optstring(L,3,NULL);
		}

		else if(strcmp(key,"version")==0)
			apreq_cookie_version_set(c, luaL_checkint(L,3));
		else if(strcmp(key,"expires")==0)
		{
			char expires[APR_RFC822_DATE_LEN];
			if(lua_isstring(L,3))
			{
				const char* exp = lua_tostring(L,3);
				apreq_cookie_expires(c, exp);
			}else
			{
				apr_rfc822_date(expires, luaL_checkint(L,3));
				apreq_cookie_expires(c, expires);
			}
		}
		else if(strcmp(key,"secure")==0)
		{
			unsigned falgs = lua_toboolean(L, 3);
			if(falgs!=0)
				apreq_cookie_secure_on(c);
			else
				apreq_cookie_secure_off(c);
		}
		else if(strcmp(key,"tainted")==0)
		{
			unsigned flags = lua_toboolean(L, 3);
			if(flags!=0)
				apreq_cookie_tainted_on(c);
			else
				apreq_cookie_tainted_off(c);
		}
		else if(strcmp(key,"flags")==0)
		{
			c->flags = lua_toboolean(L, 3);
		}
	}
	return 0;
}

static luaL_reg cookie_mlibs[] = {
	{"__index",	cookie_index},
	{"__newindex",	cookie_index},
	{"__tostring",  cookie_as_string},

	{NULL,          NULL}
};


/*
input 
    1 apreq object
    2 header string
output 
    table(nil) apr_status
*/



static int ap2req_cookie_make(lua_State*L) {
	size_t nlen, vlen;
	apreq_cookie_t *c = NULL;
	const char* name = NULL;
	const char* value = NULL;
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	if(lua_isnoneornil(L,2) || lua_isboolean(L,2))
	{
		if(lua_isnoneornil(L,2)){
			apr_table_t* t =  apreq_cookies  ( h,  h->pool);

			if(t!=NULL)
			{
				ap_lua_push_apr_table(L,t);
			}else
			{
				lua_pushnil(L);
			}
			return 1;
		}else{
			int obj = lua_toboolean(L,2);
			const apr_table_t *t;
			apr_status_t rc = apreq_jar  ( h,  &t);
			if(rc==APR_SUCCESS)
			{
				if(!obj){
					ap_lua_push_apr_table(L,(apr_table_t*)t);
				}
				else
				{
					const apr_array_header_t *arr = apr_table_elts(t);
					int i;
					lua_newtable(L);
					for(i=0;i<arr->nelts;i++)
					{
						struct apr_table_entry_t e = APR_ARRAY_IDX(arr,i,struct apr_table_entry_t);
						apreq_cookie_t *c;
						lua_pushstring(L,e.key);
						c = apreq_jar_get  (h,  e.key);
						PUSH_COOKIE_OBJECT(c);
						lua_settable(L,-3);
					}


				}
				return 1;
			}else
			{
				lua_pushnil(L);
			}
			lua_pushinteger(L,rc);
			return 2;
		}
	}else if(lua_isstring(L,3))
	{
		name = luaL_checklstring(L,2, &nlen);
		value = luaL_checklstring(L,3, &vlen);
		c = apreq_cookie_make(h->pool, name, nlen, value, vlen);
		if(lua_istable(L,4))
		{
			lua_getfield(L,-1,"path");
			c->path = (char*)luaL_optstring(L,-1,NULL);
			lua_pop(L,1);

			lua_getfield(L,-1,"domain");
			c->domain = (char*)luaL_optstring(L,-1,NULL);
			lua_pop(L,1);

			lua_getfield(L,-1,"port");
			c->port = (char*)luaL_optstring(L,-1,NULL);
			lua_pop(L,1);

			lua_getfield(L,-1,"comment");
			c->comment = (char*)luaL_optstring(L,-1,NULL);
			lua_pop(L,1);

			lua_getfield(L,-1,"commentURL");
			c->commentURL = (char*)luaL_optstring(L,-1,NULL);
			lua_pop(L,1);


			lua_getfield(L,-1,"version");
			if(!lua_isnil(L,-1)) apreq_cookie_version_set(c, luaL_checkint(L,-1));
			lua_pop(L,1);

			lua_getfield(L,-1,"expires");
			if(!lua_isnil(L,-1))
			{
				char expires[APR_RFC822_DATE_LEN];
				if(lua_isstring(L,-1))
				{
					const char* exp = lua_tostring(L, -1);
					apreq_cookie_expires(c, exp);
				}else
				{
					apr_rfc822_date(expires, luaL_checkint(L, -1));
					apreq_cookie_expires(c, expires);
				}
			}
			lua_pop(L,1);

			lua_getfield(L,-1,"secure");
			if(!lua_isnil(L,-1))
			{
				int falgs = lua_toboolean(L, -1);
				if(falgs!=0)
					apreq_cookie_secure_on(c);
				else
					apreq_cookie_secure_off(c);
			}
			lua_pop(L,1);


			lua_getfield(L,-1,"tainted");
			if(!lua_isnil(L,-1))
			{
				int falgs = lua_toboolean(L, -1);
				if(falgs!=0)
					apreq_cookie_tainted_on(c);
				else
					apreq_cookie_tainted_off(c);
			}
			lua_pop(L,1);

			lua_getfield(L, -1, "flags");
			if(!lua_isnil(L, -1)){
				c->flags = luaL_checkint(L,-1);
			}
			lua_pop(L,1);
		}
	}else{
		if(lua_isnoneornil(L,3))
		{
			apr_table_t* t =  apreq_cookies  ( h,  h->pool);
			name = luaL_checklstring(L,2, &nlen);
			if(t)
				lua_pushstring(L,apr_table_get(t,name));
			else
				lua_pushnil(L);
			return 1;
		}else{
			int header = lua_toboolean(L,3);
			if(!header){
				value = luaL_checklstring(L,2, &vlen);
				c = apreq_value_to_cookie(value);
			}else{
				apr_status_t rc;
				apr_table_t *jar = apr_table_make(h->pool, APREQ_DEFAULT_NELTS);
				value = luaL_checkstring(L,2);
				rc = apreq_parse_cookie_header(h->pool, jar, value);
				if(rc==APR_SUCCESS) {
					ap_lua_push_apr_table(L, jar);
				}
				return ap2req_push_status(L, rc);
			}
		}
	}
	if(c)
		return PUSH_COOKIE_OBJECT(c);
	else
		return 0;
}

/************************************************************************/
/*   param object                                                       */
/************************************************************************/
static int param_index(lua_State*L)
{
	apreq_param_t *p = (apreq_param_t *)CHECK_PARAM_OBJECT(1);
	const char* key  = luaL_checkstring(L,2);
	if(lua_gettop(L)==2)
	{
		if(strcmp(key,"charset")==0)
		{
			apreq_charset_t set = apreq_param_charset_get(p);
			lua_pushinteger(L, set);
			if (set==APREQ_CHARSET_ASCII)
				lua_pushstring(L, "ascii");
			else if(set==APREQ_CHARSET_LATIN1)
				lua_pushstring(L, "latin1");
			else if(set==APREQ_CHARSET_CP1252)
				lua_pushstring(L, "cp1252");
			else if(set==APREQ_CHARSET_UTF8)
				lua_pushstring(L, "utf8");
			else
				lua_pushstring(L, "unknown");
			return 2;
		}else if(strcmp(key,"encode")==0)
		{
		    //FIXME:
		    apr_pool_t* pool = NULL;
		    apr_pool_create(&pool, NULL);
		    lua_pushstring(L,apreq_param_encode(pool, p));
		    apr_pool_destroy(pool);
		}else if(strcmp(key,"info")==0)
		{
			if (p->info)
                ap_lua_push_apr_table(L, p->info);
			else
				lua_pushnil(L);
		}else if(strcmp(key,"tainted")==0)
		{
			lua_pushboolean(L, apreq_param_is_tainted(p));
		}else if(strcmp(key,"upload")==0)
		{
			if (p->upload) {
				PUSH_BUCKETBRIGADE_OBJECT(p->upload);
			}else
				lua_pushnil(L);
		}else if(strcmp(key,"flags")==0) {
			lua_pushinteger(L,p->flags);
		}else if(strcmp(key,"value")==0){
			ap2req_pushvalue(L,&(p->v));
		}else
			lua_pushnil(L);
		return 1;
	}else
	{
		if(strcmp(key,"charset")==0) {
			int charset = luaL_checkint(L,3);
			apreq_param_charset_set(p, charset);
		}else if(strcmp(key,"tainted")==0)
		{
			unsigned falgs = lua_toboolean(L, 2);
			if(falgs!=0)
				apreq_param_tainted_on(p);
			else
				apreq_param_tainted_off(p);
			return 1;
		}
		return 0;
	}
	return 0;
};
static int param_tostring(lua_State*L){
    lua_pushfstring(L, "apreq_param(%p)", CHECK_PARAM_OBJECT(1));
    return 1;
}
static luaL_reg param_mlibs[] = {
	{"__tostring",	param_tostring},
	{"__index",		param_index},
	{"__newindex",	param_index},

	{NULL, NULL}
};



static int ap2req_param(lua_State *L)
{
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	int top = lua_gettop(L);
	if(top==1){
		apr_table_t* t = apreq_params(h,h->pool);

		if(t)
			ap_lua_push_apr_table(L,t);
		else
			lua_pushnil(L);
		return 1;
	}else{
		if(lua_isboolean(L,2))
		{
			int body = lua_toboolean(L, 2);
			const apr_table_t *t = NULL;
			apr_status_t s = APR_SUCCESS;
			if(body){
				s = apreq_body(h, &t);
			}else{
				s = apreq_args(h, &t);
			}

			if(s==APR_SUCCESS && t)
			{
				ap_lua_push_apr_table(L,(apr_table_t*)t);
				lua_pushboolean(L, body);
			}else
			{
				lua_pushnil(L);
				lua_pushinteger(L, s);
			}

			return 2;
		}else{
			const char* key = luaL_checkstring(L,2);

			if(top>2){
				if(lua_isboolean(L, 3))
				{
					int body = lua_toboolean(L, 3);
					apreq_param_t* p = NULL;
					if(body){
						p = apreq_args_get(h,  key);
					}else{
						p = apreq_body_get(h,  key);
					}

					if(p)
					{
						PUSH_PARAM_OBJECT(p);
					}else
						lua_pushnil(L);
					return 1;
				}else if(lua_isstring(L, 3))
				{
					size_t nlen, vlen;
					const char* name = luaL_checklstring(L,2,&nlen);
					const char* value = luaL_checklstring(L,2, &vlen);
					apreq_param_t *p = apreq_param_make(h->pool, name, nlen, value, vlen);

					return PUSH_PARAM_OBJECT(p);
				}
			}else{
				apreq_param_t* p = apreq_param  (h,  key);
				if(p)
				{
					PUSH_PARAM_OBJECT(p);
				}else
					lua_pushnil(L);
				return 1;
			}
		}
	}

	return 1;
}


static int ap2req_upload(lua_State*L) {
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	int top = lua_gettop(L);
	const apr_table_t *t = NULL;
	int start = 0, ret = 0;

	if(lua_isuserdata(L,2))
	{
		t = ap_lua_check_apr_table(L, 2);
		start = 3;
	}else{
		apr_status_t s = apreq_body(h, &t);
		if(s!=APR_SUCCESS)
			return ml_push_status(L,s);
		start = 2;
	}
	if(top<start)
	{
		ap_lua_push_apr_table(L, (apr_table_t *)apreq_uploads  (t,  h->pool));
		return 1;
	}
	while(start<=top)
	{
		const char* name = luaL_checkstring(L,3);
		const apreq_param_t* p = apreq_upload(t, name);
		if(p){
			PUSH_PARAM_OBJECT(p);
		}else
			lua_pushnil(L);
		start++;
		ret++;
	}
	return ret;
}

//////////////////////////////////////////////////////////////////////////


static int ap2req_param_decode(lua_State*L) {
	size_t len;
	apr_status_t rc;
	apreq_param_t *p;
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	const char* word = luaL_checklstring(L, 2, &len);
	size_t nlen = luaL_optint(L, 3, 0);
	size_t vlen = luaL_optint(L, 4, 0);
	//Url-decodes a name=value pair into a param.

	if(nlen==0)
	{
		const char* pos = strchr(word,'=');
		nlen = pos - word;
	}
	if(vlen==0)
	{
		vlen = len - nlen - 1;
	}

	assert(len == nlen + vlen + 1);

	rc = apreq_param_decode(&p, h->pool, word, nlen, vlen);
	if(rc==APR_SUCCESS) {
		PUSH_PARAM_OBJECT(p);
	} else
		lua_pushnil(L);

	lua_pushinteger(L, rc);
	return 2;
}

static int ap2req_params_as_string(lua_State*L) {
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	apr_table_t *t = ap_lua_check_apr_table(L, 2);
	const char* key = luaL_checkstring(L,3);
	apreq_join_t mode = luaL_optint(L,4,APREQ_JOIN_AS_IS);

	const char* string = apreq_params_as_string  (h->pool, t, key, mode);

	lua_pushstring(L, string);
	return 1;
}

static int ap2req_parse_query_string(lua_State*L) {
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	apr_table_t *t = ap_lua_check_apr_table(L, 2);
	const char* query = luaL_checkstring(L,3);

	apr_status_t rc = apreq_parse_query_string  ( h->pool,  t,  query ) ;

	lua_pushinteger(L,rc);
	return 1;
}

static int ap2req_value_to_param(lua_State*L) {
    apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
    const char* value = luaL_checkstring(L,2);
    apreq_param_t* p = apreq_value_to_param  (value); 
    (void*)h;
    return PUSH_PARAM_OBJECT(p);
}



/************************************************************************/
/*  mod_luaex object                                                       */
/************************************************************************/

static int ap2req_brigade_limit(lua_State*L)
{
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	if(lua_gettop(L)==2)
	{
		apr_size_t bytes;

		apr_status_t rc = apreq_brigade_limit_get  (  h,  &bytes );
		if(rc==APR_SUCCESS)
			lua_pushinteger(L, bytes);
		else
			lua_pushnil(L);
		return 1;
	}else
	{
		apr_size_t bytes = luaL_checkint(L,2);

		apr_status_t rc = apreq_brigade_limit_set  (h, bytes);
		if(rc==APR_SUCCESS)
		    lua_pushboolean(L,1);
		else{
		    lua_pushnil(L);
		    lua_pushinteger(L, rc);
		}
		return 2;
	}
}


static int ap2req_read_limit(lua_State*L)
{
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);	
	if(lua_gettop(L)==0)
	{
		apr_uint64_t l = luaL_checkint(L, 2);	

		apr_status_t rc = apreq_read_limit_set(h,l);
		lua_pushinteger(L,rc);
		return 1;
	}else
	{
		apr_uint64_t limit;

		apr_status_t rc = apreq_read_limit_get(h, &limit);
		if(rc==APR_SUCCESS)
		{
			lua_pushinteger(L, (apr_uint32_t)limit);
		}
		else
			lua_pushnil(L);
		lua_pushinteger(L, rc);
		return 2;
	}
}

static int ap2req_temp_dir(lua_State*L)
{
	apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
	if (lua_gettop(L)==2)
	{
		const char* path = luaL_checkstring(L, 2);	

		apr_status_t rc = apreq_temp_dir_set(h,path);
		lua_pushinteger(L,rc);
		return 1;
	}else
	{
		const char* path;

		apr_status_t rc = apreq_temp_dir_get(h, &path);
		if(rc==APR_SUCCESS)
			lua_pushstring(L, path);
		else
			lua_pushnil(L);
		return 1;
	}
}

static int apreq_tostring(lua_State*L){
    apreq_handle_t *h = CHECK_APREQ_OBJECT(1);
    lua_pushfstring(L, "apreq_handle(%p)", h);
    return 1;
};

/************************************************************************/
/*                                                                      */
/************************************************************************/

static luaL_reg apreq_libs[] = {
    { "strerror",           ap2req_strerror },
    { "atoi64f",            ap2req_atoi64f },
    { "atoi64t",            ap2req_atoi64t },

    { "charset_divine",     ap2req_charset_divine },
    { "cp1252_to_utf8",     ap2req_cp1252_to_utf8 },

    { "decode",             ap2req_decode },
    { "encode",             ap2req_encode },
    { "escape",             ap2req_escape },
    { "header_attribute",   ap2req_header_attribute },

    { "index",              ap2req_index },
    { "quote",              ap2req_quote },
    { "quote_once",         ap2req_quote_once },
    { "unescape",           ap2req_unescape },
    { "is_error",           ap2req_module_status_is_error },
    {NULL,          NULL},
};

static int ml_functions(lua_State *L)
{
    request_rec *r = CHECK_REQUEST_OBJECT(1);
    apr_hash_t *dispatch;
    apr_hash_index_t *iter;
    lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
    dispatch = lua_touserdata(L, -1);
    lua_pop(L, 1);
    assert(dispatch);

    lua_newtable(L);
    for(iter = apr_hash_first(r->pool, dispatch); iter; iter = apr_hash_next(iter)){
	    const char* key;
	    apr_ssize_t klen;
	    lua_CFunction func;

	    apr_hash_this(iter, (const void**)&key, &klen, (void**)&func);
	    lua_pushlstring(L,key,klen);
	    lua_pushcfunction(L,func);
	    lua_rawset(L,-3);
    }
    return 1;
}

int lua_apreq_bucket (lua_State *L);

int ml_luaopen_apreq(lua_State *L, apr_pool_t *p) {
    apr_hash_t *dispatch;
    luaL_register(L, "apreq", apreq_libs);

    luaL_newmetatable(L, "mod_luaex.cookie");
    luaL_register(L, NULL, cookie_mlibs);
    luaL_newmetatable(L, "mod_luaex.param");
    luaL_register(L, NULL,param_mlibs);

    
    lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
    dispatch = lua_touserdata(L, -1);
    lua_pop(L, 1);
    assert(dispatch);

    /* cookies function */
    apr_hash_set(dispatch, "cookie", APR_HASH_KEY_STRING, ml_makefun(&ap2req_cookie_make, APL_REQ_FUNTYPE_LUACFUN, p));
    /* param function */
    apr_hash_set(dispatch, "param",  APR_HASH_KEY_STRING, ml_makefun(&ap2req_param, APL_REQ_FUNTYPE_LUACFUN, p));
    /* upload function */
    apr_hash_set(dispatch, "upload", APR_HASH_KEY_STRING, ml_makefun(&ap2req_upload, APL_REQ_FUNTYPE_LUACFUN, p));


    apr_hash_set(dispatch, "param_decode", APR_HASH_KEY_STRING, ml_makefun(&ap2req_param_decode, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "param_as_string", APR_HASH_KEY_STRING, ml_makefun(&ap2req_params_as_string, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "parse_query_string", APR_HASH_KEY_STRING, ml_makefun(&ap2req_parse_query_string, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "value_to_param", APR_HASH_KEY_STRING, ml_makefun(&ap2req_value_to_param, APL_REQ_FUNTYPE_LUACFUN, p));



    apr_hash_set(dispatch, "brigade_limit", APR_HASH_KEY_STRING, ml_makefun(&ap2req_brigade_limit, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "bucket", APR_HASH_KEY_STRING, ml_makefun(&lua_apreq_bucket, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "read_limit", APR_HASH_KEY_STRING, ml_makefun(&ap2req_read_limit, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "temp_dir", APR_HASH_KEY_STRING, ml_makefun(&ap2req_temp_dir, APL_REQ_FUNTYPE_LUACFUN, p));

    apr_hash_set(dispatch, "pointer", APR_HASH_KEY_STRING, ml_makefun(&apreq_tostring, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "functions", APR_HASH_KEY_STRING, ml_makefun(&ml_functions, APL_REQ_FUNTYPE_LUACFUN, p));

    return 0;
}

