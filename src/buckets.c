#include "mod_luaex.h"

static int brigade_destory(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_status_t rc = apr_brigade_destroy(bb);
	lua_pushinteger(L,rc);
	return 1;
}

static int brigade_cleanup(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_status_t rc = apr_brigade_cleanup(bb);
	lua_pushinteger(L,rc);
	return 1;
}

static int brigade_split(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_bucket *b = (apr_bucket *)CHECK_BUCKET_OBJECT(2);
	apr_bucket_brigade *bbb = apr_brigade_split(bb,b);

    return PUSH_BUCKETBRIGADE_OBJECT(bbb);
}

static int brigade_partition(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_off_t point = luaL_checkint(L,2);
	apr_bucket * b = NULL;

	apr_status_t rc = apr_brigade_partition(bb,point, &b);
	if(rc==APR_SUCCESS)
	{
        PUSH_BUCKET_OBJECT(b);
	}else
	{
		lua_pushnil(L);
	}

	lua_pushinteger(L, rc);
	return 2;
}

#if APR_NOT_DONE_YET
/**
* consume nbytes from beginning of b -- call apr_bucket_destroy as
* appropriate, and/or modify start on last element 
* @param b The brigade to consume data from
* @param nbytes The number of bytes to consume
*/
APU_DECLARE(void) apr_brigade_consume(apr_bucket_brigade *b,
									  apr_off_t nbytes);
static int brigade_consume(lua_State*L)
{
	apr_bucket_brigade *bb = CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_off_t nbytes = luaL_checkint(L,2);

	apr_brigade_consume(bb,nbytes);

	return 0;
}
#endif

static int brigade_length(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade*)CHECK_BUCKETBRIGADE_OBJECT(1);
	int read_all = lua_isnoneornil(L,2) ? 1 : lua_toboolean(L, 2);
	apr_off_t length = 0;

	apr_status_t rc = apr_brigade_length(bb, read_all, &length);
	lua_pushinteger(L, (lua_Integer)length);
	lua_pushinteger(L, rc);
	return 2;
}

static int brigade_flatten(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade*)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_off_t off = luaL_optinteger(L,2, 0);
	apr_status_t rc = off==0 ? 0 : apr_brigade_length(bb, 1, &off);
	apr_size_t len = (apr_size_t)off;
	if(rc==APR_SUCCESS)
	{
		char* buf = apr_bucket_alloc(len, bb->bucket_alloc);

		rc = apr_brigade_flatten(bb, buf, &len);
		if(rc==APR_SUCCESS)
		{
			lua_pushlstring(L,buf, len);
		}else
		{
			lua_pushnil(L);
		}
		apr_bucket_free(buf);
	}else
	{
		lua_pushnil(L);
	}
	lua_pushinteger(L,rc);
	return 2;
}

static int brigade_pflatten(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade*) CHECK_BUCKETBRIGADE_OBJECT(1);
    request_rec *r = CHECK_REQUEST_OBJECT(2);
	apr_size_t len = luaL_checkint(L,3);
	char* c;

	apr_status_t rc = apr_brigade_pflatten(bb, &c, &len, r->pool);
	if(rc==APR_SUCCESS)
	{
		lua_pushlstring(L,c,len);
	}else
	{
		lua_pushnil(L);
	}
	lua_pushinteger(L,rc);
	return 2;
}


/**
* Split a brigade to represent one LF line.
* @param bbOut The bucket brigade that will have the LF line appended to.
* @param bbIn The input bucket brigade to search for a LF-line.
* @param block The blocking mode to be used to split the line.
* @param maxbytes The maximum bytes to read.  If this many bytes are seen
*                 without a LF, the brigade will contain a partial line.
*/

static int brigade_split_line(lua_State*L)
{
	apr_bucket_brigade *bbout = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	apr_bucket_brigade *bbin = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(2);
	apr_read_type_e block = luaL_checkint(L,3);
	apr_off_t maxbytes = luaL_checkint(L,4);
	apr_status_t rc = apr_brigade_split_line(bbout,bbin,block,maxbytes);
	lua_pushinteger(L,rc);
	return 1;
}


/**
* create an iovec of the elements in a bucket_brigade... return number 
* of elements used.  This is useful for writing to a file or to the
* network efficiently.
* @param b The bucket brigade to create the iovec from
* @param vec The iovec to create
* @param nvec The number of elements in the iovec. On return, it is the
*             number of iovec elements actually filled out.
*/
//APU_DECLARE(apr_status_t) apr_brigade_to_iovec(apr_bucket_brigade *b, struct iovec *vec, int *nvec);

/**
* This function writes a list of strings into a bucket brigade. 
* @param b The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param va A list of strings to add
* @return APR_SUCCESS or error code.
*/
// 不能从lua中直接调用
/*
APU_DECLARE(apr_status_t) apr_brigade_vputstrs(apr_bucket_brigade *b,
	apr_brigade_flush flush,
	void *ctx,
	va_list va);
*/


/**
* This function writes a string into a bucket brigade.
* @param b The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param str The string to add
* @param nbyte The number of bytes to write
* @return APR_SUCCESS or error code
*/

static int brigade_write(lua_State*L)
{
	apr_size_t nbyte;
	apr_status_t rc;
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	const char* str = luaL_checklstring(L,2,&nbyte);
	nbyte = luaL_optinteger(L,3,nbyte);

	rc = apr_brigade_write(bb, NULL,NULL, str,nbyte);
	lua_pushinteger(L,rc);
	return 1;
}


/**
* This function writes multiple strings into a bucket brigade.
* @param b The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param vec The strings to add (address plus length for each)
* @param nvec The number of entries in iovec
* @return APR_SUCCESS or error code
*/
// 不能从lua中直接调用
/*
APU_DECLARE(apr_status_t) apr_brigade_writev(apr_bucket_brigade *b,
											 apr_brigade_flush flush,
											 void *ctx,
											 const struct iovec *vec,
											 apr_size_t nvec);
*
/**
* This function writes a string into a bucket brigade.
* @param bb The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param str The string to add
* @return APR_SUCCESS or error code
*/

static int brigade_puts(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *)CHECK_BUCKETBRIGADE_OBJECT(1);
	const char* str = luaL_checkstring(L,2);

	apr_status_t rc = apr_brigade_puts(bb, NULL,NULL, str);
	lua_pushinteger(L,rc);
	return 1;
}

/**
* This function writes a character into a bucket brigade.
* @param b The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param c The character to add
* @return APR_SUCCESS or error code
*/

static int brigade_putc(lua_State*L)
{
	apr_bucket_brigade *bb = (apr_bucket_brigade *) CHECK_BUCKETBRIGADE_OBJECT(1);
	const char c = (const char)luaL_checkint(L,2);

	apr_status_t rc = apr_brigade_putc(bb, NULL,NULL, c);
	lua_pushinteger(L,rc);
	return 1;
}

/**
* This function writes an unspecified number of strings into a bucket brigade.
* @param b The bucket brigade to add to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param ... The strings to add
* @return APR_SUCCESS or error code
*/
// 不能从lua中直接调用
/*
APU_DECLARE_NONSTD(apr_status_t) apr_brigade_putstrs(apr_bucket_brigade *b,
													 apr_brigade_flush flush,
													 void *ctx, ...);
*/
/**
* Evaluate a printf and put the resulting string at the end 
* of the bucket brigade.
* @param b The brigade to write to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param fmt The format of the string to write
* @param ... The arguments to fill out the format
* @return APR_SUCCESS or error code
*/
/*
APU_DECLARE_NONSTD(apr_status_t) apr_brigade_printf(apr_bucket_brigade *b, 
													apr_brigade_flush flush,
													void *ctx,
													const char *fmt, ...)
													__attribute__((format(printf,4,5)));
*/
/**
* Evaluate a printf and put the resulting string at the end 
* of the bucket brigade.
* @param b The brigade to write to
* @param flush The flush function to use if the brigade is full
* @param ctx The structure to pass to the flush function
* @param fmt The format of the string to write
* @param va The arguments to fill out the format
* @return APR_SUCCESS or error code
*/
/*
APU_DECLARE(apr_status_t) apr_brigade_vprintf(apr_bucket_brigade *b, 
											  apr_brigade_flush flush,
											  void *ctx,
											  const char *fmt, va_list va);
*/
static luaL_reg bb_libs[] = {
	{"destory",			brigade_destory},
	{"cleanup",			brigade_cleanup},
	{"split",			brigade_split},		//%
	{"partitiion",		brigade_partition},
	{"length",			brigade_length},	//#
	{"flatten",			brigade_flatten},
	{"pflatten",		brigade_pflatten},
	{"split_line",		brigade_split_line},
	{"write",			brigade_write}
	,
	{"puts",			brigade_puts},	//+
	{"putc",			brigade_putc},	//+
       
	{NULL,          NULL}
};

static int brigade_tostring(lua_State *L)
{
    apr_bucket_brigade *bb = CHECK_BUCKETBRIGADE_OBJECT(1);

    lua_pushfstring(L, "apr_bucket_brigade(%p)",bb);

    return 1;
}

static luaL_reg bb_mlibs[] = {
    {"__tostring",          brigade_tostring},
    {NULL,          NULL}
};

/*
** Register binding functions and the constants.
** All of them use the request_rec as an upvalue.
** Leaves the table on top of the stack.
*/

int lua_apreq_bucket (lua_State *L) {
    apreq_handle_t* h = CHECK_APREQ_OBJECT(1);

    return PUSH_BUCKET_OBJECT(apr_brigade_create(h->pool,h->bucket_alloc));
    return 1;
}

int ml_luaopen_buckets(lua_State *L) {
    luaL_newmetatable(L, "mod_luaex.bucketbrigade");
    luaL_register(L, NULL,bb_mlibs);
    lua_pushstring(L,"__index");
    lua_newtable(L);
    luaL_register(L, NULL, bb_libs);
    lua_settable(L,-3);
    luaL_newmetatable(L, "mod_luaex.bucket");
    return 0;
}
