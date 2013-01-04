# An apache module to extend mod_lua

mod_luaex is a module for apache2, which extend mod_lua(http://httpd.apache.org/docs/2.4/mod/mod_lua.html) to support socache, session, dbd, filter and other, so more flexible.


## Introduce

   In 2005 year, I begin write a lua modlue(http://mod-lua.sourceforge.net), inspired by mod_python. Some years pass, I glad to see office mod_lua appreas.
 But officer version not fully function. So I want to write a module which extend office version. mod_luaex not to replace mod_lua, mod_luaex works after active mod_lua.
 Lua/APR is a good apr bind for lua, So I embed Lua/APR in mod_luaex.

   mod_luaex depends on mod_lua, mod_dbd, mod_session,  mod_socache.
   Target apache version is httpd 2.4

## How to get and install the binding

### patch mod_lua with patch.txt

  Index: lua_vmprep.c

  ===================================================================

  --- lua_vmprep.c  (revision 1428708)

  +++ lua_vmprep.c  (working copy)

  @@ -320,7 +320,13 @@

                : lua_tostring(L, 0));
		     return APR_EBADF;
		 }
	-        lua_pcall(L, 0, LUA_MULTRET, 0);
	+        rc = lua_pcall(L, 0, LUA_MULTRET, 0);
	+		if(rc!=0){
	+			printf(
	+				"Error compilre %s: %s", spec->file,
	+				rc == LUA_ERRMEM ? "memory allocation error"
	+				: lua_tostring(L, -1));
	+		}
	     }
	
	 #ifdef AP_ENABLE_LUAJIT
	Index: mod_lua.c

	===================================================================

	--- mod_lua.c	(revision 1428708)

	+++ mod_lua.c	(working copy)

	@@ -82,11 +82,11 @@

	     ap_lua_load_apache2_lmodule(L);
	     ap_lua_load_request_lmodule(L, p);
	     ap_lua_load_config_lmodule(L);
	+	ap_lua_run_lua_open(L, p);
	 }
	
	 static int lua_open_hook(lua_State *L, apr_pool_t *p)
	 {
	-    lua_open_callback(L, p, NULL);
	     return OK;
	 }
	


### Build on Windows with MSVC IDE.

   Open build\mod_luaex.vcproj with MSVC 2008 or 2010.

### Build on UNIX using makefile

   Please wait for finished.

### Build on Windows using makefile

  1) change setting in config.win
  2) nmake -f makefile.win

## API

  mod_luaex extends mod_lua in apache, which add more apis, e.g. apreq, apr-dbd, and so on.

### The fields of request\_rec supplied mod\_lua.	

#### functions
    puts, write, parseargs, parsebody,add_output_filter*,construct_url,escape_html,ssl_var_lookup,
    debug,info,notice,warn,err,crit,alert,emerg,trace1,trace2,trace3,trace4,trace5,trace6,trace7,trace8

####strings
    document_root,protocol,content_type,content_encoding,ap_auth_type,unparsed_uri,filename,
    canonical_filename,path_info,args,handler,hostname,req_uri_field,uri,the_request,method,proxyreq

####boolean
    is_https,assbackwards

####integer
    status
####table
    headers_in,headers_out,err_headers_out,notes,subprocess_env

### The fields of request\_rec supplied mod\_luaex.	



### cookie object

#### r:cookie()	  -- it will return an apr_table with cookie key and value
#### r:cookie(boolean)
	if arg is false, it will return an cookies key and value as apr_table object
	if arg is true, it will return an table,name and cookie object keypaire
#### r:cookie('key','value'[, {}]   --will make a new cookie
      option table support below params
      path;        /**< Restricts url path */
      domain;      /**< Restricts server domain */
      port;        /**< Restricts server port */
      comment;     /**< RFC cookies may send a comment */
      commentURL;  /**< RFC cookies may place an URL here */
      max_age;     /**< total duration of cookie: -1 == session */
      flags;       /**< charsets, taint marks, app-specific bits */
      charsets, tainted, secure
#### r:cookie('name')        --will get cookie value
#### r:cookie('cookievalstr',false) --will parse cookie string and make a new cookie
#### r:cookie('cookiestrinheader',true) -- will return a table which store cookie objects

### param

#### r:param()	    -- it will return an apr_table with param key and value
#### r:param(boolean)
         if arg is false, it will return an apr_table with query key and value, apreq_args
         if arg is true, it will return an apr_table with post key and value, apreq_body
#### r:param('key','value') -- it will make a param object wich key and value
#### r:param(key)   -- it will return an param object
#### r:param(key,false)	 -- it will return an query param object
#### r:param(key,true)   -- it will return an post param object

### upload

#### r:upload([apr_table])
	it will return an apr_table with param which has upload part
	if argument apr_table not given, it will be get by apreq_body()
#### r:upload([apr_table],...)
	it will return multi param object which contains upload part
	arg must be string as name

### dbd

## Status

## Contact

If you have questions, bug reports, suggestions, etc. the author can be contacted at <zhaozg@gmail.com>.

## License

This software keep same license with apache.

Third party code [Lua/APR]
Lua/APR is write by 2011 Peter Odding (<peter@peterodding.com>) and a few by zhiguo zhao (<zhaozg@gmail.com>).
[Lua/APR]: http://peterodding.com/code/lua/apr/