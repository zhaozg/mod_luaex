# An Apache module to extend mod_lua

mod_luaex is a module for apache2 that extends mod_lua (http://httpd.apache.org/docs/2.4/mod/mod_lua.html) to support socache, session, dbd, filter and other, making it more flexible.


## Introduction

   Back in 2005, I began writing my own Lua module (http://mod-lua.sourceforge.net), inspired by mod_python. A few years later I was glad to see the official mod_lua came out.
 Because some functionality is missing in the official version, I wanted to write a module that extends it. 
 Lua/APR is a good binding of the Apache Portable Runtime (APR) for Lua, so I embedded it in mod_luaex.

   mod_luaex does not replace mod_lua, it works after mod_lua is enabled and active. mod_luaex depends on mod_lua, as well as mod_dbd, mod_session and mod_socache.
   The target environment is Apache HTTPd 2.4

## How to get and install the binding

### patch mod_lua with patch.txt

  Please see mod_lua.patch to view what changed.

### Build on Windows with MSVC IDE.

   Open build\mod_luaex.vcproj with MSVC 2008 or 2010.

### Build on UNIX using makefile

   Please wait until it is finished.

### Build on Windows using makefile

  1) Change setting in config.win
  2) nmake -f makefile.win

## API

  mod_luaex extends Apache's mod_lua, adding more APIs, such as apreq, apr-dbd, and so on.

### The request\_rec fields supplied by mod\_lua.	

####functions
    puts, write, parseargs, parsebody, add_output_filter*, construct_url,escape_html, ssl_var_lookup,
    debug, info, notice, warn, err, crit, alert, emerg, trace1, trace2, trace3, trace4, trace5, trace6, trace7, trace8

####strings
    document_root, protocol, content_type, content_encoding, ap_auth_type, unparsed_uri, filename,
    canonical_filename, path_info, args, handler, hostname, req_uri_field, uri, the_request, method, proxyreq

####boolean
    is_https, assbackwards

####integer
    status
    
####table
    headers_in, headers_out, err_headers_out, notes, subprocess_env

### The request\_rec fields added by mod\_luaex.	



### cookie object

#### r:cookie()	  -- it will return an apr_table with cookie key and value
#### r:cookie(boolean)
	if the arg is false, it will return a cookies key and value as apr_table object
	if the arg is true, it will return a table, name and cookie object key pair
#### r:cookie('key','value'[, {}]   --will make a new cookie
      option table supports the params below
      path;        /**< Restricts URL path */
      domain;      /**< Restricts server domain */
      port;        /**< Restricts server port */
      comment;     /**< RFC cookies may send a comment */
      commentURL;  /**< RFC cookies may place an URL here */
      max_age;     /**< total duration of cookie: -1 == session */
      flags;       /**< charsets, taint marks, app-specific bits */
      charsets, tainted, secure
#### r:cookie('name')        --will get the cookie value
#### r:cookie('cookievalstr',false) --will parse a cookie string and make a new cookie
#### r:cookie('cookiestrinheader',true) -- will return a table which stores cookie objects

### param

#### r:param()	    -- it will return an apr_table with param key and value
#### r:param(boolean)
         if the arg is false, it will return an apr_table with query key and value, apreq_args
         if the arg is true, it will return an apr_table with post key and value, apreq_body
#### r:param('key','value') -- it will make a param object with key and value
#### r:param(key)   -- it will return a param object
#### r:param(key,false)	 -- it will return a query param object
#### r:param(key,true)   -- it will return a POST param object

### upload

#### r:upload([apr_table])
	it will return an apr_table with param which contains upload part
	if the argument apr_table is not given, it will be obtained from apreq_body()
#### r:upload([apr_table],...)
	it will return a multi param object which contains upload part
	arg must be a string as name

### dbd

## Status

## Contact

If you have questions, bug reports, suggestions, etc. the author can be contacted at <zhaozg@gmail.com>.

## License

This software is provided under the same license as Apache.

Third party code [Lua/APR]
Lua/APR was written in 2011 by Peter Odding (<peter@peterodding.com>) and a few by zhiguo zhao (<zhaozg@gmail.com>).
[Lua/APR]: http://peterodding.com/code/lua/apr/
