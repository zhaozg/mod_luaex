# An Apache module to extend mod_lua

mod_luaex is a module for apache2 that extends [mod_lua](http://httpd.apache.org/docs/2.4/mod/mod_lua.html) to support socache, session, filter and other, making it more flexible.

## Introduction

Back in 2005, I began writing my own [mod_lua](https://sourceforge.net/projects/mod-lua/), inspired by mod_python. A few years later I was glad to see the official mod_lua came out. Because some functionality is missing in the official version, I need to write a ext module. 

mod_luaex does not replace mod_lua, it works after mod_lua is enabled and active. mod_luaex depends on mod_lua, as well as mod_dbd, mod_session and mod_socache.

The target environment is Apache HTTPd 2.4

## How to get and install the binding

### patch mod_lua with [patch](mod_lua.patch)

Please see mod_lua.patch to view what changed. 

>cd $HTTPSRC/modules/lua
>patch < path of mod_lua.path

then recompile apache httpd and install it.

### Build on UNIX using makefile

>make HTTPSRC=...  HTTPDST=...

HTTPSRC: path to Aapche HTTPD 2.4 source dir
HTTPDST: path to Apache HTTPD 2.4 binary installed dir

### Build on Windows using makefile

1. Change setting in config.win
2. nmake -f makefile.win

## API

### The request\_rec fields supplied by mod\_lua.	

####functions
puts, write, parseargs, parsebody, add_output_filter*, construct_url,escape_html, ssl_var_lookup, debug, info, notice, warn, err, crit, alert, emerg, trace1, trace2, trace3, trace4, trace5, trace6, trace7, trace8

####strings
document_root, protocol, content_type, content_encoding, ap_auth_type, unparsed_uri, filename, canonical_filename, path_info, args, handler, hostname, req_uri_field, uri, the_request, method, proxyreq

####boolean
is_https, assbackwards

####integer
status

####table
headers_in, headers_out, err_headers_out, notes, subprocess_env

### The request\_rec fields added by mod\_luaex.	


## Contact

If you have questions, bug reports, suggestions, please mailto zhaozg(at)gmail.com.

## License

This software is provided under the same license as Apache.
