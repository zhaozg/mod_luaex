# An Apache module to extend mod\_lua

mod\_luaex is a module for apache2 that extends [mod_lua](http://httpd.apache.org/docs/2.4/mod/mod_lua.html) to support socache, session, filter and other, making it more flexible.

## Introduction

Back in 2005, I began writing my own [mod_lua](https://sourceforge.net/projects/mod-lua/), inspired by mod_python. A few years later I was glad to see the official mod_lua came out. Because some functionality is missing in the official version, I need to write a ext module. 

mod\_luaex does not replace mod\_lua, it works after mod\_lua is enabled and actived. mod\_luaex depends on mod\_lua, as well as mod\_dbd, mod_session and mod\_socache.

The target environment is Apache HTTPd 2.4

## Build

### patch mod\_lua with [patch](mod_lua.patch)

Please see mod\_lua.patch to view what changed. 

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

### mod_lua
[mod_lua](http://httpd.apache.org/docs/2.4/mod/mod_lua.html)

### mod_luaex
need to add

## Bug

### mod_lua
[all lists](https://bz.apache.org/bugzilla/buglist.cgi?bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED&bug_status=NEEDINFO&component=mod_lua&product=Apache%20httpd-2&query_format=advanced)  
[Bug 60419](https://bz.apache.org/bugzilla/show_bug.cgi?id=60419) will make lua filter not work, you can given LuaInherit to avoid it.  
[Bug 51001](https://bz.apache.org/bugzilla/show_bug.cgi?id=51001) not hook hook ap\_lua\_run\_lua\_open at all.  

please see [patch](mod_lua.patch) to solve it partially.

### mod_luaex
[issues](https://github.com/zhaozg/mod_luaex/issues)

## License

This software is provided under the same license as Apache.
