#   the used tools
APXS=apxs -i -a -c -n luaex
APACHECTL=apachectl
HTTPDSRC=../httpd-2.4.10

SRC=src/mod_luaex.c src/apreq.c src/buckets.c src/extends.c src/handle.c src/modules.c src/request.c src/reslist.c src/server.c src/service.c src/table.c \
src/apreq2/cookie.c src/apreq2/module.c src/apreq2/parser.c src/apreq2/parser_multipart.c src/apreq2/util.c src/apreq2/error.c src/apreq2/param.c \
src/apreq2/parser_header.c src/apreq2/parser_urlencoded.c  src/apreq2/version.c

###############################################################################################
#   additional defines, includes and libraries
LUA_VERSION = $(shell pkg-config luajit --print-provides)
LUA_LIBPATH=/usr/local/lib/lua/5.1/
ifeq ($(LUA_VERSION),)
LUA_CFLAGS=$(shell pkg-config lua --cflags)
LUA_LIBS=$(shell pkg-config lua --libs)
else
LUA_CFLAGS=$(shell pkg-config luajit --cflags)
LUA_LIBS=$(shell pkg-config luajit --libs)
endif

LUA_APR=/usr/local/lib/liblua_apr.a

exist = $(shell if [ -f $(LUA_APR) ]; then echo "exist"; else echo "notexist"; fi;)
ifeq ($(exist), exist)
LUA_LIBS+=$(LUA_APR)
LUA_CFLAGS+=-DLUA_APR_DECLARE_STATIC -DSUPPORT_MOD_DBD 
endif


INCLUDES=-I$(HTTPDSRC)/modules/lua -Isrc/apreq2 $(LUA_CFLAGS)
LIBS=$(LUA_LIBS)
CFLAGS+=$(LUA_CFLAGS)

shared=mod_luaex.so

#   the default target
all: $(shared)
	echo exist = $(shell if [ -f $(LUA_APR) ]; then echo "exist"; else echo "notexist"; fi;)

$(shared):	$(SRC)
	$(APXS) -DWall $(INCLUDES) $(LIBS) $(SRC) $(LUA_APR) /usr/local/modules/mod_lua.so

#   cleanup
clean:
	-rm -f mod_luaex.o mod_luaex.lo mod_luaex.slo mod_luaex.la 
	-rm -f $(shared)
	-rm -f $(patsubst %.c,%.lo, $(SRC))
	-rm -f $(patsubst %.c,%.slo,$(SRC))
	-rm -f $(patsubst %.c,%.o,  $(SRC))
	-rm src/.libs -rf
	-rm src/apreq2/.libs -rf

install:
	cp src/.libs/mod_luaex.so /usr/local/modules

#   simple test
test: reload
	lynx -mime_header http://localhost/luaex

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

