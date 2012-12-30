

#   the used tools
APXS=apxs
APACHECTL=apachectl
HTTPDSRC=/mnt/hgfs/httpd

SRC=src/mod_luaex.c src/apreq.c src/buckets.c src/extends.c src/handle.c src/modules.c src/request.c src/reslist.c src/server.c src/service.c src/table.c \
src/apreq2/cookie.c src/apreq2/module.c src/apreq2/parser.c src/apreq2/parser_multipart.c src/apreq2/util.c src/apreq2/error.c src/apreq2/param.c \
src/apreq2/parser_header.c src/apreq2/parser_urlencoded.c  src/apreq2/version.c

###############################################################################################
#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
INCLUDES=-I$(HTTPDSRC)/modules/lua -Isrc/apreq2
LIBS=-L/usr/local/lib -lluajit-5.1 -lapr-2

shared=mod_luaex.so

#   the default target
all: $(shared)

$(shared):	$(SRC)
	$(APXS) -DWall  $(INCLUDES) $(LIBS) $(SRC)

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

