APXS=apxs
HTTPDSRC=/mnt/hgfs/httpd
APXSFLAGS=-c -Wc,-O8 -Wc,-Wall -llua-5.1  -I$(HTTPDSRC)/modules/lua -Isrc -Isrc/apreq2
SRC=src/apreq.c  src/buckets.c  src/extends.c  src/handle.c  src/mod_luaex.c  src/modules.c  src/request.c  src/reslist.c  src/server.c  src/service.c  src/table.c \
src/apreq2/cookie.c  src/apreq2/module.c      src/apreq2/module_custom.c  src/apreq2/parser.c         src/apreq2/parser_multipart.c   src/apreq2/util.c \
src/apreq2/error.c   src/apreq2/module_cgi.c  src/apreq2/param.c          src/apreq2/parser_header.c  src/apreq2/parser_urlencoded.c  src/apreq2/version.c
 


all: mod_lua


mod_lua: $(SRC)
	$(APXS) $(APXSFLAGS) $(SRC) 

clean:
	cd src
	rm -r *.la *.slo *.o  *.lo .libs

