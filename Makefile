HTTPSRC	?= ../httpd-2.4.23
HTTPDST	?= /usr/local/httpd

APXS=$(HTTPDST)/bin/apxs -i -a -c -n luaex -I$(HTTPSRC)/include -I$(HTTPSRC)/modules/lua
SRC=src/mod_luaex.c src/extends.c  src/request.c

all:
	$(APXS) -DWall $(SRC)

clean:
	-rm -f mod_luaex.o mod_luaex.lo mod_luaex.slo mod_luaex.la 
	-rm -f $(shared)
	-rm -f $(patsubst %.c,%.lo, $(SRC))
	-rm -f $(patsubst %.c,%.slo,$(SRC))
	-rm -f $(patsubst %.c,%.o,  $(SRC))
	-rm src/.libs -rf
