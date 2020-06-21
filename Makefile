HTTPSRC ?= ../httpd
HTTPDST ?= /usr/local/apache2
APXS    ?= $(HTTPDST)/bin/apxs
LUAINCS ?= /usr/local/include/luajit-2.1
CFLAGS  += -I$(LUAINCS) -I$(HTTPSRC)/include -I$(HTTPSRC)/modules/lua
FLAGS    = -i -a -c -n luaex $(CFLAGS) $(INCS) -lluajit-5.1 -L/usr/local/lib
SRC      = src/mod_luaex.c src/extends.c  src/request.c

all:
	$(APXS) -DWall $(FLAGS) $(SRC)

clean:
	-rm -f mod_luaex.o mod_luaex.lo mod_luaex.slo mod_luaex.la
	-rm -f $(shared)
	-rm -f $(patsubst %.c,%.lo, $(SRC))
	-rm -f $(patsubst %.c,%.slo,$(SRC))
	-rm -f $(patsubst %.c,%.o,  $(SRC))
	-rm src/.libs -rf
