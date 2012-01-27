##############################################
#
# mod_lua Makefile V0.5 by zhaozg@nutstech.com
#
##############################################

APXS=/opt/bin/apxs 
APXSFLAGS=-c -i -a -Wc,-O8 -Wc,-Wall
APXSFLAGS=-c -Wc,-O8 -Wc,-Wall -l lua -L /opt/lib
SRC=mod_lua.c apache2_lib.c storage_shmht.c storage_shmcb.c storage_util_table.c lhtml_compile.c storage_dbm.c storage_util.c storage_util_mutex.c 

all: mod_lua


mod_lua: $(SRC)
	echo $(APXS) $(APXSFLAGS) $(SRC) 
	$(APXS) $(APXSFLAGS) $(SRC) 

clean:
	rm -r *.la *.slo *.o  *.lo .libs

