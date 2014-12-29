#manfeel, port wifidog to ralink sdk
DIRS = libhttpd src
 
all romfs:
	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done
 
clean:
	for i in $(DIRS) ; do make -C $$i clean ; done
