#manfeel, port wifidog to ralink sdk
OBJS = api.o ip_acl.o protocol.o version.o
 
LIBRARY = libhttpd.a

all: $(LIBRARY)
 
test:
 
romfs:
 
$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@
 
clean::
	$(RM) $(OBJS) $(LIBRARY)
