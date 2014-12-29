#manfeel, port wifidog to ralink sdk
WIFIDOG_OBJS = auth.o client_list.o conf.o firewall.o gateway.o httpd_thread.o safe.o \
                centralserver.o  commandline.o  debug.o  fw_iptables.o  http.o ping_thread.o util.o  wdctl_thread.o \
				extendapi.c
 
WDCTL_OBJS = wdctl.o
 
CFLAGS += -I../libhttpd
 
USELIBS = ../libhttpd/libhttpd.a
 
all: wifidog wdctl
 
test:
 
wifidog: $(WIFIDOG_OBJS) $(USELIBS)
	$(CC) $(CFLAGS)  -o $@ $(WIFIDOG_OBJS) $(USELIBS) $(LDLIBS) $(LDFLAGS) -lpthread
 
wdctl: $(WDCTL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(WDCTL_OBJS) $(LDLIBS) -lpthread
 
romfs:
	$(ROMFSINST) /usr/bin/wifidog
	$(ROMFSINST) /usr/bin/wdctl
#	$(ROMFSINST) ../fs/wifidog-init /usr/bin/wifidog-init
	$(ROMFSINST) ../wifidog.conf /etc_ro/wifidog.conf
	$(ROMFSINST) ../wifidog-msg.html /etc_ro/wifidog-msg.html
#	mkdir -p $(ROOTDIR)/romfs/etc_ro/init.d
#	$(ROMFSINST) ../scripts/init.d/wifidog /etc_ro/init.d/wifidog
 
clean:
	-rm -f $(EXEC) *.gdb *.elf *.o
