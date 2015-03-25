#
#
#

lib = \
	lib/bluetooth.o \
	lib/hci.o \
	lib/sdp.o

hciattach-objs = \
	hciattach.o \
	hciattach_ath3k.o \
	hciattach_bcm43xx.o \
	hciattach_intel.o \
	hciattach_qualcomm.o \
	hciattach_st.o \
	hciattach_ti.o \
	hciattach_tialt.o

hciconfig-objs = \
	hciconfig.o \
	csr.o

hcitool-objs = \
	hcitool.o \
	src/oui.o

CFLAGS = -I. -Ilib -Wall

all: hciattach hciconfig hcitool

hciattach: $(hciattach-objs) $(lib)
	$(CC) -o $@ $^

hciconfig: $(hciconfig-objs) $(lib)
	$(CC) -o $@ $^

hcitool: $(hcitool-objs) $(lib)
	$(CC) -o $@ $^

clean:
	-rm -f hciattach $(hciattach-objs)
	-rm -f hciconfig $(hcicofig-objs)
	-rm -f hcitool $(hcitool-objs)
	-rm -f $(lib)

install: hciattach hciconfig hcitool
	install -m 755 hciattach $(DESTDIR)/sbin/hciattach
	install -m 755 hciconfig $(DESTDIR)/sbin/hciconfig
	install -m 755 hcitool $(DESTDIR)/bin/hcitool
