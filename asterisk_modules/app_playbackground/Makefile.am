pkgdir = $(asteriskmoduledir)
pkg_LTLIBRARIES = app_playbackground.la
PROTO_BUILT_SOURCES = \
	tts.pb.cc tts.pb.h \
	tts.grpc.pb.cc tts.grpc.pb.h \
	google/api/annotations.pb.cc google/api/annotations.pb.h \
	google/api/http.pb.cc google/api/http.pb.h
BUILT_SOURCES = ../thirdparty/inst/include/grpc/grpc.h roots.pem.h $(PROTO_BUILT_SOURCES)

app_playbackground_la_SOURCES = \
	app_playbackground.c \
	stream_layers.c \
	bytequeue.cpp \
	channelbackend.cpp \
	channel.cpp \
	grpctts.cpp \
	grpctts_conf.c \
	job.cpp \
	jwt.cpp \
	$(PROTO_BUILT_SOURCES)

app_playbackground_la_CFLAGS = -Wall -pthread -O3 -Werror=implicit-function-declaration -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fPIC -DAST_MODULE=\"app_playbackground\" \
	-DASTERISK_MODULE_VERSION_STRING=\"`git describe --tags --always`\" $(OPUS_CFLAGS)
app_playbackground_la_CXXFLAGS = -Wall -pthread -O3 -std=c++11 -I../thirdparty/inst/include -fPIC $(OPUS_CFLAGS)
app_playbackground_la_LDFLAGS = -Wl,-E -pthread -g -module -avoid-version -ldl -Wl,-fuse-ld=gold \
	$(OPUS_LIBS) \
	../thirdparty/inst/lib/libprotobuf.a \
	../thirdparty/inst/lib/libprotoc.a \
	../thirdparty/inst/lib/libaddress_sorting.a \
	../thirdparty/inst/lib/libgpr.a \
	../thirdparty/inst/lib/libgrpc.a \
	../thirdparty/inst/lib/libgrpc++.a \
	../thirdparty/inst/lib/libgrpc_cronet.a \
	../thirdparty/inst/lib/libgrpc++_cronet.a \
	../thirdparty/inst/lib/libgrpc++_error_details.a \
	../thirdparty/inst/lib/libgrpc++_reflection.a \
	../thirdparty/inst/lib/libgrpc_unsecure.a \
	../thirdparty/inst/lib/libgrpc++_unsecure.a
app_playbackground_la_LIBTOOLFLAGS = --tag=disable-static

CLEANFILES=$(PROTO_BUILT_SOURCES) roots.pem.h


tts.pb.cc tts.pb.h: tts.proto
	../thirdparty/inst/bin/protoc -I . -I ../thirdparty/googleapis --cpp_out=. tts.proto

google/api/annotations.pb.cc google/api/annotations.pb.h: ../thirdparty/googleapis/google/api/annotations.proto
	../thirdparty/inst/bin/protoc -I ../thirdparty/googleapis --cpp_out=. ../thirdparty/googleapis/google/api/annotations.proto

google/api/http.pb.cc google/api/http.pb.h: ../thirdparty/googleapis/google/api/http.proto
	../thirdparty/inst/bin/protoc -I ../thirdparty/googleapis --cpp_out=. ../thirdparty/googleapis/google/api/http.proto

tts.grpc.pb.cc tts.grpc.pb.h: tts.proto
	../thirdparty/inst/bin/protoc -I . -I ../thirdparty/googleapis --grpc_out=. --plugin=protoc-gen-grpc=../thirdparty/inst/bin/grpc_cpp_plugin tts.proto


../thirdparty/inst/include/grpc/grpc.h:
	make -C ../thirdparty inst/include/grpc/grpc.h

roots.pem.h: ../thirdparty/grpc/etc/roots.pem
	echo "static unsigned char grpc_roots_pem[] = {" > roots.pem.h.tmp
	xxd -i ../thirdparty/grpc/etc/roots.pem | tail -n +2 | head -n -1 >> roots.pem.h.tmp
	mv roots.pem.h.tmp roots.pem.h

XMLDOC_FILES = app_playbackground.c

all-local: .xmldocs/app_playbackground-en_US.xml

.xmldocs/app_playbackground-en_US.xml_tmp: $(XMLDOC_FILES)
	mkdir -p .xmldocs
	@echo "Generating $@..."
	@echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > $@
	@echo "<!DOCTYPE docs SYSTEM \"appdocsxml.dtd\">" >> $@
	@echo "<docs xmlns:xi=\"http://www.w3.org/2001/XInclude\">" >> $@
	@for i in $(XMLDOC_FILES); do \
		$(AWK) -f awk_get_documentation $$i >> $@ ; \
	done ;
	@echo "</docs>" >> $@
	@echo "Generating $@ done"

.xmldocs/app_playbackground-en_US.xml: $(XMLDOC_FILES)
	echo $@_tmp
	make $@_tmp || (rm -f $@_tmp; false)
	mv $@_tmp $@

install-data-local: .xmldocs/app_playbackground-en_US.xml
	test -d $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty || $(mkinstalldirs) $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty
	$(INSTALL) -m 644 .xmldocs/app_playbackground-en_US.xml $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty


clobber: distclean
	rm -rf ./{configure,aclocal.m4,libtool,ltmain.sh,autom4te.cache,config.h.in,Makefile.in,google,roots.pem.h.tmp,.xmldocs}
