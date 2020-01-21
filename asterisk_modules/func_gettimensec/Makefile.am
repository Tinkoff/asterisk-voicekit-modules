pkgdir = $(asteriskmoduledir)
pkg_LTLIBRARIES = func_gettimensec.la
func_gettimensec_la_SOURCES = \
func_gettimensec.c

func_gettimensec_la_CFLAGS = -Wall -O3 -Werror=implicit-function-declaration -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -fPIC -DAST_MODULE=\"func_gettimensec\"
func_gettimensec_la_CXXFLAGS = -Wall -O3 -std=c++11 -fPIC
func_gettimensec_la_LDFLAGS = -Wl,-E -pthread -g -module -avoid-version -ldl
func_gettimensec_la_LIBTOOLFLAGS = --tag=disable-static


XMLDOC_FILES = func_gettimensec.c

all-local: .xmldocs/func_gettimensec-en_US.xml

.xmldocs/func_gettimensec-en_US.xml_tmp: $(XMLDOC_FILES)
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

.xmldocs/func_gettimensec-en_US.xml: $(XMLDOC_FILES)
	echo $@_tmp
	make $@_tmp || (rm -f $@_tmp; false)
	mv $@_tmp $@

install-data-local: .xmldocs/func_gettimensec-en_US.xml
	test -d $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty || $(mkinstalldirs) $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty
	$(INSTALL) -m 644 .xmldocs/func_gettimensec-en_US.xml $(DESTDIR)$(asterisk_xmldoc_dir)/thirdparty


clobber: distclean
	rm -rf ./{configure,aclocal.m4,libtool,ltmain.sh,autom4te.cache,config.h.in,Makefile.in,.xmldocs}
