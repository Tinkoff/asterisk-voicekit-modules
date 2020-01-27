all: inst/include/grpc/grpc.h inst/lib/libjansson.a


inst/include/grpc/grpc.h:
	@command -v which &> /dev/null || (echo "Error: no 'which' tool present; please install one"; false)
	cd grpc && make -j`nproc` -e prefix=../inst -e EXTRA_CFLAGS="-fPIC -Wno-error" -e EXTRA_CXXFLAGS="-fPIC -Wno-error" -e REQUIRE_CUSTOM_LIBRARIES_opt=1 install-static install-headers install-plugins
	cd grpc/third_party/protobuf && make install

inst/lib/libjansson.a:
	cd jansson-2.12 && CFLAGS="${CFLAGS:+${CFLAGS} }-fPIC" ./configure --prefix=`pwd`/../inst --enable-static --disable-shared && make install

clobber:
	rm -rf grpc inst googleapis jansson-2.12
