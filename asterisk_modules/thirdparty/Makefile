all: inst/include/grpc/grpc.h


inst/include/grpc/grpc.h:
	cd grpc && make -j`nproc` -e prefix=../inst -e EXTRA_CFLAGS=-fPIC -e EXTRA_CXXFLAGS=-fPIC -e REQUIRE_CUSTOM_LIBRARIES_opt=1 install-static install-headers install-plugins
	cd grpc/third_party/protobuf && make install


clobber:
	rm -rf grpc inst googleapis
