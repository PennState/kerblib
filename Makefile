BUILD_VERSION := $(shell git --no-pager describe --tags --always)
BUILD_DATE := $(shell date --iso=seconds)
BUILD_INFO := -DBUILD_VERSION=\"$(BUILD_VERSION)\" -DBUILD_DATE=\"$(BUILD_DATE)\"

target_dir := ./obj

lib_src_files := src/userMetrics.cpp
lib_obj_files = userMetrics.o

kadminRest_src :=  kadminRest/base64.cpp kadminRest/kadminRestHandler.cpp
kadminRest_obj_files = $(kadminRest_src:%.cpp=%.o)

examples_src := examples/testUsage.cpp
examples_obj_files = $(examples_src:%.cpp=%.o)

library_destination = ./lib/libkrb_security.a

CC_ARGS := -std=c++14 -Wall -I. -I./include -I/usr/local/include -I/usr/include/et -I/usr/include/apr-1 -I/usr/include/mit-krb5/ -L./lib -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -Bstatic -lpistache -lpthread -Bdynamic -lkrb5 -lkadm5clnt $(BUILD_INFO)

.PHONY: src loggers lib kadminRest examples

all : src lib kadminRest

src : $(lib_src_files)
	$(CXX) -c $< $(CC_ARGS)

loggers : $(loggers_src)
	$(CXX) -c $< $(CC_ARGS) 

kadminRest : $(kadminRest_src)
	$(CXX) -g -o bin/kadminRest $? $(CC_ARGS) -L./lib -lkrb_security

examples : $(examples_src)
	$(CXX) -o bin/examples $< $(CC_ARGS) -L./lib -lkrb_security 

lib : $(lib_obj_files)
	rm -f $(library_destination);
	ar cq $(library_destination) $(lib_obj_files)
	rm -f *.o;
