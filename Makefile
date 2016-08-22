target_dir := ./obj

lib_src_files := src/userMetrics.cpp
lib_obj_files = userMetrics.o #jmsLogger.o

adminLock_src := adminLock/adminLock.cpp
adminLock_obj_files = $(adminLock_src:%.cpp=%.o)

adminUnlock_src := adminUnlock/adminUnlock.cpp
adminUnlock_obj_files = $(adminUnlock_src:%.cpp=%.o)

kadminRest_src := kadminRest/kadminRestHandler.cpp base64.cpp
kadminRest_obj_files = $(kadminRest_src:%.cpp=%.o)

examples_src := examples/testUsage.cpp
examples_obj_files = $(examples_src:%.cpp=%.o)

#loggers_obj_files = $(loggers_src:%.cpp=%.o)

library_destination = ./lib/libkrb_security.a

CC_ARGS := -std=gnu++0x -Wall -I. -I./include -I/usr/include/apr-1 -I/usr/include/mit-krb5/ -I$(COMMON_LIB_ROOT)/c++/util -I$(COMMON_LIB_ROOT)/c++/networking -I$(COMMON_LIB_ROOT)/c++/exception -I$(COMMON_LIB_ROOT)/c++/communication/include -L/usr/lib/x86_64-linux-gnu -lkrb5 -lkadm5clnt_mit -L$(COMMON_LIB_ROOT)/lib -lait_utilities -lait_communications 

.PHONY: src loggers lib adminLock adminUnlock examples

#all : src loggers lib adminLock adminUnlock examples
all : src lib adminLock adminUnlock examples

src : $(lib_src_files)
	$(CXX) -c $< $(CC_ARGS)

loggers : $(loggers_src)
	$(CXX) -c $< $(CC_ARGS) 

adminLock : $(adminLock_src)
	$(CXX) -o bin/adminLock $< $(CC_ARGS) -L./lib -lait_security -L$(COMMON_LIB_ROOT)/lib/ -lait_utilities -lait_communications -lboost_regex

adminUnlock : $(adminUnlock_src)
	$(CXX) -g -o bin/adminUnlock $< $(CC_ARGS) -L./lib -lait_security -L$(COMMON_LIB_ROOT)/lib/ -lait_utilities -lait_communications -lboost_regex

examples : $(examples_src)
	$(CXX) -o bin/examples $< $(CC_ARGS) -L./lib -lait_security 

lib : $(lib_obj_files)
	rm -f $(library_destination);
	ar cq $(library_destination) $(lib_obj_files)
	rm -f *.o;
