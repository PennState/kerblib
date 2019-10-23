target_dir := ./obj

lib_src_files := src/userMetrics.cpp
lib_obj_files = userMetrics.o

adminLock_src := adminLock/adminLock.cpp
adminLock_obj_files = $(adminLock_src:%.cpp=%.o)

adminUnlock_src := adminUnlock/adminUnlock.cpp
adminUnlock_obj_files = $(adminUnlock_src:%.cpp=%.o)

kadminRest_src :=  kadminRest/base64.cpp kadminRest/kadminRestHandler.cpp
kadminRest_obj_files = $(kadminRest_src:%.cpp=%.o)
$(warning $(kadminRest_obj_files))

examples_src := examples/testUsage.cpp
examples_obj_files = $(examples_src:%.cpp=%.o)

#loggers_obj_files = $(loggers_src:%.cpp=%.o)

#library_destination = ./lib/libkrb_security.a
library_destination = /usr/local/lib/libkrb_security.a

#CC_ARGS := -std=c++11 -Wall -I. -I./include -I/usr/local/include -I/usr/include/et -I/usr/include/apr-1 -I/usr/include/mit-krb5/ -I$(COMMON_LIB_ROOT)/c++/util -I$(COMMON_LIB_ROOT)/c++/networking -I$(COMMON_LIB_ROOT)/c++/exception -I$(COMMON_LIB_ROOT)/c++/communication/include -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -Bstatic -lpistache  -lpthread -L$(COMMON_LIB_ROOT)/lib -lait_utilities -lait_communications -lboost_regex -Bdynamic -lkrb5 -lkadm5clnt 
CC_ARGS := -std=c++11 -Wall -I. -I./include -I/usr/local/include -I/usr/include/et -I/usr/include/apr-1 -I/usr/include/mit-krb5/ -I$(COMMON_LIB_ROOT)/c++/util -I$(COMMON_LIB_ROOT)/c++/networking -I$(COMMON_LIB_ROOT)/c++/exception -I$(COMMON_LIB_ROOT)/c++/communication/include -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -Bstatic -lpistache  -lpthread -L$(COMMON_LIB_ROOT)/lib -lait_utilities -lait_communications -lboost_regex -Bdynamic -lkrb5 -lkadm5clnt 

.PHONY: src loggers lib adminLock adminUnlock kadminRest examples

#all : src loggers lib adminLock adminUnlock kadminRest examples
all : src lib adminLock adminUnlock kadminRest examples

src : $(lib_src_files)
	$(CXX) -c $< $(CC_ARGS)

loggers : $(loggers_src)
	$(CXX) -c $< $(CC_ARGS) 

adminLock : $(adminLock_src)
	$(CXX) -o bin/adminLock $< $(CC_ARGS) -L./lib -lkrb_security -L$(COMMON_LIB_ROOT)/lib/ -lait_utilities -lait_communications 

adminUnlock : $(adminUnlock_src)
	$(CXX) -g -o bin/adminUnlock $< $(CC_ARGS) -L./lib -lkrb_security -L$(COMMON_LIB_ROOT)/lib/ -lait_utilities -lait_communications 

$(warning $(kadminRest_src))
kadminRest : $(kadminRest_src)
	$(CXX) -g -o bin/kadminRest $? $(CC_ARGS) -L./lib -lkrb_security -L$(COMMON_LIB_ROOT)/lib/ -lait_utilities -lait_communications 

#examples : $(examples_src)
#	$(CXX) -o bin/examples $< $(CC_ARGS) -L./lib -lkrb_security 

lib : $(lib_obj_files)
	rm -f $(library_destination);
	ar cq $(library_destination) $(lib_obj_files)
	rm -f *.o;
