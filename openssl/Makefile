export CC=/opt/rh/devtoolset-2/root/usr/bin/gcc  
export CPP=/opt/rh/devtoolset-2/root/usr/bin/cpp
export CXX=/opt/rh/devtoolset-2/root/usr/bin/c++

CXXFLAGS=-std=c++11 -I/usr/include/openssl -O3 -Wall -c -g
LDFLAGS=-L/usr/lib64 -lssl -lcrypto -lstdc++ -g 

all: sslserver sslclient

sslserver: common.o sslserver.o

sslclient: common.o sslclient.o
