# The changes need a c++11 compatible C++ compiler
#
CXXFLAGS=-std=c++11 -I/usr/include/openssl -O3 -Wall -c -g
LDFLAGS=-L/usr/lib64 -lssl -lboost_system -lboost_filesystem -lcrypto -lstdc++ -g 

all: sslserver sslclient

sslserver: common.o sslserver.o

sslclient: common.o sslclient.o

clean:
	rm -f sslclient sslserver *.o
