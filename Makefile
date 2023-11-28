#############################################################################################
# Makefile
#############################################################################################
# G++ is part of GCC (GNU compiler collection) and is a compiler best suited for C++
CC=g++

# Compiler Flags: https://linux.die.net/man/1/g++
#############################################################################################
# -g: produces debugging information (for gdb)
# -Wall: enables all the warnings
# -Wextra: further warnings
# -Werror: treat warnings as errors
# -O: Optimizer turned on
# -std: use the C++ 20 standard
# -c: says not to run the linker
# -pthread: Add support for multithreading using the POSIX threads library. This option sets 
#           flags for both the preprocessor and linker. It does not affect the thread safety 
#           of object code produced by the compiler or that of libraries supplied with it. 
#           These are HP-UX specific flags.
#############################################################################################
CFLAGS=-g -Wall -Wextra -Werror -O -std=c++20 -pthread

rebuild: clean all
all: ./bin/server ./bin/client

clean:
	clear
	rm -f bin/* obj/*

./obj/mypw.o: mypw.cpp mypw.hpp
	${CC} ${CFLAGS} -o obj/mypw.o mypw.cpp -c

./obj/myclient.o: myclient.cpp mypw.hpp
	${CC} ${CFLAGS} -o obj/myclient.o myclient.cpp -c

./obj/myserver.o: myserver.cpp mypw.hpp
	${CC} ${CFLAGS} -o obj/myserver.o myserver.cpp -c

./bin/server: ./obj/myserver.o ./obj/mypw.o
	${CC} ${CFLAGS} -o bin/server obj/myserver.o obj/mypw.o -lldap -llber -lpthread

./bin/client: ./obj/myclient.o ./obj/mypw.o
	${CC} ${CFLAGS} -o bin/client obj/myclient.o obj/mypw.o

