CC=clang
CFLAGS=-std=gnu90 -g -pedantic -Weverything
LDLIBS=-lpcap
OBJECTS=options.o session.o output.o sniffle.o


sniffle : $(OBJECTS)

sniffle.o : sniffle.c decode.h session.h options.h
options.o : options.c options.h
session.o : session.c session.h output.h options.h
output.o : output.c output.h

test : sniffle
	sudo ./test.sh

doc : 
	doxygen Doxyfile

.PHONY : test doc


