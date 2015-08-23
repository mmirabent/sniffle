CC=clang
CFLAGS=-std=gnu90 -g -pedantic -Weverything
LDFLAGS=-lpcap
OBJECTS=options.o session.o output.o


sniffle : $(OBJECTS)
	$(CC) -o sniffle $(CFLAGS) $(LDFLAGS) main.c $(OBJECTS) 

options.o : options.c options.h
session.o : session.c session.h output.h options.h
output.o : output.c output.h

test : sniffle
	sudo ./test.sh

doc : main.c decode.h session.h session.c output.h output.c options.h options.c
	doxygen Doxyfile

.PHONY : test doc


