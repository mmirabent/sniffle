sniffle : main.c decode.h session.h session.c output.c output.h options.c options.h
	clang -o sniffle -std=gnu90 -lpcap -g -pedantic -Weverything main.c session.c output.c options.c

test : sniffle
	sudo ./test.sh

doc : main.c decode.h session.h session.c output.h output.c options.h options.c
	doxygen Doxyfile

.PHONY : test doc


