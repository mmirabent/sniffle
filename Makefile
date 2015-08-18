main : main.c decode.h session.h session.c output.c output.h options.c options.h
	clang -o main -std=c90 -lpcap -g -pedantic -Weverything main.c session.c output.c options.c

