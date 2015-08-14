main : main.c decode.h session.h session.c output.c output.h options.c options.h
	gcc -o main -std=gnu99 -lpcap -g -pedantic -Wall -Wextra main.c session.c output.c options.c

