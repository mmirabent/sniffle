main : main.c decode.h session.h session.c output.c output.h
	gcc -o main -lpcap -g -pedantic -Wall -Wextra main.c session.c output.c

