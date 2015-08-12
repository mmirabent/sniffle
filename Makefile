main : main.c decode.h session.h session.c
	gcc -o main -lpcap -g -pedantic -Wall -Wextra main.c session.c

