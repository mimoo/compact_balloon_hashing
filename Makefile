.PHONY: static shared main main_shake scan clean

# by default, build the shared library balloon.1.so
all: shared_with_shake

# there are two variants: one that accepts a callback for the hash function
shared:
	$(CC) -shared -std=c99 -Os -fpic -Wall -Iinclude src/balloon.c -o balloon.1.so
balloon.o:
	$(CC) -std=c99 -Os -Wall -Iinclude src/balloon.c -c -o balloon.o
main: balloon.o
	$(CC) -Iinclude -std=c99 -Os -Wall balloon.o main_balloon.c && ./a.out

# one that integrates SHAKE128 as the hash function
shared_with_shake:
	$(CC) -shared -std=c99 -Os -fpic -Wall -Iinclude src/balloon_shake.c -o balloon_shake.1.so
balloon_shake.o:
	$(CC) -std=c99 -Os -Wall -Iinclude src/balloon_shake.c -c -o balloon_shake.o
main_shake: balloon_shake.o
	$(CC) -std=c99 -Os -Wall -Iinclude balloon_shake.o main_balloon_shake.c && ./a.out

# scanning with clang static analyzer
scan:
	scan-build -v -o . make

# 
clean:
	rm -f *.o
	rm -f *.so
	rm -f a.out