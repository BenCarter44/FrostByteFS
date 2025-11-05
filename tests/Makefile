
all: hello-world rawdisk-example allocator-example

hello-world: hello.c
	gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello.out

rawdisk-example: rawmain.c
	gcc ../src/rawdisk.c ../src/error.c rawmain.c -I../include/ `pkg-config fuse3 --cflags --libs` -o rawdisk.out

allocator-example: allocator_test.c
	gcc -DCOMPILE_FOR_TESTS ../src/*.c allocator_test.c -I../include/ `pkg-config fuse3 --cflags --libs` -o allocator.out