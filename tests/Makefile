
all: hello-world rawdisk-example allocator-example inode-example

hello-world: hello.c
	gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -Wl,-rpath=/usr/local/lib64 -o hello.out

rawdisk-example: rawmain.c
	gcc ../src/rawdisk.c ../src/error.c rawmain.c -I../include/ `pkg-config fuse3 --cflags --libs` -g3 -O0 -Wl,-rpath=/usr/local/lib64 -o rawdisk.out

allocator-example: allocator_test.c
	gcc -DCOMPILE_FOR_TESTS ../src/*.c allocator_test.c -I../include/ `pkg-config fuse3 --cflags --libs` -g3 -O0 -Wl,-rpath=/usr/local/lib64 -o allocator.out

inode-example: inode_test.c
	gcc -DCOMPILE_FOR_TESTS ../src/*.c inode_test.c -I../include/ `pkg-config fuse3 --cflags --libs` -g3 -O0 -Wl,-rpath=/usr/local/lib64 -o inode.out