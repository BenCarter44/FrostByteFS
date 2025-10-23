


hello-world: hello.c
	gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello

passthrough-example: passthrough_ll.c
	gcc -Wall passthrough_ll.c `pkg-config fuse3 --cflags --libs` -o passthrough

rawdisk-example: rawmain.c
	gcc ../src/rawdisk.c rawmain.c -I../include/ `pkg-config fuse3 --cflags --libs`