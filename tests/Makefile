


hello-world: hello.c
	gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello

passthrough-example: passthrough_ll.c
	gcc -Wall passthrough_ll.c `pkg-config fuse3 --cflags --libs` -o passthrough