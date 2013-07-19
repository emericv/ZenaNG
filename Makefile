

default:
	mkdir -p build
	gcc -o build/zena zena.c -lusb-1.0 -lrt
