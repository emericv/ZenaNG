

default:
	mkdir -p build
	gcc -o build/zenang zenang.c -lusb-1.0 -lrt
