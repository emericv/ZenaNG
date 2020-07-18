
default:
	mkdir -p build
	gcc -o build/zenang zenang.c -O2 -lusb-1.0 -lrt
