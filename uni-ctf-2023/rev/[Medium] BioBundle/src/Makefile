.PHONY := clean

biobundle: main.c libflag.so.enc.h
	gcc  main.c -o biobundle -ldl

libflag.so.enc.h: libflag.so enc.py
	python3 enc.py libflag.so libflag.so.enc.h

libflag.so: flag.c
	gcc -shared -o libflag.so flag.c

clean:
	rm -f biobundle libflag.so libflag.so.enc.h
