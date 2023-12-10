.PHONY := clean

windows: main.c flag.h
	gcc main.c -o windows

flag.h: generate.py
	python3 generate.py > flag.h

clean:
	rm -f windows flag.h