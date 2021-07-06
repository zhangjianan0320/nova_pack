CC=g++
CFLAGS=-lpthread
OBJECT=edit
SOURCE=$(wildcard *.cpp)
$(OBJECT):$(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) -o $@

clean:
	rm $(OBJECT)
