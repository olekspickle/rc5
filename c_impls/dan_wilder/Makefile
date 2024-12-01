CC=gcc
CFLAGS=-c -g -Wno-endif-labels

SOURCES=rc5.c
OBJECTS=rc5.o

EXECUTABLE=rc5

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)  
	$(CC) $(OBJECTS) -o $(EXECUTABLE) 

obj/%.o: src/%.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean

clean:
	rm $(OBJECTS) $(EXECUTABLE)

