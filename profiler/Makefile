CC=gcc
CFLAGS=-I. -W -Wall
LDFLAGS=-lelf
DEPS = profiler.h vmas.h utils.h
OBJ = vmas.o utils.o profiler.o
TARGET = profiler

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *~ $(TARGET)
