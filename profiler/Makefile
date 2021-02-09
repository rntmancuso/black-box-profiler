CC=${CROSS_COMPILE}gcc
CFLAGS=-I. -W -Wall -I./libs/include/
LDFLAGS=-lelf -L./libs/lib/ -lz
DEPS = profiler.h vmas.h utils.h
OBJ = vmas.o utils.o profiler.o
TARGET = profiler

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o *~ $(TARGET)
