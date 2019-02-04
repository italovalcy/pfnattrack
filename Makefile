# Basic Makefine

OBJS= hash.o list.o

all: $(OBJS)
	$(CC) -o pf_nattrack pf_nattrack.c $(OBJS)

clean:
	rm $(OBJS) pf_nattrack
