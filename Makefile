# Basic Makefine

OBJS= hash.o list.o pf_nattrack

all: $(OBJS)
	$(CC) -o pf_nattrack $(OBJS)

clean:
	rm $(OBJS) pf_nattrack
