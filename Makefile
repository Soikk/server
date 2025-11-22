CC = gcc
CFLAGS = -O0 -Wall -ggdb3 -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto

SRCDIR = src
OBJDIR = obj
ifeq ($(OS),Windows_NT)
	LIBDIR = C:/Users/quique/Documents/Programming/libs
	RUNCMD = server.exe
else
	LIBDIR = /mnt/c/Users/quique/Documents/Programming/libs
	RUNCMD = ./server.exe
endif

OBJS = $(addprefix $(OBJDIR)/, bit.o files.o str.o log.o list.o crc64.o net.o ipc.o mime.o rewrites.o config.o)

INCL = -I$(LIBDIR) -I$(SRCDIR)



all: server.exe worker.exe

server.exe: $(SRCDIR)/main.c $(OBJS)
	$(CC) $< $(OBJS) $(INCL) $(CFLAGS) -o server.exe $(LDFLAGS)

worker.exe: $(SRCDIR)/worker.c $(OBJS)
	$(CC) $< $(OBJS) $(INCL) $(CFLAGS) -o worker.exe $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%/*.c $(SRCDIR)/%/*.h
	$(CC) -c $(SRCDIR)/$*/$*.c $(INCL) $(CFLAGS) -o $(OBJDIR)/$*.o $(LDFLAGS)

$(OBJDIR)/%.o: $(LIBDIR)/%/*.c $(LIBDIR)/%/*.h
	$(CC) -c $(LIBDIR)/$*/$*.c $(INCL) $(CFLAGS) -o $(OBJDIR)/$*.o $(LDFLAGS)

clean:
	rm -f worker.exe server.exe $(OBJDIR)/*.o

memcheck:
	sudo valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --trace-children=yes -s $(RUNCMD) config
	
