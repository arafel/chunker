# TODO do this properly
CRYPTLIB_DIR=../cryptlib-3.4.1
CRYPTLIB_LIB=libcl.a

CFLAGS += -Wall -O0 -g
#CFLAGS += -Wall -O2

LIBS=$(CRYPTLIB_DIR)/$(CRYPTLIB_LIB) -lpthread

chunker: chunker.c $(CRYPTLIB_DIR)/$(CRYPTLIB_LIB)
	$(CC) $(CFLAGS) -c chunker.c -I$(CRYPTLIB_DIR)
	$(CC) -o chunker chunker.o $(LIBS)

run: chunker
	./chunker 
