# TODO do this properly
CRYPTLIB_DIR=../cryptlib-3.4.1
CRYPTLIB_LIB=libcl.a

CFLAGS += -Wall -O0 -g -Werror
#CFLAGS += -Wall -O2 -Werror

LIBS=$(CRYPTLIB_DIR)/$(CRYPTLIB_LIB) -lpthread

chunker: chunker.c $(CRYPTLIB_DIR)/$(CRYPTLIB_LIB)
	$(CC) $(CFLAGS) -c chunker.c -I$(CRYPTLIB_DIR)
	$(CC) -o chunker chunker.o $(LIBS)

run: chunker
	./chunker tests/testinput_1.bin testinput_1.bin.

# Run unit-tests
check: chunker
	./chunker

valgrind: chunker
	valgrind --suppressions=valgrind.supp --leak-check=full ./chunker tests/testinput_1.bin testinput_1.bin.
