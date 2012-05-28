# TODO do this properly
CRYPTLIB_DIR=../cryptlib-3.4.1
CRYPTLIB_LIB=libcl.a

QUIET=@
CFLAGS += -Wall -O0 -g -Werror
#CFLAGS += -Wall -O2 -Werror

LIBS=$(CRYPTLIB_DIR)/$(CRYPTLIB_LIB) -lpthread

chunker: chunker.c $(CRYPTLIB_DIR)/$(CRYPTLIB_LIB)
	$(CC) $(CFLAGS) -c chunker.c -I$(CRYPTLIB_DIR)
	$(CC) -o $@ chunker.o $(LIBS)

run: chunker
	./chunker tests/testinput_1.bin testinput_1.bin.

gdb: chunker
	gdb -x gdb.args

strace: chunker
	strace ./chunker tests/testinput_1.bin testinput_1.bin.

clean:
	$(RM) testinput_1.bin.* chunker *.o

dataclean:
	$(RM) testinput_1.bin.*

# Run unit-tests
check: run 
	$(QUIET)./check.sh testinput_1.bin.

# see Run target earlier
stopcheck: chunker
	./chunker -v -s 2 tests/testinput_1.bin testinput_1.bin.

valgrind: chunker
	valgrind --suppressions=valgrind.supp --leak-check=full ./chunker tests/testinput_1.bin testinput_1.bin.
