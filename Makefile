CRYPTLIB_VERSION=343_beta
CRYPTLIB_FILE=cl$(CRYPTLIB_VERSION).zip
CRYPTLIB_URL=http://www.cypherpunks.to/~peter/$(CRYPTLIB_FILE)
CRYPTLIB_DIR=cryptlib-$(CRYPTLIB_VERSION)
CRYPTLIB_LIB=libcl.a

QUIET=@
ifeq ($(RELEASE),1)
	CFLAGS += -Wall -O2 -Werror
else
	CFLAGS += -Wall -O0 -g -Werror
endif

LIBS=$(CRYPTLIB_DIR)/$(CRYPTLIB_LIB) -lpthread

chunker: chunker.c $(CRYPTLIB_DIR)/$(CRYPTLIB_LIB)
	$(CC) $(CFLAGS) -c chunker.c -I$(CRYPTLIB_DIR)
	$(CC) -o $@ chunker.o $(LIBS)

get-deps: clean-deps
	mkdir $(CRYPTLIB_DIR)
	curl -o $(CRYPTLIB_DIR)/$(CRYPTLIB_FILE) $(CRYPTLIB_URL)
	unzip -o -q -a -d $(CRYPTLIB_DIR) $(CRYPTLIB_DIR)/$(CRYPTLIB_FILE)

build-deps: $(CRYPTLIB_DIR)
	make -C $(CRYPTLIB_DIR)

clean-deps:
	rm -rf $(CRYPTLIB_DIR)

run: chunker
	./chunker tests/testinput_1.bin testinput_1.bin.

run2: chunker
	./chunker -s 15360 tests/testinput_1.bin testinput_1.bin.

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

check2: run2
	$(QUIET)./check.sh testinput_1.bin.

# requires at least one 'run' target to have been run
verify: chunker
	./chunker -c testinput_1.bin.

# see Run target earlier
stopcheck: chunker
	./chunker -v -m 2 tests/testinput_1.bin testinput_1.bin.

valgrind: chunker
	valgrind --suppressions=valgrind.supp --leak-check=full ./chunker tests/testinput_1.bin testinput_1.bin.
