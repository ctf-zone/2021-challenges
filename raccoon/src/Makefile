DEBUG ?= 0

ifneq (, $(shell which clang))
	CC = clang
else ifneq (, $(shell which gcc))
	CC = gcc
else
	CC = cc
endif

SYS := $(shell $(CC) -dumpmachine)

# LINUX
ifneq (, $(findstring linux, $(SYS)))
	LIBS = -lpthread -lssl -lcrypto
	INCLUDES = -Ishared
endif

# MAC OS X
ifneq (, $(findstring darwin, $(SYS)))
	LIBS = -L/usr/local/opt/openssl/lib -lssl -lcrypto
	INCLUDES = -Ishared -I/usr/local/opt/openssl/include
endif

ifeq ($(DEBUG), 1)
    DEFINES = -DDEBUG
	CFLAGS = -g $(INCLUDES) $(DEFINES) -Wall -Werror -O0 -fsanitize=address
	LDFLAGS = -fsanitize=address
else
    DEFINES = -DNDEBUG
	CFLAGS = -g $(INCLUDES) $(DEFINES) -Wall -Werror -O2
	LDFLAGS = 
endif

ifeq ($(COVERAGE), 1)
	CFLAGS += -fprofile-instr-generate -fcoverage-mapping
endif

DEFINES += -DHACK

.SUFFIXES: .c .cpp

all: bin/raccoon-server bin/raccoon-client bin/raccoon-tests

server: bin/raccoon-server bin/raccoon-tests 

tmp/client/%.o: RaccoonClient/%.c shared/*.h
	$(CC) $(CFLAGS) -c $< -o $@
	
tmp/server/%.o: RaccoonServer/%.c shared/*.h
	$(CC) $(CFLAGS) -c $< -o $@
	
tmp/tests/%.o: RaccoonTests/%.c RaccoonTests/*.h shared/*.h
	$(CC) $(CFLAGS) -c $< -o $@
	
tmp/shared/%.o: shared/%.c shared/*.h
	$(CC) $(CFLAGS) -c $< -o $@

SRC_CLIENT = $(sort $(wildcard RaccoonClient/*.c))
SRC_SERVER = $(sort $(wildcard RaccoonServer/*.c))
SRC_TESTS = $(sort $(wildcard RaccoonTests/*.c))
SRC_SHARED = $(sort $(wildcard shared/*.c))
OBJ_CLIENT = $(addprefix tmp/client/, $(notdir $(addsuffix .o, $(basename $(SRC_CLIENT))))) 
OBJ_SERVER = $(addprefix tmp/server/, $(notdir $(addsuffix .o, $(basename $(SRC_SERVER))))) 
OBJ_TESTS = $(addprefix tmp/tests/, $(notdir $(addsuffix .o, $(basename $(SRC_TESTS)))))
OBJ_SHARED = $(addprefix tmp/shared/, $(notdir $(addsuffix .o, $(basename $(SRC_SHARED))))) 


bin/raccoon-server: $(OBJ_SERVER) $(OBJ_SHARED)
	$(CC) $(CFLAGS) -o $@ $(OBJ_SERVER) $(OBJ_SHARED) $(LDFLAGS) $(LIBS)

bin/raccoon-client: $(OBJ_CLIENT) $(OBJ_SHARED)
	$(CC) $(CFLAGS) -o $@ $(OBJ_CLIENT) $(OBJ_SHARED) $(LDFLAGS) $(LIBS)

bin/raccoon-tests: $(OBJ_TESTS) $(OBJ_SHARED)
	$(CC) $(CFLAGS) -o $@ $(OBJ_TESTS) $(OBJ_SHARED) $(LDFLAGS) $(LIBS)

clean:
	rm -f tmp/client/*.o
	rm -f tmp/server/*.o
	rm -f tmp/tests/*.o
	rm -f tmp/shared/*.o
	rm -f bin/raccoon-server
	rm -f bin/raccoon-client
	rm -f bin/raccoon-tests
