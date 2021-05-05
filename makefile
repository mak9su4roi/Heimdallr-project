CC = clang

PRG_DIR = prg
SRC_DIR = src
INC_DIR = inc

XDP_NAME = bpf_program
LDR_NAME = launcher
MAP_NAME = map_util

I_PATH = -I/usr/include/bpf -Iinc
L_PATH = -L/usr/lib64
U_LIBS = -lbpf -lelf

XDP = $(PRG_DIR)/$(XDP_NAME).o
LDR = $(PRG_DIR)/$(LDR_NAME)
MAP = $(PRG_DIR)/$(MAP_NAME)

LDR_SRC = $(SRC_DIR)/$(LDR_NAME).c
XDP_SRC = $(SRC_DIR)/$(XDP_NAME).c
MAP_SRC = $(SRC_DIR)/$(MAP_NAME).c $(SRC_DIR)/map_driver.c

MAP_INC = $(INC_DIR)/common.h $(INC_DIR)/map_driver.h

XDP_TOOLS = $(XDP) $(LDR) $(MAP)

all: $(PRG_DIR) $(XDP_TOOLS)

$(PRG_DIR):
		mkdir -p $(PRG_DIR)

$(MAP): $(MAP_SRC) $(INC_DIR)
		$(CC) $(MAP_SRC) $(I_PATH) $(U_LIBS) -o $@

$(XDP): $(XDP_SRC)
		$(CC) -O2 -target bpf $(I_PATH) -c $^ -o $@

$(LDR): $(LDR_SRC)
		$(CC) $(CFLAGS) $^ $(I_PATH) $(U_LIBS) $(L_PATH) -o $@

.PHONY: clean

clean:
		rm $(XDP_TOOLS)