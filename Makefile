CC = clang

PRG_DIR = prg
SRC_DIR = src

XDP_NAME = bpf_program
LDR_NAME = loader

EXE_NAME = monitor-exec

I_PATH = -I/usr/include/bpf
L_PATH = -L/usr/lib64
U_LIBS = -lbpf -lelf

EXE = $(PRG_DIR)/$(EXE_NAME)
XDP = $(PRG_DIR)/$(XDP_NAME).o

LDR_SRC = $(SRC_DIR)/$(LDR_NAME).c
XDP_SRC = $(SRC_DIR)/$(XDP_NAME).c

all: $(PRG_DIR) $(XDP) $(EXE)

clean:
	rm -rf $(PRG_DIR)

$(PRG_DIR):
	mkdir -p $(PRG_DIR)

$(XDP): $(XDP_SRC)
	$(CC) -O2 -target bpf -c $^ -o $@

$(EXE): $(LDR_SRC)
	$(CC) $(CFLAGS) $^ $(I_PATH) $(U_LIBS) $(L_PATH) -o $@

.PHONY: clean