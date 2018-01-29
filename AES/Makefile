C_Files := main.c $(wildcard aes/*.c) $(wildcard utils/*.c)

C_Flags := -Iaes -Iutils
Link_Flags := -Wall -lcrypto

Objects_Files := $(C_Files:.c=.o)

App_Name := main

.PHONY: all

all: $(App_Name)

%.o: %.c
	@echo "$(CC) $(C_Flags) -c $< -o $@"
	@$(CC) $(C_Flags) -c $< -o $@

$(App_Name): $(Objects_Files)
	@echo "$(CC) $^ -o $@ $(Link_Flags)"
	@$(CC) $^ -o $@ $(Link_Flags)
