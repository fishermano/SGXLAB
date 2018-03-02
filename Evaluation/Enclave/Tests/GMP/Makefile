
######################## GMP Settings ######################

GMP_Cpp_Files := Simple_GMP.cpp
GMP_Include_Paths := -I../../GMP/Includes

GMP_C_Flags := $(GMP_Include_Paths)

GMP_Link_Flags := -L../../GMP -lgmp

GMP_Objects_Files := $(GMP_Cpp_Files:.cpp=.o)

App_Name := app


.PHONY: all

all: $(App_Name)

%.o: %.cpp
	@echo "$(CC) $(GMP_C_Flags) -c $< -o $@"
	@$(CC) $(GMP_C_Flags) -c $< -o $@

$(App_Name): $(GMP_Objects_Files)
	@echo "$(CC) $^ -o $@ $(GMP_Link_Flags)"
	@$(CC) $^ -o $@ $(GMP_Link_Flags)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(GMP_Objects_Files)
