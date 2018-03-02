
######################## PBC Settings ######################

PBC_Cpp_Files := Simple_PBC.cpp
PBC_Include_Paths := -I../../PBC/Includes -I../../GMP/Includes

PBC_C_Flags := $(PBC_Include_Paths)

PBC_Link_Flags := -L../../PBC -lpbc

PBC_Objects_Files := $(PBC_Cpp_Files:.cpp=.o)

App_Name := app


.PHONY: all

all: $(App_Name)

%.o: %.cpp
	@echo "$(CC) $(PBC_C_Flags) -c $< -o $@"
	@$(CC) $(PBC_C_Flags) -c $< -o $@

$(App_Name): $(PBC_Objects_Files)
	@echo "$(CC) $^ -o $@ $(PBC_Link_Flags)"
	@$(CC) $^ -o $@ $(PBC_Link_Flags)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(PBC_Objects_Files)
