
######## Remote Attestation Settings ########

Remote_Attestation_C_Files := RemoteAttestation/ecp.c RemoteAttestation/remote_attestation.c RemoteAttestation/ias_ra.c

Remote_Attestation_Include_Paths := -IRemoteAttestation -IThirdPartyLibrary

Remote_Attestation_C_Flags := -fPIC -Wno-attributes -IRemoteAttestation -IThirdPartyLibrary
Remote_Attestation_Cpp_Flags := $(Remote_Attestation_C_Flags) -std=c++11
Remote_Attestation_Link_Flags :=  -shared -LThirdPartyLibrary -lsample_libcrypto

Remote_Attestation_C_Objects := $(Remote_Attestation_C_Files:.c=.o)

######## Key Management Settings ########

Key_Management_C_Files := KeyManagement/key_management.c

Key_Management_Include_Paths := -IKeyManagement -IThirdPartyLibrary

Key_Management_C_Flags := -fPIC -Wno-attributes -IRemoteAttestation -IThirdPartyLibrary
Key_Management_Cpp_Flags := $(Key_Management_C_Flags) -std=c++11
Key_Management_Link_Flags := -shared -LThirdPartyLibrary -lsample_libcrypto

Key_Management_C_Objects := $(Key_Management_C_Files:.c=.o)


.PHONY: all


######## Service Provider Objects ########
all: libremote_attestation.so libkey_management.so

RemoteAttestation/%.o: RemoteAttestation/%.c
	@$(CXX) $(Remote_Attestation_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

KeyManagement/%.o: KeyManagement/%.c
	@$(CXX) $(Key_Management_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

libremote_attestation.so: $(Remote_Attestation_C_Objects)
	@$(CXX) $^ -o $@ $(Remote_Attestation_Link_Flags)
	@echo "LINK =>  $@"

libkey_management.so: $(Key_Management_C_Objects)
	@$(CXX) $^ -o $@ $(Key_Management_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f libkey_management.so libremote_attestation.so $(Key_Management_C_Objects) $(Remote_Attestation_C_Objects)
