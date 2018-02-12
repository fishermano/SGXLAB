
######## Remote Attestation Settings ########

Remote_Attestation_C_Files := RemoteAttestation/ecp.c RemoteAttestation/remote_attestation.c RemoteAttestation/ias_ra.c

Remote_Attestation_Include_Paths := -IRemoteAttestation -IThirdPartyLibrary

Remote_Attestation_C_Flags := -fPIC -Wno-attributes -IRemoteAttestation -IThirdPartyLibrary
Remote_Attestation_Cpp_Flags := $(Remote_Attestation_C_Flags) -std=c++11
Remote_Attestation_Link_Flags :=  -shared -LThirdPartyLibrary -lsample_libcrypto

Remote_Attestation_C_Objects := $(Remote_Attestation_C_Files:.c=.o)

.PHONY: all


######## Service Provider Objects ########
all: libremote_attestation.so

RemoteAttestation/%.o: RemoteAttestation/%.c
	@$(CXX) $(Remote_Attestation_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
libremote_attestation.so: $(Remote_Attestation_C_Objects)
	@$(CXX) $^ -o $@ $(Remote_Attestation_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f RemoteAttestation/libremote_attestation.so $(Remote_Attestation_C_Objects)
