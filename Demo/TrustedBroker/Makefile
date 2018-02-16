
######## Remote Attestation Settings ########

Remote_Attestation_C_Files := RemoteAttestation/ecp.c RemoteAttestation/remote_attestation.c RemoteAttestation/ias_ra.c

Remote_Attestation_Include_Paths := -IRemoteAttestation -IThirdPartyLibrary

Remote_Attestation_C_Flags := -fPIC -Wno-attributes $(Remote_Attestation_Include_Paths)
Remote_Attestation_Cpp_Flags := $(Remote_Attestation_C_Flags) -std=c++11
Remote_Attestation_Link_Flags :=  -shared -LThirdPartyLibrary -lsample_libcrypto

Remote_Attestation_C_Objects := $(Remote_Attestation_C_Files:.c=.o)

######## Key Management Settings ########

Key_Management_C_Files := KeyManagement/key_management.c KeyManagement/keys.c

Key_Management_Include_Paths := -IRemoteAttestation -IKeyManagement -IThirdPartyLibrary

Key_Management_C_Flags := -fPIC -Wno-attributes $(Key_Management_Include_Paths)
Key_Management_Cpp_Flags := $(Key_Management_C_Flags) -std=c++11
Key_Management_Link_Flags := -shared -LThirdPartyLibrary -lsample_libcrypto

Key_Management_C_Objects := $(Key_Management_C_Files:.c=.o)

######## Data Upload Settings ########

Data_Upload_C_Files := DataUpload/data_upload.c

Data_Upload_Include_Paths := -IRemoteAttestation -IDataUpload -IThirdPartyLibrary

Data_Upload_C_Flags := -fPIC -Wno-attributes $(Data_Upload_Include_Paths)
Data_Upload_Cpp_Flags := $(Data_Upload_C_Flags) -std=c++11
Data_Upload_Link_Flags := -shared -LThirdPartyLibrary -lsample_libcrypto

Data_Upload_C_Objects := $(Data_Upload_C_Files:.c=.o)


.PHONY: all


######## Service Provider Objects ########
all: libremote_attestation.so libkey_management.so libdata_upload.so

RemoteAttestation/%.o: RemoteAttestation/%.c
	@$(CXX) $(Remote_Attestation_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

KeyManagement/%.o: KeyManagement/%.c
	@$(CXX) $(Key_Management_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

DataUpload/%.o: DataUpload/%.c
	@$(CXX) $(Data_Upload_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

libremote_attestation.so: $(Remote_Attestation_C_Objects)
	@$(CXX) $^ -o $@ $(Remote_Attestation_Link_Flags)
	@echo "LINK =>  $@"

libkey_management.so: $(Key_Management_C_Objects)
	@$(CXX) $^ -o $@ $(Key_Management_Link_Flags)
	@echo "LINK =>  $@"

libdata_upload.so: $(Data_Upload_C_Objects)
		@$(CXX) $^ -o $@ $(Data_Upload_Link_Flags)
		@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f libkey_management.so libremote_attestation.so libdata_upload.so $(Key_Management_C_Objects) $(Remote_Attestation_C_Objects) $(Data_Upload_C_Objects)
