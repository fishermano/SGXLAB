# SGX_LAB

This is a prototype project for the paper "A Secure Remote Patient Monitoring Framework Supporting Efficienct Fine-grained Access Control and Data Processing in IoT" targeting SecureCom 2018.

It mainly inlcudes two parts: Demo and Evaluation.

Demo
---------------------------------------------
This part implements the prototype described in Section Implementation, which involves the entities, i.e., trusted broker and health care provider.

For the trusted broker, we implement the following six function modules.
------------
DataSample: To simulate the activities of monitoring devices.

DataUpload: To encrypt collected data by monitoring devices and upload the ciphertexts as per device to the public cloud storage.

Heartbeat: To emit frequently heartbeat signal to HCPs.

KeyManagement: To generate device keys and distribute them to different HCPs.

RemoteAttestation: To remotely verify the hardware and software TCB of the HCP enclave.

With regard to the HCP, we implement an application module and an enclave module.
----------
The application module mainly illustrates the invocation of the ECALL functions implemented in the enclave module.

In HCP enclave, we mainly offer five function sub-modules according to their functionalities.

Functions: It implements functional computation related interfaces. In particular, we implement a statistice interface.

Heartbeat: It implements interfaces that handle the heartbeat signal.

KeyManagement: It implements interfaces that load assigned keys into the enclave.

RemoteAttestation: It implements interfaces that facilitate remote attestation.

SealSecrets: It implements interfaces that enable to flush the secrets within the enclave to the untrusted secondary storage.

Evaluation
---------------------------------------------
This part implements the evaluation described in Section Evaluation.

You can execute the below command to draw the evaluation result.
$python encryption_drawer.py


Build
---------------------------------------------
$souce environment (you should replace the 'environment' file with the generated one located in you installed SGX_SDK directory)

$make
or
$make SGX_MODE=SIM (For those who do not install the isClient that is required by sealing functionality)

$./demo_app
