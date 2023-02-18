# VTPM Server

VTPM (located in `pkg/vtpm`) is a server listening on port `8877` in EVE, exposing limited functionality of the TPM to the clients. VTPM allows clients to execute [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) binaries from a list of [hardcoded options](https://github.com/lf-edge/eve/blob/883547fe7978550a30e4389aac24d562d1dae105/pkg/vtpm/src/server.cpp#L58).

## Packet Structure

VTPM server accepts `EveTPMRequest` commands and outputs `EveTPMResponse`. Both structures are defined in probuf format in a file located in `pkg/vtpm/proto/vtpm_api.proto`.

## Communicating with VTPM

You can communicate with VTPM by consuming the probuf definitions in your own client or using external tools like `protoc` to generate raw protobuf commands to send over the network.

Another way is using `eve_run` client from [eve-tools](https://github.com/lf-edge/eve-tools).  Using `eve_run` is easy because it already has a predefined command-file table and can map a command's required files to `EveTPMRequest`. To use this client, simply build it (or follow the [installation](https://github.com/lf-edge/eve-tools/blob/master/INSTALL.md) instructions if you prefer otherwise):

```bash
sudo apt-get install -y libprotobuf-dev libprotoc-dev protobuf-compiler cmake g++ libssl-dev libcurl4-openssl-dev uuid-dev
cd ~
git clone https://github.com/lf-edge/eve-tools.git
cd eve-tools/eve-tools
make
```

To run `eve_run` without installation make sure the `libevetools.so` is accessible:

```bash
LD_LIBRARY_PATH=~/eve-tools/eve-tools
export LD_LIBRARY_PATH
```

### Commands

Currently execution of the following commands are allowed:
| No |Command  |
|--|--|
| 1 |tpm2_getcap |
| 2 |tpm2_readpublic |
| 3 |tpm2_startauthsession |
| 4 |tpm2_policysecret |
| 5 |tpm2_activatecredential |
| 6 |tpm2_flushcontext |
| 7 |tpm2_startauthsession |
| 8 |tpm2_policysecret |
| 9 |tpm2_import |
| 10 |tpm2_flushcontext |
| 11 |tpm2_load |
| 12 |tpm2_hmac |
| 13 |tpm2_hash |
| 14 |tpm2_sign |
| 15 |tpm2_verifysignature |

To get the details about each command, please consult the related [documentation](https://github.com/tpm2-software/tpm2-tools/tree/master/man). As an example, signing a message using TPM through `eve_run` goes as follows:

```bash
#Using well-known AIK handle 0x81000003 (RSA cipher and RSASSA signing scheme, with SHA256)
echo "secret data" > data_to_be_signed

# Preparing ticket file to pass for signing
eve_run tpm2_hash -Q -C e -t ticket.bin -g sha256 -o digest.bin data_to_be_signed

# Performing signing...
eve_run tpm2_sign -Q -c 0x81000003 -g sha256 -s rsassa -o data.out.sign -t ticket.bin -f plain data_to_be_signed

# Reading public key for using it in openssl
eve_run tpm2_readpublic -Q -c 0x81000003 -o ak.pub -f pem

# Verifying signature using openssl
openssl dgst -verify ak.pub -keyform pem -sha256 -signature data.out.sign data_to_be_signed
```
