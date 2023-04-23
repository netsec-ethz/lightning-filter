# SCION

## Installation

Some information to install SCION so that it can be run locally can be found online on the documentation website of Anapaya:
https://scion.docs.anapaya.net/en/latest/build/setup.html

The following instructions describe a relatively minimal installation, which allows running LightningFilter and its tests.

### Install Go:

https://go.dev/doc/install

On x86:
```
curl -LO https://go.dev/dl/go1.17.9.linux-amd64.tar.gz
echo "9dacf782028fdfc79120576c872dee488b81257b1c48e9032d122cfdb379cca6 go1.17.9.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.17.9.linux-amd64.tar.gz
```

```
echo >> ~/.profile
echo "# set PATH so it includes Go" >> ~/.profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile 
```

Check Version:
```
go version
```

Remove Go installation:
```
sudo rm -rf /usr/local/go
```
Don't forget to remove the PATH entry in `~/.profile`.

### Install SCION (Modules)

Besides the official SCION repository, there also exists the experimental fork from the Network Security Group at ETH Zurich:
https://github.com/netsec-ethz/scion

Currently, only the experimental fork supports DRKey.
Therefore, LightningFilter requires that version.

To obtain the source, clone the repository:
```
git clone https://github.com/netsec-ethz/scion.git
```

Modules can be installed with `go build`.
E.g., the `testnet_scion` setup requires the control service (cs), border router (posix-router), dispatcher (dispatcher), daemon (daemon), the PKI (scion-pki), and SCION tools like ping (scion):

```
go build -o ./bin/ ./go/cs/
go build -o ./bin/ ./go/posix-router/
go build -o ./bin/ ./go/dispatcher/
go build -o ./bin/ ./go/daemon/
go build -o ./bin/ ./go/scion-pki/
go build -o ./bin/ ./go/scion/
```
