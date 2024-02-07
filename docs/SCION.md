# SCION

## Installation

Some information to install SCION so that it can be run locally can be found online on the documentation website of Anapaya:
https://scion.docs.anapaya.net/en/latest/build/setup.html

The following instructions describe a relatively minimal installation, which allows running LightningFilter and its tests.

### Install Go:

https://go.dev/doc/install

On x86:
```
curl -LO https://golang.org/dl/go1.21.2.linux-amd64.tar.gz
echo "f5414a770e5e11c6e9674d4cd4dd1f4f630e176d1828d3427ea8ca4211eee90d go1.21.2.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.21.2.linux-amd64.tar.gz
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

To obtain the source, clone the repository:
```
git clone https://github.com/scionproto/scion.git
cd scion
git checkout v0.9.1
```

Modules can be installed with `go build`.
E.g., the `testnet_scion` setup requires the control service (control), border router (router), dispatcher (dispatcher), daemon (daemon), the PKI (scion-pki), and SCION tools like ping (scion):

```
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./router/cmd/router
go build -o ./bin/ ./scion/cmd/scion
go build -o ./bin/ ./scion-pki/cmd/scion-pki
```
