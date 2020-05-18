# Bitcoinlove 1.0.0

 **What is Bitcoinlove ?**

Bitcoinlove is an implementation of the "Zerocash" protocol. Based on Bitcoin's code, it intends to offer a far higher standard of privacy through a sophisticated zero-knowledge proving scheme that preserves confidentiality of transaction metadata.

This software is the Bitcoinlove node and command-line client. It downloads and stores the entire history of Bitcoinlove transactions; depending on the speed of your computer and network connection, the synchronization process could take a day or more once the blockchain has reached a significant size.

* **P2P Port -** 16525  
* **RPC Port -** 16524


## Build (Ubuntu 16.04 Tested)
1. Get dependencies
```
sudo apt-get update
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake curl
```

2. Build
```
# pull
https://github.com/biggiddybust/BitcoinLove bitcoinlove
cd bitcoinlove
# Build
./zcutil/build.sh -j$(nproc)
```

#### Run Bitcoinlove 
1. Create bitcoinlove.conf file
```
mkdir -p  ~/.bitcoinlove
echo "rpcuser=username" >> ~/.bitcoinlove/bitcoinlove.conf
echo "rpcpassword=`head -c 32 /dev/urandom | base64`" >> ~/.bitcoinlove/bitcoinlove.conf
echo "addnode=128.199.96.201" >> ~/.bitcoinlove/bitcoinlove.conf
echo "addnode=178.128.92.22" >> ~/.bitcoinlove/bitcoinlove.conf
echo "addnode=178.128.83.219" >> ~/.bitcoinlove/bitcoinlove.conf
echo "addnode=206.189.89.103" >> ~/.bitcoinlove/bitcoinlove.conf
please add those  command  in bitcoinlove.conf file to complete bitcoinlove.conf
cd ~/.bitcoinlove
nano  bitcoinlove.conf
listen=1
rpcport=16524
#rpcallowip=10.1.1.34
#rpcallowip=192.168.*.*
#rpcallowip=1.2.3.4/255.255.255.0
rpcallowip=127.0.0.1
rpctimeout=30
gen=1
equihashsolver=tromp
showmetrics=1
 #Use Secure Sockets Layer (also known as TLS or HTTPS) to communicate
# with bitcoinlove -server or bitcoinloved
#rpcssl=1
# OpenSSL settings used when rpcssl=1
#rpcsslciphers=TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH
#rpcsslcertificatechainfile=server.cert
#rpcsslprivatekeyfile=server.pem


```

2. Fetch keys
```
cd bitcoinlove
./zcutil/fetch-params.sh
```

3. Run a Bitcoinlovenode
```
./src/bitcoinloved --daemon
```
