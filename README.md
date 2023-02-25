# BDLS
Efficient BFT in partial synchronous networks 

git push <远程主机名> <本地分支名>:<远程分支名>

# BDLS Consensus

## Introduction

BDLS is an innovative BFT consensus algorithm that features safety and liveness by
presenting a mathematically proven secure BFT protocol that is resilient in open networks such as
the Internet. BDLS overcomes many problems, such as the deadlock problem caused by unreliable
p2p/broadcast channels. These problems are all very relevant to existing realistic open
network scenarios, and are the focus of extensive work in improving Internet security, but it
is an area largely ignored by most in mainstream BFT protocol design.
(Paper: https://eprint.iacr.org/2019/1460.pdf or https://dl.acm.org/doi/abs/10.1145/3538227 or  https://doi.org/10.1145/3538227 or https://www.doi.org/10.1007/978-3-030-91859-0_2 )

For this library, to make the runtime behavior of consensus algorithm predictable as function:
y = f(x, t), where 'x' is the message it received, and 't' is the time while being called,
  then'y' is the deterministic status of consensus after 'x' and 't' applied to 'f',
it has been designed in a deterministic scheme, without parallel computing, networking, and
the correctness of program implementation can be proven with proper test cases.

## Features

1. Pure algorithm implementation in deterministic and predictable behavior, easily to be integrated into existing projects, refer to [DFA](https://en.wikipedia.org/wiki/Deterministic_finite_automaton) for more.
2. Well-tested on various platforms with complicated cases.
3. Auto back-off under heavy payload, guaranteed finalization(worst case gurantee).
4. Easy integratation into Blockchain & non-Blockchain consensus, like [WAL replication](https://en.wikipedia.org/wiki/Replication_(computing)#Database_replication) in database.
5. Builtin network emulation for various network latency with comprehensive statistics.

## Documentation

For complete documentation, see the associated [Godoc](https://pkg.go.dev/github.com/Sperax/bdls).


## Install BDLS on Ubuntu Server 20.04 

```
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get install autoconf automake libtool curl make g++ unzip
cd /tmp
wget https://go.dev/dl/go1.19.linux-amd64.tar.gz 
sudo tar -xvf go1.19.linux-amd64.tar.gz
sudo mv go /usr/local
cd
echo 'export GOROOT=/usr/local/go' >> .profile
echo 'export GOPATH=$HOME/go' >> .profile
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> .profile
source ~/.profile 
go version
go env
git clone https://github.com/yonggewang/bdls.git
cd bdls/
git checkout master
cd cmd/emucon/
go build .
./emucon help genkeys
./emucon genkeys --count 4

[open four terminals to run four participants. if you log to remote Linux, 
you may use tmux commands. In tmux, you can switch termian using "ctrl+b d" 
and use "tmux attach -t 0" to enter the terminal. Use "tmux list-session" 
to check the current active terminals]


./emucon run --id 0 --listen ":4680"
./emucon run --id 1 --listen ":4681"
./emucon run --id 2 --listen ":4682"
./emucon run --id 3 --listen ":4683"

cd ../..
go test -v -cpuprofile=cpu.out -memprofile=mem.out -timeout 2h
```
## Regenerate go.mod and go.sum
```
rm go.*
go mod init github.com/yonggewang/bdls
go mod tidy
go mod vendor
```

See benchmark ourput at: [AMD-NORMAL.TXT](benchmarks/AMD-NORMAL.TXT) and [PI4-OVERLOAD.TXT](benchmarks/PI4-OVERLOAD.TXT)

## Specification

1. Consensus messages are specified in [message.proto](message.proto), users of this library can encapsulate this message in a carrier message, like gossip in TCP.
2. Consensus algorithm is **NOT** thread-safe, it **MUST** be protected by some synchronization mechanism, like `sync.Mutex` or `chan` + `goroutine`.

## Usage

1. A testing IPC peer -- [ipc_peer.go](ipc_peer.go)
2. A testing TCP node -- [TCP based Consensus Emualtor](cmd/emucon)

## Status

On-going

## Configuration

一、公私钥对

1、管理员

公：73ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795ce7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d

私：2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d323536000001210273ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795c012102e7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d00012102fe8e63a919332baa17c60530a70cd3fbe505848e2d26ffc23ae3e1bb138db5c900

地址：1JwHdG4iwvnQJLPVKEU4TMEG9645H8n4Lr

D:115139043655121369876744144402956672223889454523067809828600815499456893793737
2、测试

私钥：

2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d32353600000121022dfc3beb9713ad2929a3775b31100bbd39d05d2d43e7c4e5c07b752112b6362e0121022963233add649bb5a8512246e3c9b975f57132181b5abe32afa60b2e677c790c00012102326d8dcdcede9f9795646c23f06ad95e1fdbb7bb7b8976a249ac7a0b5c9ce21300

公钥：2dfc3beb9713ad2929a3775b31100bbd39d05d2d43e7c4e5c07b752112b6362e2963233add649bb5a8512246e3c9b975f57132181b5abe32afa60b2e677c790c

## StatusCode

一、区块链
1、登录

| 返回结果 | 结果说明 |
| :------: | :------: |
|  admin   |  管理员  |
|   user   | 普通用户 |
|  error   |  未注册  |

