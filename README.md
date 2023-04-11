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

{
  "bureau": [
    49624149884731608025010404971466914257400673330400294022575467063114007337404,
    39768071510817073226140262263206051208749279994486054090114595674368662421931,
    83429073784661175068881678637158095244962704506756893177541146272626920253954,
    54849056188089780465823175484348998292288214507429128119088710058752045778345
  ]
}
{
  "port":7000,
  "prev":83429073784661175068881678637158095244962704506756893177541146272626920253954,
  "keys": [
    63438572337355659774995434143178077830719805987432246025242266895333961833307,
    115266140337880486913605739389910472318846950459880883277686513585280292868977,
    7152170998764611911827368816069466304134331105983645086224302058620033416575,
    101350739687434834074873906692056699174500340023693291918368607557782767319198
  ]
  "account": [
    "e389dfa38820b564c0af0a4c038cc76d12e2153c563e36189a32bdcbffa92404df19eedf95df165776d070e63584d6242036df598627cf7049f9827d55726867",
    "ec7513e6893e24d6678f4b6942cfa34bd1810037249cae423f3a562902addf219e0c3b881c89a992952a0536a160dbadfb855bb3097df2b8f92e76742a351a13",
    "cd347c86269f021b863f46553d50fb091d3917286392298af8ac6058d28604468439fd9462c63530c1180ed146432ebb82a15470f0e546c3fdc7f057280f1775",
    "6e29607be394e1bd7d59b6d8b598707f2f6fb987887ab4bbc5b4d881f24b9aa80cecc98ee8bc93c367fd44a7de61ab476f5b0d25659668f181f416d192eaf992"
  ]
}
{
  "port":8000
  "prev":54849056188089780465823175484348998292288214507429128119088710058752045778345
  "keys": [
  12505204611044228039821354989705303947300663496284769889250480968805228002364,
  5511069461032492260798732555029243246468338633947931463091460679484338192045,
  47231507637426126233361877853849779368282032565842543950043599663858856465004,
  64649293304118322012981298004975479994670810756296244328966169335824837302029
  ],
  "account": [
  "780ac044dcae51b95d3815aefb76706367f2573401b33dfa47d00e4630d19f822992a55999ddd5b738baeaadd5531d141adae0362fa6743c6992459249480e81",
  "9e9672b8d54b03b3f30ce276865ab89d9d929c2b69d1c4a9c13dbbdb9dcbbed1aeb73a8da00b9ef0dd78ed0bc0a1b7124c0f6a80d728a8e160da1d99931916c3",
  "4bc016a2a49294e79192702193bb7afbd439cc646676ee39d21b2e7bb5417b465e42ee955d569f444d91c4bf2fb7ba66058f90318a0cf027f9f18ba9c69c8ac0",
  "9de70fefb27a49195595edd915ea3069fc35c9d8f8800592c14e044cc929042c74c507f2eddaca7f239938019d19b06d40a9f71389b1feef85bbb50447f10dbb"
  ]
}
{
  "port":5000,
  "prev":49624149884731608025010404971466914257400673330400294022575467063114007337404
  "keys": [
  64809792147571645334777786616009672900595087841768602845697900795765835271278,
  8518984573627322669470675711924768462752124183715055076006127038337295354764,
  59733733072806551411474857441341712884337735651521631332275368341159849307679,
  5116627648137779588250235919021548776376413580946961640627257160545758491143
  ],
  "account": [
  "9ec23f21a35adb1526b0879c3bd7303921045a00cec5efd74842707702e8a48fa6ea7b59568fbd41c01be169d650a2eefdeccf28d569c910af0350566a89070f",
  "25f917c61da0e8563afd2a3e809e7c1a85b77af57f4e90e01b5e6f7fcae8d1d1fe947450d43c18115b12ddc050bca906dd2fba511379627907e9ac82cdd28d6f",
  "6b56f82ce88e908eb7b12b64f1669e5ea3b9263403cb9413544122b025ca77c420c029dd41f49034ad05f2db52cced00b09305ea56bfa416dad06e930f1b480e",
  "01ad3e4d9979eed282b4344aa19b1b0d53e01e37fb1ab6bde9a0cd2786bb4b002b2d654736f68f774c12ffeefff57647ea4768ea0f5a3acc26b3b404f9a6be15"
  ]
}
{
  "port":6000,
  "prev":39768071510817073226140262263206051208749279994486054090114595674368662421931
  "keys": [
  46707732539576079422600686704015304433461040654688395347087636726336326534112,
  103872809729530045443544385997684965475035284617411954463276501204032654593032,
  68296884055544629704266813901534866090976874130826486506220949994895244298621,
  94210748623697879086743249261548082755936664348144364846390959382853183459713
  ],
  "account": [
  "7eaf3d500c77a47a7994dda96e4cb57bbdbb0de7c8ad31341dfeaed94b02132373a3cb33b0aafc37ed4229fac766b51f2d10decc112bbb181359d74b34c93e6a",
  "a60db50d7472c9bbc2a197f15b46cedffa059fada6e39e94725c990954e5c057934e7a937dbd73c9ecbb612da136a942460221f87c3a19a6d6a4a6238b1c3d64",
  "fe8d55576852c35a71b8ab035de07f58a80b4b094e059e1d83d08a3909550dff7991aa050925828bb14d3f2ba469b9f862e88c35d5a81b3d7655cb8d678e11f1",
  "ba941ea1d9b7155c933cc68e92c7de29bc6de4c273938bfd15ae9ad1364ecca740126e98112af93922b45d3600516893585501c70d923feacac4c5704241d745"
  ]
}

## StatusCode

一、区块链
1、登录

| 返回结果 | 结果说明 |
| :------: | :------: |
|  admin   |  管理员  |
|   user   | 普通用户 |
|  error   |  未注册  |

