# MPFuzz

MPFuzz a parallel fuzzing tool designed to secure IoT messaging protocols through collaborative packet generation. The approach leverages the critical role of certain fields within IoT messaging protocols that specify the logic for message forwarding and processing by protocol brokers.
In this repository, we put a prototype version of MPFuzz. It is implemented in C# language and reuses the structure of Pits, also the basic running framework of the traditional black-box Peach Fuzzer (community version v3.0). The executable files are all in the directory [executable](./executable/README.md).


## Prerequisites

- build-essential
- automake
- libtool
- libc6-dev-i386
- python-pip
- g++-multilib
- mono-complete
- python-software-properties
- software-properties-common


Install automake, mono package and some required packages

```shell
sudo apt update
sudo apt install build-essential automake libtool libc6-dev-i386 python-pip g++-multilib mono-complete python-software-properties software-properties-common
```

## Build

```shell
./waf configure
./waf install -j 8 -o output
```

Setup environment variables:

append the following entries in the shell configuration file (`~/.bashrc`).

```shell
export PATH=/path-to-mpfuzz/:$PATH
export LD_LIBRARY_PATH=/path-to-mpfuzz/:$LD_LIBRARY_PATH
```

**or** execute the following shell (**not always safe!**):

```shell
bash setup_env.sh
```


## Running

### Create shared memory for global field pool

```shell
cd /dev/shm
dd if=/dev/zero bs=1M count=1 of=${name-of-pool}
```

**Hint**: `$name-of-pool` should be replaced by any name you like.

### Parallel Fuzzing

Single fuzzing instance running command

```shell
export SHM_POOL_ENV=/dev/shm/${name-of-pool}
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe --usepool /path-to-mpfuzz/output/linux_x86_64_release/bin/samples/HelloWorld.xml
```

#### 1. Launch Server Under Test

Use the `Process` Monitor to launch the server under test. The monitor will save the crash information when the server crashes.

``` shell
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe server.xml
```

#### 2. Launch Parallel Fuzzing Instances

Run the fuzzing instances in different terminals without the monitor, while setting the same environment variable `SHM_POOL_ENV` to indicate the global field pool.

``` shell
export SHM_POOL_ENV=/dev/shm/${name-of-pool}
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe --usepool test_f1.xml &


export SHM_POOL_ENV=/dev/shm/${name-of-pool}
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe --usepool test_f2.xml &

...

export SHM_POOL_ENV=/dev/shm/${name-of-pool}
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe --usepool test_fn.xml &
```

> Use the `Random` MutationStrategy for each instances.


### Usage

Options for using field pool to sync key field between fuzzing instances.

```
--usepool: MPFuzz use the field pools to sync information between instances;
```

## Files:
MPFuzz command line program:
- MPFuzz.exe

MPFuzz Engine (based on Peach's framework):
- MPFuzz.Core.dll
- MPFuzz.Core.OS.Linux.dll
- MPFuzz.Core.Test.dll
- MPFuzz.Core.Test.OS.Linux.dll

Thirdparty dependence:
- NLog.dll
- Ionic.Zip.dll
- nunit.framework.dll
- Renci.SshNet.dll
- SharpPcap.dll
- ZeroMQ.dll
- PacketDotNet.dll
- IronPython.StdLib.zip


# Pit

### Monitor Example

(1) Don't restart on each test

```xml
...

<Agent name="LocalAgent">
  <Monitor class="Process">
    <Param name="Executable" value="/path-to-under-test-program/" />
    <Param name="Arguments" value="...options..." />
    <Param name="RestartOnEachTest" value="false" />
    <Param name="FaultOnEarlyExit" value="true" />
  </Monitor>
</Agent>

<Test name="Default">
  <Agent ref="LocalAgent" />
  ...
</Test>
```

### Data Element and Attribute:

Attribute 'sync' for specifies the fields that need to be synchronized, similar to the usage of the attribute mutable, but the default value is `false`.

For example, in MQTT protocol:

```xml
  <Topic name="topic" size="64" value="tpc/test" endian="network" mutable="true" sync="true"/>
```

For example, in AMQP protocol:

```xml
  <URI name="routekey" size="72" value="route.key" endian="network" mutable="true" sync="true"/>
```



# Branch Coverage 

## Requirements:
- clang (version 12.0.0+)

## Build
Build compiler in directory `compiler`, follow the instruction in it.


## Usage

Replace the original compiler (`clang` or `gcc`) with `MPFuzz-clang` (`MPFuzz-clang++`) when building a program, e.g.:

a. autoconf and make:

```shell
CC=/path-to-compiler/MPFuzz-clang CXX=/path-to-compiler/MPFuzz-clang++ ./configure [...options...]  # change complier
```

b. cmake:

```shell
cmake -DCMAKE_C_COMPILER=/path-to-compiler/MPFuzz-clang -DCMAKE_CXX_COMPILER=/path-to-compiler/MPFuzz-clang++ [..options..] ../src    # change complier
```

Before launching the server under test, you need to set two environment variables to help to dump the branch coverage.

```shell
cov_edge_path="/dev/shm/edge"
cov_bitmap_path="/dev/shm/bitmap"

dd if=/dev/zero of=${cov_edge_path}  bs=10M count=1
dd if=/dev/zero of=${cov_bitmap_path} bs=10M count=1

SHM_ENV_VAR=${cov_bitmap_path} LUCKY_GLOBAL_MMAP_FILE=${cov_edge_path}  \
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe server.xml
```

Then use a python3 script to collect the branch coverage during fuzzing.
```shell
python3 cov_collect.py ${cov_edge_path} ${cov_file_path} &
```