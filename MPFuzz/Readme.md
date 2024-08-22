# Installation

## Prerequisites

Install automake, mono package and some required packages

```shell
sudo apt-get install build-essential automake libtool libc6-dev-i386 python-pip g++-multilib mono-complete python-software-properties software-properties-common
```



Install gcc-4.4 and g++-4.4 (as Pin component in Peach has a compilation issue with newer version of gcc like gcc-5.4)

First add apt repository:

```shell
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
```

If you find that it just didn't work on your linux distribution and got failed at installing gcc/g++ 4.4 follow the commands below :

First edit the sources.list file:

```shell
sudo vim /etc/apt/sources.list
```

then add the following line to your sources.list file :

```shell
deb  http://dk.archive.ubuntu.com/ubuntu/  trusty  main  universe
```



Now:

```shell
sudo apt-get update
sudo apt install gcc-4.4
sudo apt install g++-4.4
```



## Build

```shell
./waf configure
./waf install
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



# Running

## Create shared memory for global field pool

```shell
cd /dev/shm
dd if=/dev/zero bs=1M count=1 of=${name-of-pool}
```

**Hint**: `$name-of-pool` should be replaced by any name you like.

## Parallel Fuzzing

Single fuzzing instance running command

```shell
export SHM_POOL_ENV=/dev/shm/${name-of-pool}
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe --usepool /path-to-mpfuzz/output/linux_x86_64_release/bin/samples/HelloWorld.xml
```

### 1. Launch Server Under Test

Use the `Process` Monitor to launch the server under test. The monitor will save the crash information when the server crashes.

``` shell
mono /path-to-mpfuzz/output/linux_x86_64_release/bin/mpfuzz.exe server.xml
```

### 2. Launch Parallel Fuzzing Instances

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


# Usage

Options for using field pool to sync key field between fuzzing instances.

```
--usepool: MPFuzz use the field pools to sync information between instances;
```


# Branch Coverage 

Build compiler in directory `compiler`, follow the instruction in it.

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

