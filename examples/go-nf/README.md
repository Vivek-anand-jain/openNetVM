```
git clone https://github.com/vivek-anand-jain/opennetvm
cd opennetvm
git submodule update --init --recursive
export ONVM_HOME=`pwd`
export RTE_SDK=`pwd`/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

# Building DPDK
cd scripts
./install.sh

# Building ONVM
cd $ONVM_HOME/onvm
make

# Building GO based handler
cd $ONVM_HOME/example/go-nf
export CGO_CFLAGS="-m64 -pthread -O3 -march=native -I${RTE_SDK}/${RTE_TARGET}/include -I${ONVM_HOME}/onvm/onvm_nflib/ -I${ONVM_HOME}/onvm/lib/"
export CGO_LDFLAGS="`cat $RTE_SDK/$RTE_TARGET/lib/ldflags.txt` ${ONVM_HOME}/onvm/onvm_nflib/${RTE_TARGET}/libonvm.a ${ONVM_HOME}/onvm/lib/${RTE_TARGET}/lib/libonvmhelper.a -lm"
go build -o go-nf.so -buildmode=c-archive go-nf.go
make
```
