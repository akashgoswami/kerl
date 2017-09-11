#How to build

git submodule update --init
cd external/bignum/
make out
cd ../../
make

Then run the tests
./kerltest
