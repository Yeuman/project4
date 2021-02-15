# CMake generated Testfile for 
# Source directory: /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/common/crypto/pdo/common/tests/crypto
# Build directory: /usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/common/crypto/_build/pdo/common/tests/crypto
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(utest "env" "LD_LIBRARY_PATH=:" "./utest")
set_tests_properties(utest PROPERTIES  WORKING_DIRECTORY "/usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/common/crypto/_build/tests")
add_test(ttest "./ttest")
set_tests_properties(ttest PROPERTIES  WORKING_DIRECTORY "/usr/local/go/bin/src/github.com/hyperledger-labs/fabric-private-chaincode/common/crypto/_build/tests")
subdirs("trusted/enclave")
