SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
echo "scriptdir"
echo $SCRIPTDIR
FPC_TOP_DIR="${SCRIPTDIR}/../../.."
FABRIC_CFG_PATH="${SCRIPTDIR}/../../../integration/config"
FABRIC_SCRIPTDIR="${FPC_TOP_DIR}/fabric/bin"

. ${FABRIC_SCRIPTDIR}/lib/common_utils.sh
. ${FABRIC_SCRIPTDIR}/lib/common_ledger.sh

#this is the path that will be used for the docker build of the chaincode enclave
CC_PATH=${FPC_TOP_DIR}/demo/chaincode/helloworld/_build/lib/

CC_ID=helloworld_test
CC_VER="$(cat ${CC_PATH}/mrenclave)"
CC_EP="OR('SampleOrg.member')"
