#!/bin/sh
ZEDEDA=$HOME/go/src/github.com/zededa
ZCLI_ZEDEDA_PATH='/root/go/src/github.com/zededa'

usage() {
   echo "./BuildInstallBaseImage.sh -s <ZedCloud Server URL> -u <ZedCloud Username> -p <Zedcloud Password>"
   echo "       -t <tag for go-provision docker image> -d <device-name>"
   echo "./BuildInstallBaseImage.sh -h"
   echo "   -t <tag for go-provision docker image>"
   echo "      Name of the tag to use for the docker image for go-provision."
   echo "   -d <device name>"
   echo "      Name of the device to upgrade. The device should be configured in zed cloud already. "
   exit 0
}

#Parse Args
while getopts "d:hp:s:t:u:" opt; do
  case ${opt} in
    d ) DEVICE=$OPTARG; echo "DEVICE = $DEVICE" ;;
    h ) usage ;;
    p ) ZCLI_PASSWORD=$OPTARG; echo "ZCLI_PASSWORD = xxxxx" ;;
    s ) SERVER=$OPTARG; echo "SERVER = $SERVER" ;;
    t ) TAG=$OPTARG; echo "TAG = $TAG" ;;
    u ) ZCLI_USER=$OPTARG; echo "ZCLI_USER = $ZCLI_USER" ;;
    \? ) usage ;;
  esac
done

# Delete all arguments passed..
shift $((OPTIND -1))

# Check for Mandatory arguments..
if [ -z $SERVER ]
then
   echo "-s <ZedCloud Server> is a Mandatory argument"
   exit 1
fi

if [ -z $ZCLI_USER ]
then
   echo "-u <ZedCloud UserName> is a Mandatory argument"
   exit 1
fi
if [ -z $ZCLI_PASSWORD ]
then
   echo "-p <ZedCloud Password> is a Mandatory argument"
   exit 1
fi
if [ -z $TAG ]
then
   echo "-t <tag for go-provision docker image> is a Mandatory argument"
   exit 1
fi
if [ -z $DEVICE ]
then
   echo "-d <device-name> is a Mandatory argument"
   exit 1
fi

ZCLI_CONFIG_CMD="zcli configure -s $SERVER  -u $ZCLI_USER -P $ZCLI_PASSWORD -O text"
echo "ZCLI_CONFIFG_CMD: $ZCLI_CONFIG_CMD"


echo "==========================================="
echo "Building go-provision docker image"
echo "==========================================="
cd $ZEDEDA/go-provision
echo "docker build -t $TAG ."
docker build -t $TAG .
echo "\n\n\n"

echo "==========================================="
echo "Building zenbuild rootfs.img"
echo "==========================================="
cd $ZEDEDA/zenbuild
echo "ZTOOLS_TAG=$TAG make rootfs.img"
ZTOOLS_TAG=$TAG make rootfs.img
echo "\n\n\n"

IMAGE=`grep contents images/rootfs.yml | awk '{print $2}'`
echo "==========================================="
echo "IMAGE=$IMAGE"
echo "==========================================="
#contents: '0.0.0-fixes-6640a81b-dirty-2018-12-17.22.10-amd64'
#IMAGE='0.0.0-6640a81b-dirty-2018-12-18.23.51-amd64'

echo "\n\n\n"

echo "Start zcli container."
# This looks-fori/starts a container named "zcli".
zcliStatus=`docker ps -a --filter name=zcli --format "{{.Status}}"`
if [[ "$zcliStatus" =~ "Up" ]]
then
   echo "zcli already running";
elif [[ "$zcliStatus" =~ "Exited" ]]
then
   echo "zcli container not running. Restarting it."
   docker restart zcli
else
   docker pull zededa/zcli-dev:latest
   docker run -v $HOME:/root -it --name zcli  zededa/zcli-dev:latest
fi

# In ZCLI:
IMAGE_PATH="$ZCLI_ZEDEDA_PATH/zenbuild/rootfs.img"
echo "IMAGE_PATH = $IMAGE_PATH"

zcli_exec() {
   echo "docker exec zcli /bin/sh -c $1"
   docker exec zcli /bin/sh -c "$1"
}

echo "\n\n\n"
echo "=================================================================="
echo "Executing ZCLI commands to create / upload image and update device"
echo "=================================================================="
zcli_exec "$ZCLI_CONFIG_CMD"
zcli_exec "zcli login"
zcli_exec "zcli image create --datastore-name=Zededa-AWS-Image --type=baseimage --image-format=qcow2 $IMAGE"
zcli_exec "zcli image upload $IMAGE --path=$IMAGE_PATH"
echo "=================\n Waiting for Image Upload to Complete======"; sleep 60; echo "=== WAIT FOR UPLOAD DONE ===="
zcli_exec "zcli device baseimage-update $DEVICE --image=$IMAGE"
zcli_exec "zcli device baseimage-update $DEVICE --image=$IMAGE --activate"
zcli_exec "zcli device show --detail $DEVICE"

