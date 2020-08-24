#!/bin/bash
set -e

# bash script to build kernel proper along with out of band modules

LOG_FILE=/tmp/kernel-build.log
rm -Rf $LOG_FILE
exec &> >(tee -a "$LOG_FILE")

CONTAINER_BLD='no'
GIT_USERNAME='ani sinha'
GIT_EMAIL='ani@anisinha.ca'

KERNEL_VERSION_aarch64=4.19.5
KERNEL_VERSION_x86_64=4.19.5

KERNEL_VERSION="$(eval echo \$KERNEL_VERSION_"$(uname -m)")"
KERNEL_MAJOR="$(echo "$KERNEL_VERSION" | cut -f1 -d.)"
KERNEL_PATCHLEVEL="$(echo "$KERNEL_VERSION" | cut -f2 -d.)"
KERNEL_SERIES=$KERNEL_MAJOR.$KERNEL_PATCHLEVEL.x
KERNEL_GIT_TREE="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
KERNEL_SOURCE=${KERNEL_SOURCE:-$KERNEL_GIT_TREE}
KERNEL_MODULE_INSTALL_PATH=/tmp/kernel-modules
KERN_HEADERS_DIR=/tmp/kernel-headers

ZFS_VERSION=0.8.4
ZFS_COMMIT=zfs-${ZFS_VERSION}
ZFS_REPO=https://github.com/zfsonlinux/zfs.git

REALTEK_DIR=/tmp/rtl8821CU
REALTEK_TAG=93b04bfcd293fdd7d98d5a7c964ae9416a40159c

OUTPUT_ARCHIVE=out.tar.gz

PREFIX=/tmp/kernel-build

[[ -z "$1" ]] || PREFIX=$1
[[ -z "$2" ]] || OUTPUT_ARCHIVE=$2

# TODO: $3 indicates if this script is running within a container. A non-zero
# value means we are within a docker container and hence some operations may
# be skipped. We need to find out a better means of checking for a containerized
# environment. Maybe:
# https://stackoverflow.com/questions/23513045/how-to-check-if-a-process-is-running-inside-docker-container
[[ ! -z "$3" ]] && CONTAINER_BLD='yes'

echo "performing clean build ..."
[[ -d $KERNEL_MODULE_INSTALL_PATH ]] && rm -Rf $KERNEL_MODULE_INSTALL_PATH
[[ -d $KERN_HEADERS_DIR ]] && rm -Rf $KERN_HEADERS_DIR
[[ -d $REALTEK_DIR ]] && rm -Rf $REALTEK_DIR
[[ x$CONTAINER_BLD == "xno" ]] && [[ -d $PREFIX ]] && rm -Rf $PREFIX

function cleanup {
    echo "performing cleanup ..."
    rm -Rf $KERNEL_MODULE_INSTALL_PATH
    rm -Rf $KERN_HEADERS_DIR
    rm -Rf $REALTEK_DIR
    rm -Rf $PREFIX
}

trap cleanup EXIT

if [ x$CONTAINER_BLD == "xno" ]; then
    mkdir -p $PREFIX
    cp -r . $PREFIX/
    cd $PREFIX
else # within the container we need to set the git identity
    git config --global user.email \"$GIT_EMAIL\"
    git config --global user.name \"$GIT_USERNAME\"
fi

echo "generating a shallow clone of the kernel git tree for version $KERNEL_VERSION ..."
[ -d linux-${KERNEL_VERSION} ] || \
    git clone --depth 1 -b v${KERNEL_VERSION} --progress ${KERNEL_SOURCE} linux-${KERNEL_VERSION}

# creating a proper local branch which tracks the remote branch
cd linux-${KERNEL_VERSION} && \
    git checkout --progress -b ${KERNEL_VERSION} v${KERNEL_VERSION}

mv -f $PREFIX/linux-${KERNEL_VERSION} $PREFIX/linux
rm -Rf $PREFIX/out
mkdir $PREFIX/out && echo "KERNEL_SOURCE=${KERNEL_SOURCE}" > $PREFIX/out/kernel-source-info

# Apply local patches
cd $PREFIX/linux
[ ! -d $PREFIX/patches-"${KERNEL_SERIES}" ] || for patch in $PREFIX/patches-"${KERNEL_SERIES}"/*.patch; do \
        echo "Applying $patch"; \
        git am "$patch"; \
    done

case $(uname -m) in \
    x86_64) \
        KERNEL_DEF_CONF=$PREFIX/linux/arch/x86/configs/x86_64_defconfig; \
        ;; \
    aarch64) \
        KERNEL_DEF_CONF=$PREFIX/linux/arch/arm64/configs/defconfig; \
        ;; \
    esac

cp $PREFIX/kernel_config-${KERNEL_SERIES}-$(uname -m) ${KERNEL_DEF_CONF}
if [ -n "${EXTRA}" ]; then
    sed -i "s/CONFIG_LOCALVERSION=\"-linuxkit\"/CONFIG_LOCALVERSION=\"-linuxkit${EXTRA}\"/" ${KERNEL_DEF_CONF};
    if [ "${EXTRA}" = "-dbg" ]; then
        sed -i 's/CONFIG_PANIC_ON_OOPS=y/# CONFIG_PANIC_ON_OOPS is not set/' ${KERNEL_DEF_CONF};
    fi
    cat $PREFIX/kernel_config${EXTRA} >> ${KERNEL_DEF_CONF}
fi

make defconfig
make oldconfig

echo "difference between .config and ${KERNEL_DEF_CONF} ..."
[ -z "${EXTRA}" ] && diff -cw .config ${KERNEL_DEF_CONF} || true

# create a tarball of the prepared tree
echo "building a tar archive of the prepared kernel source tree"
git archive --format tar -v -o linux-${KERNEL_VERSION}.tar --prefix=linux-$KERNEL_VERSION/ HEAD 2>/dev/null
mv linux-${KERNEL_VERSION}.tar $PREFIX/out

echo "building the linux kernel ..."
make -j "$(getconf _NPROCESSORS_ONLN)" KCFLAGS="-fno-pie"
case $(uname -m) in \
    x86_64) \
        cp arch/x86_64/boot/bzImage $PREFIX/out/kernel; \
        ;; \
    aarch64) \
        cp arch/arm64/boot/Image.gz $PREFIX/out/kernel; \
        ;; \
    esac
cp System.map $PREFIX/out && \
    ([ "${EXTRA}" = "-dbg" ] && cp vmlinux $PREFIX/out || true)

# Modules
make INSTALL_MOD_PATH=$KERNEL_MODULE_INSTALL_PATH modules_install

# Out-of-tree, open source modules
#  * ZFS on Linux
echo "building ZFS ..."
mkdir $PREFIX/zfs && cd $PREFIX/zfs
git clone --depth 1 -b ${ZFS_COMMIT} ${ZFS_REPO} .
git checkout --progress -b ${ZFS_COMMIT} ${ZFS_COMMIT}
./autogen.sh && ./configure --with-linux=$PREFIX/linux && ./scripts/make_gitrev.sh && \
    make -C module -j "$(getconf _NPROCESSORS_ONLN)" && \
    make -C module INSTALL_MOD_PATH=$KERNEL_MODULE_INSTALL_PATH install

# Out-of-tree, creepy modules
#  * Maxlinear USB (option #2 https://github.com/lipnitsk/xr/archive/master.zip)
echo "building Exar USB serial driver ... "
# wget https://www.maxlinear.com/document?id=21651 /tmp/xr.zip
# unzip -d /tmp /tmp/xr.zip
make -C $PREFIX/linux INSTALL_MOD_PATH=$KERNEL_MODULE_INSTALL_PATH \
     M=$PREFIX/xr modules modules_install

echo "building Realtek rtl8821CU ..."
rm -Rf $REALTEK_DIR
git clone https://github.com/brektrou/rtl8821CU.git $REALTEK_DIR
cd $REALTEK_DIR ; git checkout $REALTEK_TAG
make -C $REALTEK_DIR KSRC=$PREFIX/linux modules
install -D -p -m 644 $REALTEK_DIR/8821cu.ko \
	$(echo $KERNEL_MODULE_INSTALL_PATH/lib/modules/*)/kernel/drivers/net/wireless/realtek/rtl8821cu/8821cu.ko

# Device Tree Blobs
# FIXME: we will switch to a native make INSTALL_DTBS_PATH=$KERNEL_MODULE_INSTALL_PATH/boot/dtb dtbs_install at some point
if [ "$(uname -m)" = aarch64 ]; then
    mkdir -p $KERNEL_MODULE_INSTALL_PATH/boot/dtb/eve
    ./scripts/dtc/dtc -O dtb -o $KERNEL_MODULE_INSTALL_PATH/boot/dtb/eve/eve.dtb -I dts /eve.dts
    strip --strip-debug `find $KERNEL_MODULE_INSTALL_PATH/lib/modules/*/extra -name \*.ko`
fi

# Package all the modules up
DVER=$(basename $(find $KERNEL_MODULE_INSTALL_PATH/lib/modules/ -mindepth 1 -maxdepth 1))
cd $KERNEL_MODULE_INSTALL_PATH/lib/modules/$DVER
rm build source && ln -s /usr/src/linux-headers-$DVER build
cd $KERNEL_MODULE_INSTALL_PATH && tar cvf $PREFIX/out/kernel.tar .

# Headers (userspace API)
rm -Rf $KERN_HEADERS_DIR
mkdir -p $KERN_HEADERS_DIR/usr
cd $PREFIX/linux
make INSTALL_HDR_PATH=$KERN_HEADERS_DIR/usr headers_install
cd $KERN_HEADERS_DIR && tar cvf $PREFIX/out/kernel-headers.tar usr

# Headers (kernel development)
DVER=$(basename $(find $KERNEL_MODULE_INSTALL_PATH/lib/modules/ -mindepth 1 -maxdepth 1))
dir=/tmp/usr/src/linux-headers-$DVER
rm -Rf $dir
mkdir -p $dir
cp $PREFIX/linux/.config $dir && cp $PREFIX/linux/Module.symvers $dir
cd $PREFIX/linux
find . -path './include/*' -prune -o \
     -path './arch/*/include' -prune -o \
     -path './scripts/*' -prune -o \
     -type f \( -name 'Makefile*' -o -name 'Kconfig*' -o -name 'Kbuild*' -o \
     -name '*.lds' -o -name '*.pl' -o -name '*.sh' \) | \
    tar cvf - -T - | (cd $dir; tar xf -)
cd /tmp && tar cvf $PREFIX/out/kernel-dev.tar usr/src

cp $LOG_FILE $PREFIX/out/
echo "generating the final output archive ..."
rm -f $OUTPUT_ARCHIVE && cd $PREFIX && tar cvzf $OUTPUT_ARCHIVE $PREFIX/out && mv $OUTPUT_ARCHIVE /tmp/
