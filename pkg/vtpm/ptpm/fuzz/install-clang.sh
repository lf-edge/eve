#!/bin/bash
CLANG_VERSION=16.0.0
echo "Choose arch (number):"
echo "1) aarch64 2) x86_64"
read -r arch

if [ "$arch" -eq 1 ]; then
    CLANG_DIR=clang+llvm-$CLANG_VERSION-aarch64-linux-gnu
else
    CLANG_DIR=clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-18.04
fi

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG_VERSION/$CLANG_DIR.tar.xz
tar xfJ $CLANG_DIR.tar.xz
sudo rm -rf /usr/local/bin/clang* /usr/local/lib/clang
sudo cp -rf  $CLANG_DIR/bin/*  /usr/local/bin
sudo cp -rf  $CLANG_DIR/lib/clang  /usr/local/lib
rm -rf $CLANG_DIR
