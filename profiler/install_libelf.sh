#!/bin/bash

HOST=aarch64-linux-gnu
ZLIB="zlib-1.2.11"

# Install necessary packages (Debian-based distros)
sudo apt-get install intltool gettext automake autoconf

# Get elfutils sources
#git clone git://sourceware.org/git/elfutils.git

# Get Zlib sources & decompress them
# wget http://zlib.net/"$ZLIB".tar.gz
# tar -xf "$ZLIB".tar.gz

# Let's compile the Zlib first
ROOTDIR=$(pwd)
# cd $ZLIB

# CC="$HOST"-gcc ./configure --prefix=$ROOTDIR/libs/
# make -j4
# make install

cd $ROOTDIR/elfutils

aclocal
autoheader
autoconf
autoreconf -f -i
automake --add-missing

./configure --host=$HOST --prefix=$ROOTDIR/libs/ \
	    --with-zlib LDFLAGS="-L$ROOTDIR/libs/lib -lz" \
	    CFLAGS=-I$ROOTDIR/libs/include  \
	    PKG_CONFIG_PATH=$ROOTDIR/libs/lib/pkgconfig \
	    --enable-maintainer-mode \
	    --disable-libdebuginfod --disable-debuginfod

cd $ROOTDIR/elfutils/libeu
make -j4
make install

cd $ROOTDIR/elfutils/libelf

make -j4
make install

