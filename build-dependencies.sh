#!/bin/bash

# Installs yara and all required dependencies and packages them into a zip used by the lambda at runtime
# There is a requirements.txt in this project but this is only dependencies for running the tests.

yum update -y
yum install -y autoconf automake bzip2-devel gcc.x86_64 gcc-c++.x86_64 libarchive-devel libffi-devel \
        libtool libuuid-devel openssl-devel pcre-devel poppler-utils python3-pip python3-devel zlib-devel \
            wget make gcc-c++ xz libpng-devel python3-setuptools

# Compile YARA
YARA_VERSION=$1
wget https://github.com/VirusTotal/yara/archive/refs/tags/v$YARA_VERSION.tar.gz
tar -xzf v$YARA_VERSION.tar.gz
cd yara-$YARA_VERSION
./bootstrap.sh
./configure
make
make check  # Run unit tests
make install

# Install cryptography and yara-python
cd /
pip3 install --upgrade pip
mkdir pip
pip3 install --requirement requirements.txt --target pip

# Clean cryptography files
cd /pip
rm -r *.dist-info *.egg-info
find . -name __pycache__ | xargs rm -r
mv _cffi_backend.cpython-39-x86_64-linux-gnu.so _cffi_backend.so
cd cryptography/hazmat/bindings

# Gather pip files
cd /
mkdir lambda
cp -r pip/* lambda
mv lambda/yara.cpython-39-x86_64-linux-gnu.so lambda/yara.so

# Download UPX
cd /
wget https://github.com/upx/upx/releases/download/v3.94/upx-3.94-amd64_linux.tar.xz
tar -xf upx-3.94-amd64_linux.tar.xz
cp upx-3.94-amd64_linux/upx lambda
cp upx-3.94-amd64_linux/COPYING lambda/UPX_LICENSE

# Gather compiled libraries
cp /usr/bin/pdftotext lambda
cp /usr/lib64/libarchive.so.13 lambda
cp /usr/lib64/libfontconfig.so.1 lambda
cp /usr/lib64/libfreetype.so.6 lambda
cp /usr/lib64/libjbig.so.2.1 lambda
cp /usr/lib64/libjpeg.so.62 lambda
cp /usr/lib64/liblcms2.so.2 lambda
cp /usr/lib64/liblzma.so.5 lambda
cp /usr/lib64/liblz4.so.1 lambda
cp /usr/lib64/libopenjp2.so.7 lambda
cp /usr/lib64/libpcrecpp.so.0 lambda
cp /usr/lib64/libpng16.so lambda
cp /usr/lib64/libpoppler.so.123 lambda
cp /usr/lib64/libstdc++.so.6 lambda
cp /usr/lib64/libtiff.so.5 lambda
cp /usr/lib64/libxml2.so.2 lambda
cp /usr/lib64/libcrypto.so.3 lambda
cp /usr/lib64/libc.so.6 lambda

# Build Zipfile
cd lambda
zip -r dependencies.zip *
