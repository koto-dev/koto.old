#!/bin/bash
#$ patch -p1 < ./zcutil/win-build.diff
#$ sudo apt install mingw-w64
#$ sudo update-alternatives --config x86_64-w64-mingw32-gcc
#(configure to use POSIX variant)
#$ sudo update-alternatives --config x86_64-w64-mingw32-g++
#(configure to use POSIX variant)
#$ HOST=x86_64-w64-mingw32 ./zcutil/build.sh

HOST=x86_64-w64-mingw32 ./zcutil/build.sh
