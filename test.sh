#!/usr/bin/env sh
cabal-dev clean && cabal-dev install --extra-include-dirs=/home/a/src/nacl-20110221/build/link/include/amd64 --extra-lib-dirs=/home/a/src/nacl-20110221/build/link/lib/amd64 --enable-tests && cabal-dev test && echo && cat dist/test/NaCl-0.1-properties.log
