#!/usr/bin/env bash

DEV=YES
VERSION=nacl-20110221

# No configuration needed past this point
URL=http://hyperelliptic.org/nacl/$VERSION.tar.bz2
CURL="curl -f#L"
HSNACLDIR=$HOME/.hs-nacl
TARBALL=$HSNACLDIR/$VERSION.tar.bz2

say () { echo "==> " $1; return 0; }
onoes () { echo "!!> " $1; exit -1; }

if [ "$DEV" == "YES" ]; then
    say "In development mode... "
    if [ ! -z "$HSENV_NAME" ] || [ ! -z "$VIRTHUALENV_NAME" ]; then
        say "Detected hsenv virtual environment ($HSENV_NAME), using 'cabal'"
        CABAL=cabal
    else
        say "Using 'cabal-dev'"
        CABAL=cabal-dev
    fi
else
    say "Using release tarball"
    CABAL=cabal
fi

# initialize
if [ ! -d "$HSNACLDIR" ]; then
    mkdir $HSNACLDIR
fi

# download
if [ ! -f "$TARBALL" ]; then
    say "Downloading $VERSION.tar.bz2..."
    $CURL $URL -o $TARBALL
else
    say "NaCl source tarball already downloaded."
fi

# extract
if [ ! -d "$HSNACLDIR/$VERSION" ]; then
    say "Extracting"
    tar -jxf $TARBALL -C $HSNACLDIR
else
    say "Source code already extracted."
fi

# build!
if [ ! -d "$HSNACLDIR/$VERSION/build" ]; then
    say "Now building $VERSION"
    say "This is going to take a while, grab some coffee..."
    D=`pwd`
    cd $HSNACLDIR/$VERSION && ./do && cd $D
    say "Done"
else
    say "Using already-completed NaCl build."
fi

SHORTHOST=`hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]'`
ARCHGREP=`ghc --info | grep x86_64`
if [ "$ARCHGREP" != "" ]; then
    ARCH=amd64
else
    ARCH=x86
fi

say "ARCH = $ARCH, HOST = $SHORTHOST"

INCDIR=$HSNACLDIR/$VERSION/build/$SHORTHOST/include/$ARCH/
LIBDIR=$HSNACLDIR/$VERSION/build/$SHORTHOST/lib/$ARCH/


if [ "$HLINT" == "YES" ]; then
    say "hlint'ing source"
    hlint -c --ignore="Use camelCase" --ignore="Eta reduce" --cpp-include=$INCDIR bench examples src tests
    exit 0
fi

if [ "$CLEAN" == "YES" ]; then
    say "Cleaning..."
    $CABAL clean -v0
fi

# get test prerequisites
if [ "$DEV" == "YES" ] || [ "$NACLTEST" == "YES" ]; then
    say "Grabbing test prerequisuites..."
    C="install -v0 QuickCheck HUnit test-framework test-framework-quickcheck2 test-framework-hunit"
    # echo $CABAL $C
    $CABAL $C
fi

# build with cabal 
say "Building with $CABAL..."

C="install --extra-include-dirs=$INCDIR --extra-lib-dirs=$LIBDIR"
if [ "$DEV" == "YES" ] || [ "$NACLTEST" == "YES" ]; then
    C="$C --enable-tests"
    # kill old test file
    rm -f ./dist/build/properties/properties
fi

if [ "$HADDOCK" == "YES" ]; then
    C="$C --enable-documentation"
fi

#echo $CABAL $C $@
$CABAL $C $@

# test
if [ "$DEV" == "YES" ] || [ "$NACLTEST" == "YES" ]; then
    if [ ! -f ./dist/build/properties/properties ]; then
        onoes "Failure to build tests"
    else
        say "Testing..."
        ./dist/build/properties/properties -a200 +RTS -N
    fi
fi

say "Completed"
