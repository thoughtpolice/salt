#!/usr/bin/env sh

DEV=0
VERSION=nacl-20110221

# No configuration needed past this point
URL=http://hyperelliptic.org/nacl/$VERSION.tar.bz2
CURL="curl -f#L"
HSNACLDIR=$HOME/.hs-nacl
TARBALL=$HSNACLDIR/$VERSION.tar.bz2

say () {
    echo "==> " $1
    return 0
}

if [ $DEV -eq 1 ]; then
    CABAL=cabal-dev
else
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
    say "Tarball already downloaded."
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
    say "Using already-completed build."
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

# get test prerequisites
say "Grabbing test prerequisuites..."
#echo " cabal-dev install QuickCheck HUnit test-framework test-framework-quickcheck2 test-framework-hunit"
$CABAL install -v0 QuickCheck HUnit test-framework test-framework-quickcheck2 test-framework-hunit

# build with cabal 
say "Building with cabal..."
#echo " cabal-dev install --extra-include-dirs=$INCDIR --extra-lib-dirs=$LIBDIR --enable-tests"
$CABAL install --extra-include-dirs=$INCDIR --extra-lib-dirs=$LIBDIR --enable-tests $@

# test
echo 
say "Testing..."
./dist/build/properties/properties +RTS -N

echo
say "Completed"
