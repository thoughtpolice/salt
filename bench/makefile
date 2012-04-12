GITSHA1=`git log --pretty=format:%H | head -1`
HOST=`uname -n -s -r -m`
CPU=`cat /proc/cpuinfo | grep "model name" | head -1 | awk '{$$1="";$$2="";$$3=""; print $$0}'`

all: testdata run
testdata:
	dd if=/dev/urandom of=testdata bs=1M count=1024
Bench: Bench.hs
	ghc -O2 Bench
run:
	./Bench -o results.html $(BENCH)
clean:
	rm -f *.o *.hi Bench *.png *.html *~
