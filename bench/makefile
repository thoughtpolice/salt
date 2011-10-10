GITSHA1=`git log --pretty=format:%H | head -1`
HOST=`uname -n -s -r -m`
CPU=`cat /proc/cpuinfo | grep "model name" | head -1 | awk '{$$1="";$$2="";$$3=""; print $$0}'`

all: Bench
	./mkhtml.hs "$(GITSHA1)" "`date`" "$(HOST)" "$(CPU)" `ls -v *.png` > results.html
Bench: Bench.hs
	ghc -O2 Bench
	./Bench -k png:640x480 $(BENCH)
clean:
	rm -f *.o *.hi Bench *.png *.html *~
