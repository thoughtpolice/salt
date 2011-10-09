all: Bench
	./mkhtml.hs "`git log --pretty=format:%H | head -1`" "`date`" "`uname -n -s -r -m`" `ls -v *.png` > results.html
Bench:
	ghc -O2 Bench
	./Bench -k png:640x480
clean:
	rm -f *.o *.hi Bench *.png *.html *~
