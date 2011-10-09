all:
	ghc -O2 Bench
	./Bench -k png:640x480
	./mkhtml.hs "`date`" "`uname -n -s -r -m`" `ls -v *.png` > results.html
clean:
	rm -f *.o *.hi Bench *.png *.html *~
