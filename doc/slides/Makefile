
all:	zmailer-fuug@sea2000.ps

zmailer-fuug@sea2000.ps:  zmailer-fuug@sea2000.dvi
	dvips -t a4 -t landscape zmailer-fuug@sea2000

zmailer-fuug@sea2000.dvi: zmailer-fuug@sea2000.tex
	latex zmailer-fuug@sea2000.tex

clean:
	rm -f *~ *.aux *.dvi *.log
