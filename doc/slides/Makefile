
all:	zmailer-fuug@sea2000.ps zmailer-fuug@sea2000.pdf

zmailer-fuug@sea2000.ps:  zmailer-fuug@sea2000.dvi
	dvips -t a4 -t landscape zmailer-fuug@sea2000
	-if [ -d /net/mea/home/ftp/zmailer ]; then \
	  gzip -9 < zmailer-fuug@sea2000.ps > /net/mea/home/ftp/zmailer/zmailer-fuug@sea2000.ps.gz; \
	fi

zmailer-fuug@sea2000.dvi: zmailer-fuug@sea2000.tex
	latex zmailer-fuug@sea2000.tex

zmailer-fuug@sea2000.pdf: zmailer-fuug@sea2000.ps
	ps2pdf zmailer-fuug@sea2000.ps
	-cp  zmailer-fuug@sea2000.pdf /net/mea/home/ftp/zmailer/

clean:
	rm -f *~ *.aux *.dvi *.log
