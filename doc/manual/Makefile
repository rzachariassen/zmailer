#
# GNU-Makefile for ZMailer manual
#

#
#  Utilizing 
#

PARTS=	zmanual.sgml		zmanual-cover.sgml		\
	zadministration.sgml    zref-router.sgml		\
	zapp-filefmts.sgml      zref-scheduler.sgml		\
	zapp-listmgrs.sgml      zref-sendmail.sgml		\
	zapp-scripts.sgml       zref-smtpserver.sgml		\
	zapp-ssl-lang.sgml      zref-transport-agents.sgml	\
	zapp-tragents.sgml      zref-utilities.sgml		\
	zinstall.sgml           zref-zmailer3.sgml		\
	zreference.sgml		zref-rmail.sgml			\
	ztutorial.sgml		zappendices.sgml		\
	zadm-dnsissues.sgml	zadm-router.sgml		\
	zadm-sm.sgml		zadm-logging.sgml		\
	zadm-scheduler.sgml	zadm-smtpserver.sgml		\
	zadm-queues.sgml	zadm-security.sgml		\
	zmanual.dsl

FIGS   :=	msgmodl.fig msgrout.fig zmailer-logo.fig \
		zmdirs.fig zmprocs.fig

FIGEPS :=	$(FIGS:%.fig=%.eps)
FIG_PS :=	$(FIGS:%.fig=%.ps)
FIGGIF :=	$(FIGS:%.fig=%.gif)

# set and export TEXINPUTS
TEXINPUTS=$(LATEX2HTMLLIB):$(LINUXDOCLIB):$$TEXINPUTS:
TEXENV=  TEXINPUTS=$(TEXINPUTS);export TEXINPUTS;


GIFS = $(L2HGIFS) zmailer-logo2.gif

all:
	@echo "make tag choices: clean dist html dvi ps pdf"

dvi:	zmanual.dvi
ps:	zmanual.ps
pdf:	zmanual.pdf
html:	zmanual.html
dist:	manual_parts.tar.gz

zmailer-logo2.gif zlogo: zmailer-logo2.gif-green
	cp -p zmailer-logo2.gif-green zmailer-logo2.gif

zmailer-logo2.gif-green: zmailer-logo.ps

gifs: $(FIGGIF)

$(L2HGIFS):

zmanual.html: gifs $(PARTS)
	rm -rf zmanual
	DB_STYLESHEET=`/bin/pwd`/zmanual.dsl   sh -x  ./db2html zmanual.sgml
	#sh -x  ./db2html zmanual.sgml
	cp -p *.gif zmanual/

zmanual.ps: zmanual.dvi $(FIGEPS)
	dvips -ta4 -ozmanual.ps zmanual.dvi

zmanual.dvi: $(PARTS) $(FIGEPS) zmanual.sgml
	STYLESHEET=`/bin/pwd`/zmanual.dsl   sh -x  ./db2dvi zmanual.sgml

zmanual.pdf: $(PARTS) $(FIGEPS) zmanual.sgml
	STYLESHEET=`/bin/pwd`/zmanual.dsl   sh -x  ./db2pdf zmanual.sgml

distclean clean:
	# Leave "zmanual.ps" in place, if it exists
	rm -f *~ *.html *.eps *.gif *.bak *.dvi *.toc *.lof
	rm -f *.css *.aux *.ptr *.old *.ilg *.gls *.cb *.glo *.log
	rm -rf l2h[1-9][0-9]* *sections.pl *internals.pl *index.pl
	rm -f *contents.pl *.ind *.idx *images.pl *table.pl
	rm -f [A-Z]*images.* *labels.pl *figure.pl IMG_PAR*
	rm -f TEXENV *.ps.gz *.xbm *.png
	rm -f *.gif-green


.SUFFIXES: .gif .fig .eps .ps .gif-green

%.gif: %.ps
	rm -f $@.ppm
	ghostscript -dNOPAUSE -sPAPERSIZE=a3 -sDEVICE=ppm -sOutputFile=$@.ppm $^ -c quit
	if [ ! -f $@.ppm ] ; then exit 1 ;fi # No file, abort!
	pnmcrop < $@.ppm | ppmtogif -transparent white > $@
	rm -f $@.ppm

%.gif-green: %.ps
	rm -f $@.ppm
	ghostscript -dNOPAUSE -sPAPERSIZE=a3 -sDEVICE=ppm -sOutputFile=$@.ppm $^ -c quit
	if [ ! -f $@.ppm ] ; then exit 1 ;fi # No file, abort!
	pnmcrop < $@.ppm | ppmtogif -transparent green > $@
	rm -f $@.ppm

%.ps: %.fig
	fig2dev -Lps -c -P -p x -z A3 -m 1.0000 -x 0 -y 0 -n $@ $< $@

zmanual-logo.eps: zmanual-logo.fig
	fig2dev -Lps -c -p x -z A3 -m 1.0000 -x 0 -y 0 -n $@ $< $@

%.eps: %.fig
	fig2dev -Lps -c -p x -z A3 -m 0.5000 -x 0 -y 0 -n $@ $< $@

#%.pdf: %.ps
#	gs510 -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile=$@ $^ -c quit


$(FIG_PS): $(FIGS)
$(FIGEPS): $(FIGS)

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS) $(FIGS)
	tar -cf manual_parts.tar Makefile $(PARTS) $(FIGS)
	gzip -c manual_parts.tar > manual_parts.tar.gz


index:	html ps
	gzip -9 < zmanual.ps > zmanual.ps.gz
	./makeindex.sh > index.html
