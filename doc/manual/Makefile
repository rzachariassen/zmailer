#
# GNU-Makefile for ZMailer manual
#

PARTS=	Makefile		\
	zadministration.tex        zref-router.tex		\
	zapp-filefmts.tex          zref-scheduler.tex		\
	zapp-listmgrs.tex          zref-sendmail.tex		\
	zapp-scripts.tex           zref-smtpserver.tex		\
	zapp-ssl-lang.tex          zref-transport-agents.tex	\
	zapp-tragents.tex          zref-utilities.tex		\
	zinstall.tex               zref-zmailer3.tex		\
	zmanual.tex                zreference.tex		\
	zref-rmail.tex             ztutorial.tex

FIGS   :=	msg_modl.fig msg_rout.fig

FIGEPS :=	$(FIGS:%.fig=%.eps)
FIG_PS :=	$(FIGS:%.fig=%.ps)
FIGGIF :=	$(FIGS:%.fig=%.gif)

LINUXDOCBIN=/usr/bin
#LINUXDOCLIB=/usr/lib/sgml-tools
LINUXDOCLIB=/usr/lib/linuxdoc-sgml
# set and export TEXINPUTS
TEXINPUTS=$$TEXINPUTS:$(LINUXDOCLIB)



all:
	@echo "make tag choices: clean dist html dvi ps"

dvi: manual.dvi
ps:  manual.ps
html: manual.html
dist: manual_parts.tar.gz

gifs: $(FIGGIF)

clean:
	rm -f *~ *.html *.ps *.eps *.gif *.bak *.dvi manual.* *.aux

.SUFFIXES: .gif .fig .eps .ps

%.gif: %.ps
	rm -f $@.ppm
	ghostscript -dNOPAUSE -sDEVICE=ppm -sOutputFile=$@.ppm $^ -c quit
	if [ ! -f $@.ppm ] ; then exit 1 ;fi # No file, abort!
	ppmtogif -transparent white < $@.ppm > $@
	rm -f $@.ppm

%.ps: %.fig
	fig2dev -Lps -c -p x -P -z A4 -m 1.0000 -p xxx -x 0 -y 0 -n $@ $< $@

%.eps: %.fig
	fig2dev -Lps -c -p x -P -z A4 -m 1.0000 -p xxx -x 0 -y 0 -n $@ $< $@

$(FIG_PS): $(FIGS)
$(FIGEPS): $(FIGS)
$(FIGGIF): $(FIG_PS)

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS) $(FIGS)
	tar -cf manual_parts.tar Makefile $(PARTS) $(FIGS)
	gzip -c manual_parts.tar > manual_parts.tar.gz

manual.html: $(PARTS) $(FIGGIF)
	@echo "****  'make html' NOT YET SUPPORTED   ****"
	@echo "**** pending  Latex2HTML installation ****"

manual.ps: manual.dvi $(FIGEPS)
	dvips -ta4 -omanual.ps manual.dvi

manual.dvi: $(PARTS) $(FIGEPS)
	TEXINPUTS=$(TEXINPUTS);export TEXINPUTS;	\
	rm -f manual.tex ; cp zmanual.tex manual.tex ;	\
	latex manual && latex manual && latex manual
