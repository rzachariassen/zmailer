#
# GNU-Makefile for ZMailer manual
#

PARTS=	intro.sgml tutorial.sgml install.sgml admin.sgml	\
	ref_smtp.sgml ref_sendmail.sgml ref_zmailer.sgml	\
	ref_router.sgml ref_scheduler.sgml ref_agents.sgml	\
	ref_utils.sgml app_scripts.sgml app_listmgr.sgml	\
	app_newagnts.sgml app_datafmt.sgml app_ssl.sgml		\
	end.sgml

FIGS   :=	msg_modl.fig msg_rout.fig
FIGEPS :=	$(patsubst %.fig,%.eps,$(FIGS))
FIG_PS :=	$(patsubst %.fig,%.ps,$(FIGS))
FIGGIF :=	$(patsubst %.fig,%.gif,$(FIGS))

LINUXDOCBIN=/usr/bin
LINUXDOCLIB=/usr/lib/sgml-tools
# set and export TEXINPUTS
TEXINPUTS=$$TEXINPUTS:$(LINUXDOCLIB)



all:
	@echo "make tag choices: clean dist html tex dvi ps"

tex: manual.tex
dvi: manual.dvi
ps:  manual.ps
html: manual.html
dist: manual_parts.tar.gz manual.sgml.gz

gifs: $(FIGGIF)

clean:
	rm -f *~ *.html manual* *.ps *.eps *.gif *.bak

manual.sgml: $(PARTS)
	cat $(PARTS) > manual.sgml

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

#msg_modl.ps:  msg_modl.fig
#msg_modl.eps: msg_modl.fig
#msg_rout.ps:  msg_rout.fig
#msg_rout.eps: msg_rout.fig

#msg_modl.gif: msg_modl.ps
#msg_rout.gif: msg_rout.ps

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS)
	tar -cf manual_parts.tar Makefile $(PARTS)
	gzip -c manual_parts.tar > manual_parts.tar.gz

manual.sgml.gz: manual.sgml
	gzip -c manual.sgml > manual.sgml.gz

manual.html: manual.sgml $(FIGGIF)
	cp -p manual.sgml manual.tmp
	cat manual.tmp | sed "/^<x>.*<\/x>/ d" > manual.sgml
	./kill_text.pl no_html manual.sgml >manual.tmp
	./kill_tags.pl no_ps manual.tmp >manual.sgml
	sgml2html manual
	#cp -p manual.tmp manual.sgml
	rm manual.tmp
	#rm manual.tmp2
	mv manual.sgml man_old.sgml 

manual.ps: manual.dvi $(FIGEPS)
	dvips -ta4 -omanual.ps manual.dvi

manual.dvi: manual.tex
	TEXINPUTS=$(TEXINPUTS);export TEXINPUTS; \
		latex manual ; latex manual ; latex manual

manual.tex: manual.sgml
	./kill_text.pl no_ps manual.sgml >manual.tmp
	./kill_tags.pl no_html manual.tmp >manual.sgml
	sgml2latex -a manual.sgml
	mv manual.sgml man_old.sgml
