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

FIGS   :=	msgmodl.fig msgrout.fig

FIGEPS :=	$(FIGS:%.fig=%.eps)
FIG_PS :=	$(FIGS:%.fig=%.ps)
FIGGIF :=	$(FIGS:%.fig=%.gif)

LINUXDOCBIN=/usr/bin
#LINUXDOCLIB=/usr/lib/sgml-tools
#LINUXDOCLIB=/usr/lib/linuxdoc-sgml
LATEX2HTMLLIB=/usr/lib/latex2html/texinputs
# set and export TEXINPUTS
TEXINPUTS=$$TEXINPUTS:$(LINUXDOCLIB):$(LATEX2HTMLLIB)
TEXENV=  TEXINPUTS=$(TEXINPUTS);export TEXINPUTS;

# L2H = latex2html  -no_math -html_version 3.2,math -scalable_fonts 
L2H = $(TEXENV) latex2html  -no_math -html_version 3.2,math 


L2HTOPTITLE  =	"ZMailer"
L2HTOP       =	../manual
L2HCONTENTS  =	node20
L2HINDEXNODE =  node21
L2HCHGNODE   =	node22
L2HREFNODE   =	node23
L2HGLOSSNODE =	node24
L2HCOMMON =	-external_file manual -dir $(L2HTOP) -info 0 -short_index \
		-contents $(L2HCONTENTS).html -index $(L2HINDEXNODE).html \
		-biblio $(L2HREFNODE) -no_auto_link -no_footnode	\
		-split 6 -link 6 -up_url $(L2HTOP).html			\
		-up_title $(L2HTOPTITLE) -show_section_numbers

L2HLTOP	     =	-short_index -split 4 -link 5 -t $(L2HTOPTITLE) \
		-dir $(L2HTOP) -external_file manual.aux zmanual.tex
L2HLSEC1     =	$(L2HCOMMON) -prefix T	\
		ztutorial.tex
L2HLSEC2     =	$(L2HCOMMON) -prefix I	\
		-split 0 -unsegment	\
		zinstall.tex
L2HLSEC3     =	$(L2HCOMMON) -prefix A	\
		zadministration.tex
L2HLSEC4     =	$(L2HCOMMON) -prefix R	\
		zreference.tex


all:
	@echo "make tag choices: clean dist html dvi ps"

dvi: manual.dvi
ps:  manual.ps
html: manual.html
dist: manual_parts.tar.gz

gifs: $(FIGGIF)

clean:
	rm -f *~ *.html *.ps *.eps *.gif *.bak *.dvi manual.*
	rm -f *.css *.aux *.ptr *.old
	rm -rf l2h[1-9][0-9]* *sections.pl *internals.pl *index.pl *contents.pl
	rm -f [A-Z]*images.* *labels.pl *figure.pl IMG_PAR*

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

manual.ps: manual.dvi $(FIGEPS)
	dvips -ta4 -omanual.ps manual.dvi

manual.dvi: $(PARTS) $(FIGEPS)
	$(TEXENV)					\
	rm -f manual.tex ; cp zmanual.tex manual.tex ;	\
	latex manual &&					\
	makeindex -s l2hidx.ist manual.idx &&		\
	makeindex -s l2hglo.ist -o manual.gls manual.glo && \
	latex manual && latex manual

manual.aux: manual.dvi

all-html: manual.aux $(PARTS) $(FIGGIF)
	$(L2H) $(L2HCOMMON) -split 0 -unsegmented manual.tex

manual.html: manual.aux $(PARTS) $(FIGGIF)
	$(L2H) $(L2HLTOP)
	$(L2H) $(L2HLSEC1)
	$(L2H) $(L2HLSEC2)
	$(L2H) $(L2HLSEC3)
	$(L2H) $(L2HLSEC4)
	$(L2H) $(L2HLTOP)
