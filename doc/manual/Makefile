#
# GNU-Makefile for ZMailer manual
#

PARTS=	zadministration.tex     zref-router.tex			\
	zapp-filefmts.tex       zref-scheduler.tex		\
	zapp-listmgrs.tex       zref-sendmail.tex		\
	zapp-scripts.tex        zref-smtpserver.tex		\
	zapp-ssl-lang.tex       zref-transport-agents.tex	\
	zapp-tragents.tex       zref-utilities.tex		\
	zinstall.tex            zref-zmailer3.tex		\
	zreference.tex		zref-rmail.tex			\
	ztutorial.tex		zappendixes.tex			\
	zmanual-head.tex	zmanual-tail.tex

FIGS   :=	msgmodl.fig msgrout.fig zmailer-logo.fig \
		zmdirs.fig

FIGEPS :=	$(FIGS:%.fig=%.eps)
FIG_PS :=	$(FIGS:%.fig=%.ps)
FIGGIF :=	$(FIGS:%.fig=%.gif)

LINUXDOCBIN=/usr/bin
LINUXDOCLIB=/usr/lib/sgml-tools
#LINUXDOCLIB=/usr/lib/linuxdoc-sgml
#LATEX2HTMLLIB=/usr/lib/latex2html/texinputs:/usr/lib/latex2html/docs
LATEX2HTMLLIB=/usr/lib/latex2html/texinputs
# set and export TEXINPUTS
TEXINPUTS=$(LATEX2HTMLLIB):$(LINUXDOCLIB):$$TEXINPUTS:
TEXENV=  TEXINPUTS=$(TEXINPUTS);export TEXINPUTS;


L2HGIFS = next_motif_gr.gif previous_motif_gr.gif up_motif.gif \
	  contents_motif.gif index_motif.gif
GIFS = $(L2HGIFS) zmailer-logo2.gif

# L2H = latex2html  -no_math -html_version 3.2,math -scalable_fonts 
L2H = $(TEXENV) latex2html  -no_math -html_version 3.2,math 

L2HTOPTITLE  =	"ZMailer"
L2HTOP       =	zmanual
L2HCONTENTS  =	node20
L2HINDEXNODE =  node21
L2HCHGNODE   =	node22
L2HREFNODE   =	node23
L2HGLOSSNODE =	node24

L2HCOMMON =	-external_file zmanual -no_subdir -toc_depth 8 \
		-contents $(L2HCONTENTS).html -index $(L2HINDEXNODE).html \
		-biblio $(L2HREFNODE) -no_auto_link -no_footnode	\
		-split 0 -link 8 -up_url $(L2HTOP).html			\
		-up_title $(L2HTOPTITLE) -show_section_numbers		\
		-short_index
#		-info 0

L2HLTOP	     =	$(L2HCOMMON) -t "ZMailer manual"
L2HLSEC1     =	$(L2HCOMMON)
L2HLSEC2     =	$(L2HCOMMON)
L2HLSEC3     =	$(L2HCOMMON)
L2HLSEC4     =	$(L2HCOMMON)
L2HLSEC5     =	$(L2HCOMMON)


all:
	@echo "make tag choices: clean dist html dvi ps"

dvi: zmanual.dvi
ps:  zmanual.ps
#html: zmanual.html
dist: manual_parts.tar.gz

zmailer-logo2.gif zlogo: zmailer-logo2.gif-green
	cp -p zmailer-logo2.gif-green zmailer-logo2.gif

zmailer-logo2.gif-green: zmailer-logo.ps

gifs: $(FIGGIF)

$(L2HGIFS):
	cp -p /usr/lib/latex2html/icons.gif/* .
	rm -f icons.html

distclean clean:
	rm -f zmanual.*
	rm -f *~ *.html *.ps *.eps *.gif *.bak *.dvi *.toc *.lof
	rm -f *.css *.aux *.ptr *.old *.ilg *.gls *.cb *.glo *.log
	rm -rf l2h[1-9][0-9]* *sections.pl *internals.pl *index.pl
	rm -f *contents.pl *.ind *.idx *images.pl *table.pl
	rm -f [A-Z]*images.* *labels.pl *figure.pl IMG_PAR*
	rm -f TEXENV *.ps.gz *.xbm *.png
	rm -f ADM.tex  ASC.tex  INS.tex  RRT.tex  RSM.tex  RZL.tex
	rm -f AFM.tex  ASS.tex  REF.tex  RSC.tex  RTA.tex  TUT.tex
	rm -f ALM.tex  ATA.tex  RRM.tex  RSE.tex  RUT.tex
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

%.eps: %.fig
	fig2dev -Lps -c -p x -z A3 -m 1.0000 -x 0 -y 0 -n $@ $< $@

$(FIG_PS): $(FIGS)
$(FIGEPS): $(FIGS)

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS) $(FIGS)
	tar -cf manual_parts.tar Makefile $(PARTS) $(FIGS)
	gzip -c manual_parts.tar > manual_parts.tar.gz

zmanual.ps: zmanual.dvi $(FIGEPS)
	dvips -ta4 -ozmanual.ps zmanual.dvi

zmanual.dvi: $(PARTS) $(FIGEPS) zmanual.tex
	$(TEXENV)					\
	latex zmanual &&				\
	makeindex -s l2hidx.ist zmanual.idx &&		\
	makeindex -s l2hglo.ist -o zmanual.gls zmanual.glo && \
	latex zmanual && latex zmanual

zmanual.tex: zmanual-head.tex zmanual-tail.tex L2H.sh Makefile
	echo "$(TEXENV)" > TEXENV
	./L2H.sh zmanual-head.tex zmanual-tail.tex zmanual.tex

zmanual.aux: zmanual.dvi

all-html: zmanual.aux $(PARTS) $(FIGEPS)
	$(L2H) $(L2HCOMMON) -split 0 -unsegmented zmanual.tex

html: zmanual.aux $(PARTS) $(FIGEPS) Makefile $(GIFS)
	#for y in figure contents index images internals labels \
	#		sections table; \
	#    	do echo "1;" > $$y.pl ; done
	echo "$(TEXENV)" > TEXENV
	# $(L2H) $(L2HLTOP)  zmanual.tex
	./L2H.sh  ztutorial.tex		TUT	section	"Tutorial"
	./L2H.sh  zinstall.tex		INS	section	"Build and Install"
	./L2H.sh  zadministration.tex	ADM	section	"Administation"
	./L2H.sh  zreference.tex	REF	section	"Reference"
	./L2H.sh  zref-smtpserver.tex	RSM  subsection "SMTP-server"
	./L2H.sh  zref-sendmail.tex	RSE  subsection "sendmail"
	./L2H.sh  zref-rmail.tex 	RRM  subsection "rmail"
	./L2H.sh  zref-zmailer3.tex	RZL  subsection "zmailer(3)"
	./L2H.sh  zref-router.tex	RRT  subsection "Router"
	./L2H.sh  zref-scheduler.tex	RSC  subsection "Scheduler"
	./L2H.sh  zref-transport-agents.tex RTA subsection "Transport Agents"
	./L2H.sh  zref-utilities.tex	RUT  subsection "Utilities"
	./L2H.sh  zapp-scripts.tex	ASC	section	"Sample Router Configuration Scripts"
	./L2H.sh  zapp-listmgrs.tex	ALM	section	"Using Zmailer with Mailinglist Managers"
	./L2H.sh  zapp-tragents.tex	ATA	section "Adding new Transport Agents"
	./L2H.sh  zapp-filefmts.tex	AFM	section "Internal File Data Formats"
	./L2H.sh  zapp-ssl-lang.tex	ASS	section "The S/SL language"
	#
	# Ok, now repeat those same commands...
	#
	# ...
	$(L2H) $(L2HLTOP)  zmanual.tex



zman:	$(FIGEPS) zmanual.tex $(GIFS)
	@touch zmanual.lof # To please LaTeX2HTML to be quiet..
	$(L2H) $(L2HLTOP)  zmanual.tex

ztut:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  ztutorial.tex		TUT	section	"Tutorial"

zinst:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zinstall.tex		INS	section	"Build and Install"

zref:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zreference.tex	REF	section	"Reference"

zrrt:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-router.tex	RRT  subsection "Router"

zrsm:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-smtpserver.tex	RSM  subsection "SMTP-server"

zrse:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-sendmail.tex	RSE  subsection "sendmail"

zrrm:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-rmail.tex 	RRM  subsection "rmail"

zrzl:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-zmailer3.tex	RZL  subsection "zmailer(3)"

index:	html ps
	gzip -9 < zmanual.ps > zmanual.ps.gz
	./makeindex.sh > index.html
