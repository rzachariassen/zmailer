#
# GNU-Makefile for ZMailer manual
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
	ztutorial.sgml		zappendixes.sgml		\
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

DSLHTML  = /usr/lib/sgml/stylesheets/nwalsh-modular/html/docbook.dsl
DSLPRINT = /usr/lib/sgml/stylesheets/nwalsh-modular/print/docbook.dsl

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
	db2html -d `/bin/pwd`/zmanual.dsl zmanual.sgml
	cp -p *.gif zmanual/

zmanual.ps: zmanual.dvi $(FIGEPS)
	dvips -ta4 -ozmanual.ps zmanual.dvi

zmanual.dvi: $(PARTS) $(FIGEPS) zmanual.sgml
	sh -x db2dvi -d `/bin/pwd`/zmanual.dsl zmanual.sgml

distclean clean:
	# Leave "zmanual.ps" in place, if it exists
	rm -f *~ *.html *.eps *.gif *.bak *.dvi *.toc *.lof
	rm -f *.css *.aux *.ptr *.old *.ilg *.gls *.cb *.glo *.log
	rm -rf l2h[1-9][0-9]* *sections.pl *internals.pl *index.pl
	rm -f *contents.pl *.ind *.idx *images.pl *table.pl
	rm -f [A-Z]*images.* *labels.pl *figure.pl IMG_PAR*
	rm -f TEXENV *.ps.gz *.xbm *.png
	rm -f ADM.sgml  ASC.sgml  INS.sgml  RRT.sgml  RSM.sgml  RZL.sgml
	rm -f AFM.sgml  ASS.sgml  REF.sgml  RSC.sgml  RTA.sgml  TUT.sgml
	rm -f ALM.sgml  ATA.sgml  RRM.sgml  RSE.sgml  RUT.sgml
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

%.pdf: %.ps
	gs510 -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile=$@ $^ -c quit


$(FIG_PS): $(FIGS)
$(FIGEPS): $(FIGS)

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS) $(FIGS)
	tar -cf manual_parts.tar Makefile $(PARTS) $(FIGS)
	gzip -c manual_parts.tar > manual_parts.tar.gz

#zmanual.ps: zmanual.dvi $(FIGEPS)
#	dvips -ta4 -ozmanual.ps zmanual.dvi

#zmanual.dvi: $(PARTS) $(FIGEPS) zmanual.sgml
#	$(TEXENV)					\
#	latex zmanual &&				\
#	makeindex -s l2hidx.ist zmanual.idx &&		\
#	makeindex -s l2hglo.ist -o zmanual.gls zmanual.glo && \
#	latex zmanual && latex zmanual

#zmanual.sgml: zmanual-head.sgml zmanual-tail.sgml L2H.sh Makefile
#	echo "$(TEXENV)" > TEXENV
#	./L2H.sh zmanual-head.sgml zmanual-tail.sgml zmanual.sgml

#zmanual.aux: zmanual.dvi

#all-html: zmanual.aux $(PARTS) $(FIGEPS)
#	$(L2H) $(L2HCOMMON) -split 0 -unsegmented zmanual.sgml

#html: zmanual.aux $(PARTS) $(FIGEPS) Makefile $(GIFS)
#	#for y in figure contents index images internals labels \
#	#		sections table; \
#	#    	do echo "1;" > $$y.pl ; done
#	echo "$(TEXENV)" > TEXENV
#	# $(L2H) $(L2HLTOP)  zmanual.sgml
#	./L2H.sh  ztutorial.sgml		TUT	chapter	"Tutorial"
#	./L2H.sh  zinstall.sgml		INS	chapter	"Build and Install"
#	./L2H.sh  zadministration.sgml	ADM	chapter	"Administation"
#	./L2H.sh  zreference.sgml	REF	chapter	"Reference"
#	./L2H.sh  zref-smtpserver.sgml	RSM	section "SMTP-server"
#	./L2H.sh  zref-sendmail.sgml	RSE	section "sendmail"
#	./L2H.sh  zref-rmail.sgml 	RRM	section "rmail"
#	./L2H.sh  zref-zmailer3.sgml	RZL	section "zmailer(3)"
#	./L2H.sh  zref-router.sgml	RRT	section "Router"
#	./L2H.sh  zref-scheduler.sgml	RSC	section "Scheduler"
#	./L2H.sh  zref-transport-agents.sgml RTA	section "Transport Agents"
#	./L2H.sh  zref-utilities.sgml	RUT	section "Utilities"
#	./L2H.sh  zapp-scripts.sgml	ASC	chapter	"Sample Router Configuration Scripts"
#	./L2H.sh  zapp-listmgrs.sgml	ALM	chapter	"Using Zmailer with Mailinglist Managers"
#	./L2H.sh  zapp-tragents.sgml	ATA	chapter "Adding new Transport Agents"
#	./L2H.sh  zapp-filefmts.sgml	AFM	chapter "Internal File Data Formats"
#	./L2H.sh  zapp-ssl-lang.sgml	ASS	chapter "The S/SL language"
#	#
#	# Ok, now repeat those same commands...
#	#
#	# ...
#	$(L2H) $(L2HLTOP)  zmanual.sgml



zman:	$(FIGEPS) zmanual.sgml $(GIFS)
	@touch zmanual.lof # To please LaTeX2HTML to be quiet..
	$(L2H) $(L2HLTOP)  zmanual.sgml

ztut:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  ztutorial.sgml		TUT	chapter	"Tutorial"

zinst:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zinstall.sgml		INS	chapter	"Build and Install"

zref:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zreference.sgml	REF	chapter	"Reference"

zrrt:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-router.sgml	RRT	section "Router"

zrsm:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-smtpserver.sgml	RSM	section "SMTP-server"

zrse:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-sendmail.sgml	RSE	section "sendmail"

zrrm:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-rmail.sgml 	RRM	section "rmail"

zrzl:	$(FIGEPS)
	echo "$(TEXENV)" > TEXENV
	./L2H.sh  zref-zmailer3.sgml	RZL	section "zmailer(3)"

index:	html ps
	gzip -9 < zmanual.ps > zmanual.ps.gz
	./makeindex.sh > index.html
