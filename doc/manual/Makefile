PARTS=intro.sgml tutorial.sgml install.sgml admin.sgml ref_smtp.sgml ref_sendmail.sgml ref_zmailer.sgml ref_router.sgml ref_scheduler.sgml ref_agents.sgml ref_utils.sgml app_scripts.sgml app_listmgr.sgml app_newagnts.sgml app_datafmt.sgml app_ssl.sgml end.sgml

LINUXDOCBIN=/usr/bin
LINUXDOCLIB=/usr/lib/linuxdoc-sgml
# set and export TEXINPUTS
TEXINPUTS=$$TEXINPUTS:$(LINUXDOCLIB)



all: manual.sgml

manual.sgml: $(PARTS)
	cat $(PARTS) > manual.sgml

tex: manual.tex
dvi: manual.dvi
ps:  manual.ps


html: manual.html
dist: manual_parts.tar.gz manual.sgml.gz

manual_parts.tar.gz: manual_parts.tar

manual_parts.tar: Makefile $(PARTS)
	tar -cf manual_parts.tar Makefile $(PARTS)
	gzip -c manual_parts.tar > manual_parts.tar.gz

manual.sgml.gz: manual.sgml
	gzip -c manual.sgml > manual.sgml.gz

manual.html: manual.sgml
	cp -p manual.sgml manual.tmp
	cat manual.tmp | sed "/^<x>.*<\/x>/ d" > manual.sgml
	./kill_text.pl no_html manual.sgml >manual.tmp
	./kill_tags.pl no_ps manual.tmp >manual.sgml

	sgml2html manual
	#cp -p manual.tmp manual.sgml
	rm manual.tmp
	#rm manual.tmp2
	mv manual.sgml man_old.sgml 

manual.ps: manual.dvi
	dvips -ta4 -omanual.ps manual.dvi

manual.dvi: manual.tex
	TEXINPUTS=$(TEXINPUTS);export TEXINPUTS; \
		latex manual ; latex manual ; latex manual

manual.tex: manual.sgml
	./kill_text.pl no_ps manual.sgml >manual.tmp
	./kill_tags.pl no_html manual.tmp >manual.sgml
	sgml2latex -a manual.sgml
	mv manual.sgml man_old.sgml


