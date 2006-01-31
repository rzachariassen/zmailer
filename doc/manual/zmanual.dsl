<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [

<!ENTITY ddash    SDATA "[ddash]"    -- Double-Dash for ZMailer docs       -->
<!ENTITY PGBREAK  SDATA "[pgbreak]"  -- LaTeX \pagebreak for ZMailer docs  -->

<!ENTITY % html "IGNORE">
<![%html;[
<!ENTITY % GEXT "gif">
<!ENTITY % print "IGNORE">
<!ENTITY % pdf   "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/share/sgml/docbook/dsssl-stylesheets/html/docbook.dsl" CDATA dsssl>
]]>
<!ENTITY % print "INCLUDE">
<![%print;[
<!ENTITY % GEXT "eps">
<!ENTITY % html  "IGNORE">
<!ENTITY % pdf   "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/share/sgml/docbook/dsssl-stylesheets/print/docbook.dsl" CDATA dsssl>
]]>
<!ENTITY % pdf "INCLUDE">
<![%print;[
<!ENTITY % GEXT "pdf">
<!ENTITY % html  "IGNORE">
<!ENTITY % print "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/share/sgml/docbook/dsssl-stylesheets/print/docbook.dsl" CDATA dsssl>
]]>
]>

<style-sheet>
<style-specification id="pdf" use="docbook">
<style-specification-body> 

;; ================================
;;   customize the PDF stylesheet
;; ================================

;; this is necessary because right now jadetex does not understand
;; symbolic entities, whereas things work well with numeric entities.
(declare-characteristic preserve-sdata?
          "UNREGISTERED::James Clark//Characteristic::preserve-sdata?"
          #t)

(define bop-footnotes
  ;; Make "bottom-of-page" footnotes?
  #t)

(define %section-autolabel% 
  ;; Are sections enumerated?
  #t)

(define %hyphenation%
  ;; Allow automatic hyphenation?
  #t)

(define preferred-mediaobject-notations
  '("PDF" "EPS" "PS" "JPG" "JPEG" "linespecific"))

(define preferred-mediaobject-extensions
  '("pdf" "eps" "ps" "jpg" "jpeg"))

(define %graphic-extensions% 
  ;; List of graphic filename extensions
  '("eps" "epsf" "gif" "tif" "tiff" "jpg" "jpeg" "png" "pdf"))

(define %graphic-default-extension% "pdf")

(define %two-side% 
  ;; Is two-sided output being produced?
  #t)

(define %paper-type%
  ;; Name of paper type
  "A4"
  ;; "USletter"
  )

(define %titlepage-in-info-order% 
  ;; Place elements on title page in document order?
  #t)


(define (dingbat usrname)
  ;; REFENTRY dingbat
  ;; PURP Map dingbat names to Unicode characters
  ;; DESC
  ;; Map a dingbat name to the appropriate Unicode character.
  ;; /DESC
  ;; /REFENTRY
  ;; Print dingbats and other characters selected by name
  (let ((name (case-fold-down usrname)))
    (case name
      ;; For backward compatibility
      (("box")                  "\white-square;")
      (("checkbox")             "\white-square;")
      ;; \check-mark prints the wrong symbol (in Jade 0.8 RTF backend)
      (("check")                "\heavy-check-mark;") 
      (("checkedbox")           "\ballot-box-with-check;")
      (("copyright")            "\copyright-sign")

      ;; Straight out of Unicode
      (("lsquo")                "\U-2018;")
      (("rsquo")                "\U-2019;")
      (("ldquo")                "\U-201C;")
      (("rdquo")                "\U-201D;")
      (("en-dash")              "\en-dash;")
      (("em-dash")              "\em-dash;")
      (("en-space")             "\U-2002;")
      (("em-space")             "\U-2003;")
      (("bullet")               "\bullet;")
      (("black-square")         "\black-square;")
      (("white-square")         "\white-square;")
      ;; \ballot-box name doesn't work (in Jade 0.8 RTF backend)
      ;; and \white-square looks better than \U-2610; anyway
      (("ballot-box")           "\white-square;")
      (("ballot-box-with-check")        "\ballot-box-with-check;")
      (("ballot-box-with-x")    "\ballot-box-with-x;")
      ;; \check-mark prints the wrong symbol (in Jade 0.8 RTF backend)
      (("check-mark")           "\heavy-check-mark;") 
      ;; \ballot-x prints out the wrong symbol (in Jade 0.8 RTF backend)
      (("ballot-x")             "\heavy-check-mark;")
      (("copyright-sign")       "\copyright-sign;")
      (("registered-sign")      "\registered-sign;")
      (else "\bullet;"))))


</style-specification-body>
</style-specification>

<style-specification id="print" use="docbook">
<style-specification-body> 

;; ================================
;;  customize the PRINT stylesheet
;; ================================




;; this is necessary because right now jadetex does not understand
;; symbolic entities, whereas things work well with numeric entities.
(declare-characteristic preserve-sdata?
          "UNREGISTERED::James Clark//Characteristic::preserve-sdata?"
          #t)

(define bop-footnotes
  ;; Make "bottom-of-page" footnotes?
  #t)

(define %section-autolabel% 
  ;; Are sections enumerated?
  #t)

(define %hyphenation%
  ;; Allow automatic hyphenation?
  #t)

(define %graphic-default-extension% "eps")

(define %two-side% 
  ;; Is two-sided output being produced?
  #t)

(define %paper-type%
  ;; Name of paper type
  "A4"
  ;; "USletter"
  )

(define %titlepage-in-info-order% 
  ;; Place elements on title page in document order?
  #t)

(define (dingbat usrname)
  ;; REFENTRY dingbat
  ;; PURP Map dingbat names to Unicode characters
  ;; DESC
  ;; Map a dingbat name to the appropriate Unicode character.
  ;; /DESC
  ;; /REFENTRY
  ;; Print dingbats and other characters selected by name
  (let ((name (case-fold-down usrname)))
    (case name
      ;; For backward compatibility
      (("box")                  "\white-square;")
      (("checkbox")             "\white-square;")
      ;; \check-mark prints the wrong symbol (in Jade 0.8 RTF backend)
      (("check")                "\heavy-check-mark;") 
      (("checkedbox")           "\ballot-box-with-check;")
      (("copyright")            "\copyright-sign")

      ;; Straight out of Unicode
      (("lsquo")                "\U-2018;")
      (("rsquo")                "\U-2019;")
      (("ldquo")                "\U-201C;")
      (("rdquo")                "\U-201D;")
      (("en-dash")              "\en-dash;")
      (("em-dash")              "\em-dash;")
      (("en-space")             "\U-2002;")
      (("em-space")             "\U-2003;")
      (("bullet")               "\bullet;")
      (("black-square")         "\black-square;")
      (("white-square")         "\white-square;")
      ;; \ballot-box name doesn't work (in Jade 0.8 RTF backend)
      ;; and \white-square looks better than \U-2610; anyway
      (("ballot-box")           "\white-square;")
      (("ballot-box-with-check")        "\ballot-box-with-check;")
      (("ballot-box-with-x")    "\ballot-box-with-x;")
      ;; \check-mark prints the wrong symbol (in Jade 0.8 RTF backend)
      (("check-mark")           "\heavy-check-mark;") 
      ;; \ballot-x prints out the wrong symbol (in Jade 0.8 RTF backend)
      (("ballot-x")             "\heavy-check-mark;")
      (("copyright-sign")       "\copyright-sign;")
      (("registered-sign")      "\registered-sign;")
      (else "\bullet;"))))


</style-specification-body>
</style-specification>

<style-specification id="html" use="docbook">
<style-specification-body> 

;; ===============================
;;  customize the HTML stylesheet 
;; ===============================

;;
;; No breaking at top-most SECTION levels, only at CHAPTER and alike.
;;
(define (chunk-element-list)
  (list
        (normalize "set")  ;; sets are definitely chunks...
        (normalize "book") ;; just in case nothing else matches...
        (normalize "part")
     ;; (normalize "chapter")
     ;; (normalize "sect1") 
     ;; (normalize "section") 

        (normalize "preface")
        (normalize "appendix") 
        (normalize "article")
        (normalize "glossary")
        (normalize "bibliography")
        (normalize "index")
        (normalize "colophon")
        (normalize "setindex")
     ;; (normalize "reference")
     ;; (normalize "refentry")
        ))


(define (chunk-section-depth)
  99)


;;
;; Redefine TOC-DEPTH for HTML so TOC will contain more of sublevel data
;; Default limit level for PRINT mode is 7 ...
;;

;; (define (toc-depth nd)
;;  (if (string=? (gi nd) (normalize "book"))
;;      7 ;; was '3'
;;      1))

;; Returns the depth of auto TOC that should be made at the nd-level
(define (toc-depth nd)  99)
(define chapter-toc?    #t)
(define %force-chapter-toc% #t)

(define %admon-graphics%
  ;; REFENTRY admon-graphics
  ;; PURP Use graphics in admonitions?
  ;; DESC
  ;; If true, admonitions are presented in an alternate style that uses
  ;; a graphic.  Default graphics are provided in the distribution.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define %admon-graphics-path%
  ;; REFENTRY admon-graphics-path
  ;; PURP Path to admonition graphics
  ;; DESC
  ;; Sets the path, probably relative to the directory where the HTML
  ;; files are created, to the admonition graphics.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  "stylesheet-images/")


;;Default extension for filenames?
(define %html-ext% 
  "shtml")

(define %stylesheet%
  ;; REFENTRY stylesheet
  ;; PURP Name of the stylesheet to use
  ;; DESC
  ;; The name of the stylesheet to place in the HTML LINK TAG, or '#f' to
  ;; suppress the stylesheet LINK.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  "zmanual.css")

(define %stylesheet-type%
  ;; REFENTRY stylesheet-type
  ;; PURP The type of the stylesheet to use
  ;; DESC
  ;; The type of the stylesheet to place in the HTML LINK TAG.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  "text/css")

(define %html40%
  ;; REFENTRY html40
  ;; PURP Generate HTML 4.0
  ;; DESC
  ;; If '%html40%' is true then the output more closely resembles HTML 4.0.
  ;; In particular, the HTML table module includes COL, THEAD, TBODY, and TFOOT
  ;; elements.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define %css-decoration%
  ;; REFENTRY css-decoration
  ;; PURP Enable CSS decoration of elements
  ;; DESC
  ;; If '%css-decoration%' is turned on then HTML elements produced by the
  ;; stylesheet may be decorated with STYLE attributes.  For example, the
  ;; LI tags produced for list items may include a fragment of CSS in the
  ;; STYLE attribute which sets the CSS property "list-style-type".
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  #t)

(define %css-liststyle-alist%
  ;; REFENTRY css-liststyle-alist
  ;; PURP Map DocBook OVERRIDE and MARK attributes to CSS
  ;; DESC
  ;; If '%css-decoration%' is turned on then the list-style-type property of
  ;; list items will be set to reflect the list item style selected in the
  ;; DocBook instance.  This associative list maps the style type names used
  ;; in your instance to the appropriate CSS names.  If no mapping exists,
  ;; the name from the instance will be used.
  ;; /DESC
  ;; AUTHOR N/A
  ;; /REFENTRY
  '(("bullet" "disc")
    ("box" "square")))




(define %indent-synopsis-lines% 
  ;; REFENTRY indent-synopsis-lines
  ;; PURP Indent lines in a 'Synopsis'?
  ;; DESC
  ;; If not '#f', each line in the display will be indented
  ;; with the content of this variable.  Usually it is set to some number
  ;; of spaces, but you can indent with any string you wish.
  ;; /DESC
  ;; /REFENTRY
  #f)


(define %hyphenation%
  ;; Allow automatic hyphenation?
  #f)

(define %graphic-default-extension% "gif")

(define %generate-article-toc% 
  ;; Should a Table of Contents be produced for Articles?
  ;; If true, a Table of Contents will be generated for each 'Article'.
  #t)

(define %section-autolabel% 
  ;; Are sections enumerated?
  #t)

(define %generate-part-toc%
  #t)

(define %shade-verbatim%
  #t)

(define %titlepage-in-info-order% 
  ;; Place elements on title page in document order?
  #t)

(element sbr 
  ;;
  ;;  SBR  processor making explicite indention for following line
  ;;
  (make sequence
    (make empty-element gi: "BR")
    (make element gi: "CODE"
	  (make entity-ref name: "nbsp")
	  (make entity-ref name: "nbsp")
	  (make entity-ref name: "nbsp")
	  (make entity-ref name: "nbsp"))))


(define (dingbat usrname)
  ;; Print dingbats and other characters selected by name
  (let ((name (case-fold-down usrname)))
    (case name
      ;; For backward compatibility
      (("copyright")            "(C)")
      (("trademark")            "TM")

      (("pgbreak")		"")
      (("ddash")		"--")
      (("dash")			"-")

      ;; Straight out of Unicode
      (("lsquo")                "\U-2018")
      (("rsquo")                "\U-2019")
      (("ldquo")                "\U-201C")
      (("rdquo")                "\U-201D")
      (("lsaquo")               "\U-2039")
      (("rsaquo")               "\U-203A")

      (("laquo")                "«")
      (("raquo")                "»")

      (("ldquor")               "\U-201C")
      (("rdquor")               "\U-201D")


      (("en-dash")              "\U-2013")
      (("em-dash")              "\U-2014")
      (("en-space")             "\U-2002")
      (("em-space")             "\U-2003")
      (("bullet")               "\U-2022")
      (("copyright-sign")       "(C)")
      (("registered-sign")      "(R)")
      (else
       (let ((err (debug (string-append "No dingbat defined for: " name))))
         "*")))))

(define (dingbat-sosofo usrname)
  ;; Print dingbats and other characters selected by name
  (let ((name (case-fold-down usrname)))
    (case name
      ;; For backward compatibility
      (("copyright")            (make entity-ref name: "copy"))
      (("trademark")            (make entity-ref name: "trade"))

      (("pgbreak")		(literal ""))
      (("ddash")		(literal "--"))
      (("dash")			(literal "-"))
      (("zwnbsp")		(literal ""))

      ;; Straight out of Unicode
      (("ldquo")                (literal "\""))
      (("rdquo")                (literal "\""))
      (("lsquo")                "'")
      (("rsquo")                "'")
      (("en-dash")              (literal "-"))
      (("em-dash")              (literal "--"))
      (("en-space")             (make entity-ref name: "nbsp"))
      (("em-space")             (make sequence
                                  (make entity-ref name: "nbsp")
                                  (make entity-ref name: "nbsp")))
      (("bullet")               (literal "*"))
      (("copyright-sign")       (make entity-ref name: "copy"))
      (("registered-sign")      (literal "(R)"))
      (else
       (let ((err (debug (string-append "No dingbat defined for: " name))))
         (literal "*"))))))


</style-specification-body>
</style-specification>
<external-specification id="docbook" document="docbook.dsl">
</style-sheet>
