<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [

<!ENTITY % html "IGNORE">
<![%html;[
<!ENTITY % GEXT "gif">
<!ENTITY % print "IGNORE">
<!ENTITY % pdf   "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/lib/sgml/stylesheets/nwalsh-modular/html/docbook.dsl" CDATA dsssl>
]]>
<!ENTITY % print "INCLUDE">
<![%print;[
<!ENTITY % GEXT "eps">
<!ENTITY % html  "IGNORE">
<!ENTITY % pdf   "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/lib/sgml/stylesheets/nwalsh-modular/print/docbook.dsl" CDATA dsssl>
]]>
<!ENTITY % pdf "INCLUDE">
<![%print;[
<!ENTITY % GEXT "pdf">
<!ENTITY % html  "IGNORE">
<!ENTITY % print "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/lib/sgml/stylesheets/nwalsh-modular/print/docbook.dsl" CDATA dsssl>
]]>
]>

<style-sheet>
<style-specification id="pdf" use="docbook">
<style-specification-body> 

;; ====================
;; customize the PDF stylesheet
;; ====================

;; this is necessary because right now jadetex does not understand
;; symbolic entities, whereas things work well with numeric entities.
(declare-characteristic preserve-sdata?
          "UNREGISTERED::James Clark//Characteristic::preserve-sdata?"
          #f)

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

</style-specification-body>
</style-specification>

<style-specification id="print" use="docbook">
<style-specification-body> 

;; ====================
;; customize the print stylesheet
;; ====================




;; this is necessary because right now jadetex does not understand
;; symbolic entities, whereas things work well with numeric entities.
(declare-characteristic preserve-sdata?
          "UNREGISTERED::James Clark//Characteristic::preserve-sdata?"
          #f)

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

</style-specification-body>
</style-specification>

<style-specification id="html" use="docbook">
<style-specification-body> 

;; ====================
;; customize the html stylesheet here
;; ====================

;;
;; No breaking at top-most SECTION levels, only at CHAPTER and alike.
;;
(define (chunk-element-list)
  (list (normalize "preface")
        (normalize "chapter")
        (normalize "appendix") 
        (normalize "article")
        (normalize "glossary")
        (normalize "bibliography")
        (normalize "index")
        (normalize "colophon")
        (normalize "setindex")
     ;; (normalize "reference")
     ;; (normalize "refentry")
        (normalize "part")
     ;; (normalize "sect1") 
     ;; (normalize "section") 
        (normalize "book") ;; just in case nothing else matches...
        (normalize "set")  ;; sets are definitely chunks...
        ))

;;
;; Redefine TOC-DEPTH for HTML so TOC will contain more of sublevel data
;; Default limit level for PRINT mode is 7 ...
;;

(define (toc-depth nd)
  (if (string=? (gi nd) (normalize "book"))
      7 ;; was '3'
      1))


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

(define %generate-part-toc% #t)

(define %shade-verbatim%
  #t)

(define %titlepage-in-info-order% 
  ;; Place elements on title page in document order?
  #t)

</style-specification-body>
</style-specification>
<external-specification id="docbook" document="docbook.dsl">
</style-sheet>
