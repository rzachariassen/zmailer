<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY % html "IGNORE">
<![%html;[
<!ENTITY % print "IGNORE">
<!ENTITY docbook.dsl SYSTEM "/usr/lib/sgml/stylesheets/nwalsh-modular/html/docbook.dsl" CDATA dsssl>
]]>
<!ENTITY % print "INCLUDE">
<![%print;[
<!ENTITY docbook.dsl SYSTEM "/usr/lib/sgml/stylesheets/nwalsh-modular/print/docbook.dsl" CDATA dsssl>
]]>
]>

<style-sheet>
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
