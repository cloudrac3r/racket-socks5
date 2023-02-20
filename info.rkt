#lang info
; my package
(define collection "socks5")
(define pkg-authors '("Cadence Ember"))
(define version "0.2.0")
(define license 'BSD-3-Clause)
; code
(define deps '("base" "typed-racket-lib" "typed-racket-more" "net-ip-lib" "http-easy-lib" "hyper-literate"))
; documentation
(define scribblings '(("socks5.rkt" (multi-page))))
(define build-deps '("scribble-lib" "scribble-enhanced" "racket-doc" "http-easy" "net-doc" "typed-racket-doc"))
