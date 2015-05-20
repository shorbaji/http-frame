;;
;; http-frame is a HTTP/2 framing library for Chicken
;; Copyright (c) 2015, Omar Shorbaji
;; All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;; Redistributions of source code must retain the above copyright notice, this
;; list of conditions and the following disclaimer. 
;; Redistributions in binary form must reproduce the above copyright notice,
;; this list of conditions and the following disclaimer in the documentation
;; and/or other materials provided with the distribution. 
;; Neither the name of the author nor the names of its contributors may be
;; used to endorse or promote products derived from this software without
;; specific prior written permission. 
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
;; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
;; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OFcl
;; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
;; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
;; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;; POSSIBILITY OF SUCH DAMAGE.

;; Implements HTTP/2 framing based on RFC 7540 - sections 4 and 6

(module http-frame
    (read-frame write-frame frame-types)
  (import chicken scheme)
  (use srfi-1 srfi-13 extras data-structures ports )

  ;;;octets
  (define (octets->integer octets)
    (fold (lambda (x r) (+ x (* r 256))) 0 octets))

  (define (integer->octets int len)
    (do ((i int (quotient i 256))
         (n len (- n 1))
         (ls '() (cons (modulo i 256) ls)))
	((zero? n) ls)))

  (define (octify s)
    (map char->integer (string->list s)))

  (define (unoctify ls)
    (list->string (map integer->char ls)))

  (define (integer->str i n)
    (unoctify (integer->octets i n)))

  (define (str->integer s)
    (octets->integer (octify s)))

  ;;; settings
  (define known-settings
    '(SETTINGS-HEADER-TABLE-SIZE SETTINGS-ENABLE-PUSH SETTINGS-MAX-CONCURRENT-STREAMS
                                 SETTINGS-INITIAL-WINDOW-SIZE SETTINGS-MAX-FRAME-SIZE SETTINGS-MAX-HEADER-LIST-SIZE))

  (define (str->setting s)
    (let* ((id (str->integer (string-take s 2)))
           (id (or (alist-ref id (zip (cdr (iota 7)) known-settings)) id))
           (val (str->integer (string-drop s 2))))
      (cons id val)))

  (define (str->settings p)
    (let lp ((ls '()) (s p))
      (if (string-null? s)
          (reverse ls)
          (lp (cons (str->setting (string-take s 6)) ls)
              (string-drop s 6)))))

  (define (setting->str s)
    (let* ((id (car s))
           (id (or (alist-ref id (map cons known-settings (cdr (iota 7))))
                   id))
           (val (cdr s)))
      (conc (integer->str id 2)
            (integer->str val 4))))

  (define (settings->str ls)
    (apply conc (map setting->str ls)))

  ;;; flags
  (define (is flag flags) (if (member flag flags) #t #f))
  (define (flag->integer f)
    (alist-ref f `((ack . 1)
                   (end-stream . 1)
                   (end-headers . 4)
                   (padded . 8)
                   (priority . 32))))
  (define (flags->octet fls) (apply + (map flag->integer fls)))

  (define (octet->flags t o)
    (filter-map
     (lambda (triple)
       (and (member t (car triple)) (eq? (bitwise-and o (cadr triple)) (cadr triple)) (caddr triple)))
     '(((settings ping) 1 ack)
       ((data headers) 1 end-stream)
       ((headers push-promise continuation) 4 end-headers)
       ((data headers push-promise) 8 padded)
       ((headers) 32 priority))))

  ;;; utilities
  (define (fuse a b)
    (unoctify (let* ((four (integer->octets b 4)))
                (if (zero? a)
                    four
                    (cons (bitwise-ior (car four) 128) (cdr four))))))

  (define (unfuse s)
    (let* ((ls (octify s)))
      (cons (if (zero? (bitwise-and 128 (car ls))) 0 1)
            (octets->integer (cons (bitwise-and 127 (car ls)) (cdr ls))))))

  (define (str->esdw s)
    (let* ((esd (unfuse (string-take s 4)))
           (e (car esd))
           (sd (cdr esd))
           (w (str->integer (string-drop s 4))))
      (list e sd w)))

  (define (esdw->str e sd w)
    (conc (fuse e sd) (integer->str w 1)))

  (define (pad s pl)
    (if pl (conc (integer->str pl 1) s (string-pad "" pl)) s))

  (define (unpad s flags)
    (let* ((padded (is 'padded flags))
           (pad-length (and padded (char->integer (car (string->list (string-take s 1))))))
           (padding (and padded (string-take-right s pad-length))))
      (if pad-length
          (if (or (< (string-length s) pad-length)
                  (not (string=? padding (string-pad "" pad-length #\0))))
              (error 'protocol-error "non-zero-pad-length")
              (string-drop (string-drop-right s pad-length) 1))
          s)))

  ;;; frame payload parsers
  (define (parse-data-payload l f id p)
    (list id (unpad p f) (is 'end-stream f)))

  (define (parse-headers-payload l f id p)
    (let* ((s (unpad p f))
           (priority? (is 'priority f))
           (esdw (and priority? (str->esdw (string-take s 5))))
           (hbf (if priority? (string-drop s 5) s))
           (eh (is 'end-headers f))
           (es (is 'end-stream f)))
      (list id hbf eh es esdw)))

  (define (parse-priority-payload l f id p)
    (cons id (str->esdw p)))

  (define (parse-rst-stream-payload l f id p)
    (list id (str->integer p)))

  (define (parse-settings-payload l f id p)
    (let* ((s (str->settings p))
           (ack (is 'ack f)))
      (list s ack)))

  (define (parse-push-promise-payload l f id p)
    (let* ((s (unpad p f))
           (psid (str->integer (string-take s 4)))
           (hbf (string-drop s 4))
           (eh (is 'end-headers f)))
      (list id psid hbf eh)))

  (define (parse-ping-payload l f id p)
    (list p (is 'ack f)))

  (define (parse-goaway-payload l f id p)
    (let* ((ls (str->integer (string-take p 4)))
           (ec (str->integer (string-take (string-drop p 4) 4)))
           (dd (string-drop p 8)))
      (list ls ec dd)))

  (define (parse-window-update-payload l f id p)
    (list id (str->integer p)))

  (define (parse-continuation-payload l f id p)
    (list id p (is 'end-headers f)))

  (define frame-types 
    '(data headers priority rst-stream settings push-promise ping goaway window-update continuation))

  (define parsers
    (map cons frame-types
         (list parse-data-payload parse-headers-payload parse-priority-payload parse-rst-stream-payload
               parse-settings-payload parse-push-promise-payload parse-ping-payload parse-goaway-payload
               parse-window-update-payload parse-continuation-payload)))

  (define (read-length) (read-string 3))
  (define (read-type) (read-string 1))
  (define (read-sid) (read-string 4))
  (define (read-flags) (read-string 1))
  (define read-payload read-string)

  (define parse-sid str->integer)
  (define parse-length str->integer)

  (define (parse-flags s t)
    (octet->flags t (str->integer s)))

  (define (parse-type s)
    (if (string=? "" s)
        'eof
        (alist-ref (str->integer s) (map cons (iota 10) frame-types))))

  (define (parse-payload l t f id s)
    ((alist-ref t parsers) l f id s))

  (define (read-frame)
    (let* ((l (parse-length (read-length)))
           (t (parse-type (read-type)))
           (f (parse-flags (read-flags) t))
           (i (parse-sid (read-sid))))
      ;;; check frame size and handle frame-size errors
      (if (or (and (member t '(rst-stream window-update)) (not (eq? l 4)))
	      (and (eq? t 'ping) (not (eq? l 8)))
	      (and (eq? t 'settings) (not (zero? (modulo l 6))))
	      (and (eq? t 'priority) (not (eq? l 5))))
	  '(connection-error frame-size-error "bad frame size - conn")
	  (let* ((p (parse-payload l t f i (read-payload l))))
	    (cons t p)))))
  ;;; writes
  (define (write-length l)
    (display (integer->str l 3)))

  (define (write-type t)
    (display (integer->char (alist-ref t (map cons frame-types (iota 10))))))

  (define (write-flags f)
    (display (integer->char (flags->octet f))))

  (define (write-sid sid)
    (display (integer->str sid 4)))

  (define (write-all l t f s p)
    (write-length l)
    (write-type t)
    (write-flags f)
    (write-sid s)
    (display p)) 

  ;;; frame unparsers
  (define (write-data-frame sid d es #!optional (pl #f))
    (let* ((l (+ (string-length d) (+ 1 (or pl -1))))
           (f (if es '(end-stream) '()))
           (f (if pl (cons 'padded f) f)))
      (write-all l 'data f sid (pad d pl))))

  (define (write-headers-frame sid hbf eh es #!optional (priority #f) (pl #f))
    (let* ((l (+ (string-length hbf)
                 (if priority 5 0)
                 (+ 1 (or pl -1))))
           (f (filter-map (lambda (p f) (and p f))
                          (list es eh priority pl)
                          '(end-stream end-headers priority padded))))
      (write-all l 'headers f sid (conc (pad hbf pl)
                                        (if priority
                                            (apply esdw->str priority)
                                            "")))))
  (define (write-priority-frame sid e sd w)
    (write-all 5 'priority '() sid (esdw->str e sd w)))

  (define (write-rst-stream-frame sid ec)
    (write-all 4 'rst-stream '() sid (integer->str ec 4)))

  (define (write-settings-frame settings ack)
    (let* ((l (* 6 (length settings))))
      (write-all l 'settings (if ack '(ack) '()) 0 (settings->str settings))))

  (define (write-push-promise-frame sid psid hbf eh #!optional (pl #f))
    (let* ((l (+ (string-length hbf)
                 4
                 (+ 1 (if pl pl -1))))
           (f (filter-map (lambda (p f) (and p f))
                          (list eh pl)
                          '(end-headers padded)))
           (p (conc (integer->str psid 4) hbf)))
      (write-all l 'push-promise f sid p)))

  (define (write-ping-frame data ack) (write-all 8 'ping (if ack '(ack) '()) 0 data))

  (define (write-goaway-frame ls ec dd)
    (write-all (+ 8 (string-length dd)) 'goaway '()
	       0 (conc (integer->str ls 4) (integer->str ec 4) dd)))

  (define (write-window-update-frame sid wsi)
    (write-all 4 'window-update '() sid (integer->str wsi 4)))

  (define (write-continuation-frame sid hbf eh)
    (write-all (string-length hbf) 'continuation (if eh '(end-headers) '()) sid hbf))

  (define writers
    (map cons frame-types
	 (list write-data-frame write-headers-frame write-priority-frame write-rst-stream-frame
	       write-settings-frame write-push-promise-frame write-ping-frame write-goaway-frame
	       write-window-update-frame write-continuation-frame)))  

  (define (write-frame e)
    (let* ((t (car e))
           (fn (alist-ref t writers)))
      (if fn
          (apply fn (cdr e))
          (error (cons 'bad-fn-type e))))))
