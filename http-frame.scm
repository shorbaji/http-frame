(module http-frame
  (
   make-data-frame data-frame-data
   make-headers-frame headers-frame-e headers-frame-sd headers-frame-w headers-frame-hbf
   make-priority-frame priority-frame-e priority-frame-sd priority-frame-w
   make-rst-stream-frame rst-stream-frame-ec
   make-settings-frame settings-frame-settings settings-ack-frame
   make-push-promise-frame push-promise-frame-psid push-promise-frame-hbf
   make-ping-frame ping-frame-data
   make-goaway-frame goaway-frame-ls goaway-frame-ec goaway-frame-dd
   make-window-update-frame window-update-frame-wsi
   make-continuation-frame continuation-frame-hbf
   frame-hbf frame-write frame-read frame->string frame-length frame-flags frame-sid frame-type frame-pad-length)

  (import chicken scheme)
  (use srfi-1 srfi-13 defstruct data-structures extras ports)

  ; frame
  (define make-frame list)
  (define frame-type        car)
  (define frame-flags       cadr)
  (define frame-sid         caddr)
  (define frame-payload     cadddr)
  (define frame-pad-length  fifth)

  ; octets 
  (define (octets->integer octets)
    (fold (lambda (x r) (+ x (* r 256))) 0 octets))

  (define (integer->octets int len)
    (do ((i int (quotient i 256))
         (n len (- n 1))
         (ls '() (cons (modulo i 256) ls)))
      ((zero? n) ls)))

  (define (indexer a b)
    (lambda (x)
      (car (alist-ref x (zip a b)))))

  ; frame types
  (define types '(data headers priority rst-stream settings push-promise
                       ping goaway window-update continuation))

  (define octet->type (indexer (iota 10) types))
  (define type->octet (indexer types (iota 10)))

  ; flags
  (define flag->integer
    (indexer '(flag-ack flag-end-stream flag-end-headers flag-padded flag-priority)
             '(1 1 4 8 32)))

  (define (octet->flags t o)
    (filter-map
      (lambda (triple)
        (and (member t (car triple)) (eq? (bitwise-and o (cadr triple)) (cadr triple)) (caddr triple)))
      '(((settings ping) 1 flag-ack)
        ((data headers) 1 flag-end-stream)
        ((headers push-promise) 4 flag-end-headers)
        ((data headers push-promise) 8 flag-padded)
        ((headers) 32 flag-priority))))

  (define (flags->octet fls)
    (apply + (map flag->integer fls)))

  ;;; frame read/write
  (define (frame-read)
    (let* ((o (map char->integer (string->list (read-string 9)))) 
           (len (octets->integer (take o 3)))
           (type (octet->type (fourth o)))
           (flags (octet->flags type (fifth o)))
           (padded? (member 'flag-padded flags))
           (pad-length (and padded? (car (map char->integer(string->list (read-string 1))))))
           (sid (octets->integer (take-right o 4)))
           (ps (read-string (- len (or pad-length 0))))
           (payload (payload-parse type flags ps))
           (padding (and pad-length (read-string pad-length))))
      (make-frame type flags sid payload pad-length)))

  (define (frame->string f)
    (let* ((l (integer->octets (frame-length f)  3))
           (t (type->octet (frame-type f)))
           (fl (flags->octet (frame-flags f)))
           (s (integer->octets (frame-sid f) 4))
           (octets (append l (list t fl) s))
           (pl (frame-pad-length f)))
      (conc (list->string (map integer->char octets))
            (if pl (integer->char (car (integer->octets pl 1))) "")
            (payload-unparse (frame-type f) (frame-flags f) f)      
            (if pl (list->string (make-list pl #\null)) ""))))

  (define (frame-write f)
    (display (frame->string f)))

  (define (fuse a b)
    (list->string
      (map integer->char
           (let* ((four (integer->octets b 4)))
             (if (zero? a)
                 four
                 (cons (bitwise-ior (car four) 128) (cdr four)))))))

  (define (defuse s)
    (let* ((ls (map char->integer (string->list s))))
      (cons (if (zero? (bitwise-and 128 (car ls)))
                0
                1)
            (cons (bitwise-and 127 (car ls))
                  (cdr ls)))))

  (define (pad s frame)
    (let* ((pad-length (frame-pad-length frame)))
      (if pad-length
          (conc (integer->char pad-length) s (string-pad "" pad-length))
          s)))

  (define (unpad s flags)
    (let* ((padded (member 'flag-padded flags))
           (pad-length (and padded (char->integer (car (string->list (string-take s 1)))))))
      (string-drop (string-drop-right s (or pad-length 0)) (if pad-length 1 0))))

  (define (integer->str i n)
    (list->string (map integer->char (integer->octets i n))))

  (define (str->integer s)
    (octets->integer (map char->integer (string->list s))))

  ; data frame
  (define data-frame-data (compose car frame-payload))
  (define (data-payload-unparse flags frame) (pad (data-frame-data frame) frame))
  (define (data-parse flags s) (list s))
  (define (make-data-frame #!key data sid end-stream (pad-length #f))
    (make-frame 'data (if end-stream '(flag-end-stream) '()) sid (list data) pad-length))

  ; headers frame
  (define (make-headers-frame #!key priority end-stream end-headers sid e sd w hbf (pad-length #f))
    (make-frame 'headers
                (filter-map (lambda (a b) (and a b))
                            `(,priority ,end-stream ,end-headers)
                            '(flag-priority flag-end-stream flag-end-headers))
                sid
                (if priority (list hbf e sd w) (list hbf))
                pad-length))

  (define headers-frame-hbf
    (compose car frame-payload))

  (define (headers-frame-e frame)
    (and (member 'flag-priority (frame-flags frame))
         (compose cadr frame-payload)))

  (define (headers-frame-sd frame)
    (and (member 'flag-priority (frame-flags frame))
         (compose caddr frame-payload)))

  (define (headers-frame-w frame)
    (and (member 'flag-priority (frame-flags frame))
         (compose cadddr frame-payload)))

  (define (headers-parse flags s)
    (let* ((s (unpad s flags))
           (priority (member 'flag-priority flags))
           (esd (and priority (defuse (string-take s 4))))
           (e (and esd (car esd)))
           (sd (and esd (cdr esd)))
           (s (if priority (string-drop s 4) s))
           (w (and priority (str->integer (string-take s 1))))
           (s (if priority (string-drop s 1) s))
           (hbf s))
      (list hbf e sd w)))

  (define (headers-payload-unparse flags frame)
    (let* ((hbf (headers-frame-hbf frame))
           (e (headers-frame-e frame))
           (sd (headers-frame-sd frame))
           (w (headers-frame-w frame))
           (priority (member 'flag-priority flags)))
      (pad (if priority (conc (fuse e sd) hbf) hbf)
           frame)))

  ; priority frame
  (define (make-priority-frame #!key sid e sd w)
    (make-frame 'priority '() sid (list e sd w) #f))

  (define priority-frame-e (compose car frame-payload))
  (define priority-frame-sd (compose cadr frame-payload))
  (define priority-frame-w (compose caddr frame-payload))

  (define (priority-payload-unparse flags frame)
    (conc (fuse (priority-frame-e frame) (priority-frame-sd frame))
          (integer->char (priority-frame-w frame))))

  (define (priority-parse flags s)
    (let* ((esd (defuse (string-take s 4)))
           (e (car esd))
           (sd (cdr esd))
           (w (char->integer (string-take-right s 1))))
      (list e sd w)))

  ; rst_stream frame
  (define (make-rst-stream-frame #!key ec sid)
    (make-frame 'rst-stream
                '()
                sid
                (list ec)))

  (define rst-stream-frame-ec (compose car frame-payload))

  (define (rst-stream-payload-unparse flags frame)
    (integer->str (rst-stream-frame-ec frame) 4))

  (define (rst-stream-parse flags s)
    (list (str->integer s)))

  ; settings frame
  (define (make-settings-frame #!key settings sid ack)
    (make-frame 'settings
                (if ack '(flag-ack) '())
                sid
                (list settings)
                #f))

  (define settings-frame-settings (compose car frame-payload))

  (define (settings-payload-unparse flags frame)
    (apply conc (map (lambda (p)
                       (conc (integer->str (car p) 2)
                             (integer->str (cdr p) 4)))
                     (settings-frame-settings frame))))

  (define (settings-parse flags s)
    (let lp ((ls '()) (b s))
      (if (string-null? b)
          (list ls)
          (let* ((six (string-take b 6))
                 (id (str->integer (string-take six 2)))
                 (value (str->integer (string-drop six 2))))
            (lp (cons (cons id value) ls) (string-drop b 6))))))

  (define settings-ack-frame (make-settings-frame sid: 0 ack: #t settings: '()))

  ; push_promise frame
  (define (make-push-promise-frame #!key sid end-headers (pad-length #f) psid hbf)
    (make-frame 'push-promise
                (if end-headers '(flag-end-headers) '())
                sid
                (list psid hbf)
                pad-length))

  (define push-promise-frame-psid (compose car frame-payload))
  (define push-promise-frame-hbf (compose cadr frame-payload))

  (define (push-promise-payload-unparse flags frame)
    (let* ((s (conc (integer->str (push-promise-frame-psid frame) 4) 
                    (push-promise-frame-hbf frame))))
      (pad s frame)))

  (define (push-promise-parse flags s)
    (let* ((s (unpad s flags))
           (psid (str->integer (string-take s 4)))
           (hbf (string-drop s 4)))
      (list psid hbf)))

  ; ping frame
  (define ping-frame-data (compose car frame-payload))
  (define (ping-payload-unparse flags frame) (ping-frame-data frame))
  (define (ping-parse flags s) (list s))
  (define (make-ping-frame #!key sid ack data)
    (make-frame 'ping (if ack '(flag-ack) '()) sid (list data) #f))

  ; goaway frame
  (define goaway-frame-ls (compose car frame-payload))
  (define goaway-frame-ec (compose cadr frame-payload))
  (define goaway-frame-dd (compose caddr frame-payload))
  (define (goaway-payload-unparse flags frame)
    (conc (integer->str (goaway-frame-ls) 4)
          (integer->str (goaway-frame-ec) 4)
          (integer->str (goaway-frame-dd) 4)))

  (define (goaway-parse flags s)
    (list (str->integer (string-take s 4))
          (str->integer (string-take (string-drop s 4) 4))
          (str->integer (string-drop s 8))))

  (define (make-goaway-frame #!key sid ls ec dd)
    (make-frame 'goaway '() sid (list ls ec dd) #f))

  ; window_update frame
  (define window-update-frame-wsi (compose car frame-payload))
  (define (window-update-payload-unparse flags frame) (integer->str (window-update-frame-wsi frame) 4))
  (define (window-update-parse flags s) (list (str->integer s)))
  (define (make-window-update-frame #!key sid wsi)
    (make-frame 'window-update '() sid (list wsi) #f))

  (define (frame-hbf frame)
    ((alist-ref (frame-type frame)
                `((headers . ,headers-frame-hbf)
                  (continuation . ,continuation-frame-hbf)
                  (push-promise . ,push-promise-frame-hbf)))
     frame))

  ; continuation frame
  (define continuation-frame-hbf (compose car frame-payload))
  (define (continuation-payload-unparse flags frame) (continuation-frame-hbf frame))
  (define (continuation-parse flags s) (list s))
  (define (make-continuation-frame #!key sid end-headers hbf)
    (make-frame 'continuation (if end-headers '(flag-end-headers) '()) sid (list hbf) #f))

  ;;; parse/unparse
  (define (parse/unparse verb)
    (lambda (t fl s)
      (let* ((fn (verb (alist-ref
                         t
                         `((data . (,data-parse . ,data-payload-unparse))
                           (headers . (,headers-parse . ,headers-payload-unparse))
                           (priority . (,priority-parse . ,priority-payload-unparse))
                           (rst-stream . (,rst-stream-parse . ,rst-stream-payload-unparse))
                           (settings . (,settings-parse . ,settings-payload-unparse))
                           (push-promise . (,push-promise-parse . ,push-promise-payload-unparse))
                           (ping . (,ping-parse . ,ping-payload-unparse))
                           (goaway . (,goaway-parse . ,goaway-payload-unparse))
                           (window-update . (,window-update-parse . ,window-update-payload-unparse))
                           (continuation . (,continuation-parse . ,continuation-payload-unparse)))))))
        (fn fl s))))

  (define payload-parse (parse/unparse car))
  (define payload-unparse (parse/unparse cdr))

  (define (frame-length f)
    (let ((pad-length (frame-pad-length f)))
      (+ (if pad-length
             (+ pad-length 1)
             0)
         (string-length
           (payload-unparse (frame-type f)
                            (frame-flags f) f))))))
