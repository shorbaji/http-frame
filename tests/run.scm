(use srfi-13)

(use test http-frame)

(define good-frames
  `((data 1 "hello" #t)
    (headers 1 "encoded header block fragment" #t #t #f)
    (priority 1 0 1 2)
    (rst-stream 1 2)
    (push-promise 1 2 "encoded header header block fragment" #t)
    (ping "-opaque-" #t)
    (goaway 1 7 "additional debug data")
    (window-update 1 7)
    (continuation 1 "encoded header block fragment" #t)))

(define (same a b)
  (and (eq? (length a)
	    (length b))
       (every (lambda (x y)
		(if (string? x)
		    (and (string? y)
			 (string=? x y))
		    (eqv? x y)))
	      a
	      b)))

(test-group (conc "good frames")
	    (for-each
	     (lambda (f)
	       (let* ((r (with-input-from-string
					 (with-output-to-string (lambda ()
								  (write-frame f)))
				       (lambda ()
					 (read-frame)))))
		 (test-assert (conc "frame: " f " " r)
			      (same f r))))
	     good-frames))

