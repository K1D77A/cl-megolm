(in-package #:cl-megolm-tests)

(defmacro mvb (values value-form &body body)
  `(multiple-value-bind ,values
       ,value-form
     (declare (ignorable ,@values))
     (progn ,@body)))

(session-test creation
  (let ((one #1=(mvb (a b s) (gen-session) s))
        (two #1#))
    (assert-true (string/= (id one) (id two)))))

(session-test pickle
  (let* ((s (mvb (a b s) (gen-session) s))
         (pickle (pickle s "abc"))
         (from (from-pickle :session pickle "abc")))
    (unwind-protect
         (assert-true (string= (id s) (id from)))
      (cleanup from))))

(session-test bad-pass-pickle
  (let* ((s (mvb (a b s) (gen-session) s))
         (pickle (pickle s "abc")))
    (print "bad pickle")
    (assert-error 'bad-account-key (from-pickle :session pickle "abc"))))

(session-test encrypt
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "dis a secret")
           (message (encrypt session plaintext)));;session is outbound with alice
      (print "googly")
      (assert-true (eql (type-of message) 'olm-message-pre-key))
      (let ((bob-session (make-inbound-session bob message nil)))
        (unwind-protect 
             (assert-true (string= plaintext (decrypt bob-session message)))
          (cleanup bob-session))))))
      
      





