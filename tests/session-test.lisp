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
    (assert-error 'bad-account-key (from-pickle :session pickle "abcdd"))))

(session-test encrypt
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "diddly doodly")
           (message (encrypt session plaintext)));;session is outbound with alice
      (assert-true (eql (type-of message) 'olm-message-pre-key))
      (let ((bob-session (make-inbound-session bob message nil)))
        (unwind-protect 
             (assert-true (string= plaintext (decrypt bob-session message)))
          (cleanup bob-session))))))

(session-test empty-message
  (mvb (alice bob session)
      (gen-session)
    (assert-error 'simple-error 
                  (decrypt session (make-olm-pre-key-message "")))))

(session-test inbound-with-id
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "diddly doodly")
           (message (encrypt session plaintext)));;session is outbound with alice
      (let ((bob-session (make-inbound-session bob message (curve alice))))        
        (unwind-protect 
             (assert-true (string= plaintext (decrypt bob-session message)))
          (cleanup bob-session))))))

(session-test two-messages
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "diddly doodly")
           (message (encrypt session plaintext));;session is outbound with alice
           (bob-session (make-inbound-session bob message (curve alice))))
      (remove-one-time-keys bob bob-session)
      (assert-true (string= plaintext (decrypt bob-session message)))
      (let* ((bob-pt "doodly diddly")
             (bob-encrypted (encrypt bob-session bob-pt)))
        (assert-true (eql (type-of bob-encrypted) 'olm-message))
        (unwind-protect 
             (assert-true (string= bob-pt (decrypt session bob-encrypted)))
          (cleanup bob-session))))))

(session-test matches
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "diddly doodly")
           (message (encrypt session plaintext));;session is outbound with alice
           (bob-session (make-inbound-session bob message (curve alice))))
      (assert-true (string= plaintext (decrypt bob-session message)))
      (unwind-protect 
           (let* ((second (encrypt session "doodly diddly")))
             (assert-true (matchesp bob-session second nil))
             (assert-true (matchesp bob-session second (curve alice))))
        (cleanup bob-session)))))


