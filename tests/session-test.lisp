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
    (assert-error 'empty-ciphertext
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
      (unwind-protect
           (progn 
             (remove-one-time-keys bob bob-session)
             (assert-true (string= plaintext (decrypt bob-session message)))
             (let* ((bob-pt "doodly diddly")
                    (bob-encrypted (encrypt bob-session bob-pt)))
               (assert-true (eql (type-of bob-encrypted) 'olm-message))
               
               (assert-true (string= bob-pt (decrypt session bob-encrypted)))))
        (cleanup bob-session)))))

(session-test matches
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "diddly doodly")
           (message (encrypt session plaintext));;session is outbound with alice
           (bob-session (make-inbound-session bob message (curve alice))))
      (unwind-protect
           (progn 
             (assert-true (string= plaintext (decrypt bob-session message)))
             (let* ((second (encrypt session "doodly diddly")))
               (assert-true (matchesp bob-session second nil))
               (assert-true (matchesp bob-session second (curve alice)))))
        (cleanup bob-session)))))

(session-test invalid
  (mvb (alice bob session)
      (gen-session)
    (let ((message (make-olm-message "X")))
      (assert-error 'invalid-message-type
                    (matchesp session message nil))
      (setf message (make-olm-pre-key-message "X"))
      (setf (ciphertext message) "")
      (assert-error 'empty-ciphertext (matchesp session message nil))
      (assert-error 'empty-ciphertext (make-inbound-session bob message nil))
      (assert-error 'empty-one-time-key (make-outbound-session alice "" "x"))
      (assert-error 'empty-id-key (make-outbound-session alice "x" "")))))

(session-test doesnt-match
  (mvb (alice bob session)
      (gen-session)
    (let* ((plaintext "oooga booga")
           (message (encrypt session plaintext))
           (alice-id (curve alice))
           (bob-session (make-inbound-session bob message alice-id)))
      (unwind-protect
           (let ((new-session (make-session)))
             (unwind-protect 
                  (let ((new-message (encrypt new-session plaintext)))
                    (assert-false (matchesp bob-session new-message nil)))
               (cleanup new-session)))
        (cleanup bob-session)))))
