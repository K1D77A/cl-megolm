(in-package #:cl-megolm-tests)

(outbound-group-test session-id
  (assert-true (stringp (id outbound))))

(outbound-group-test session-index
  (assert-equal 0 (message-index outbound)))

(outbound-group-test pickle
  (let* ((pickle (pickle outbound "abc"))  
         (id (id outbound))
         (from-pickle (from-pickle :outbound-group pickle "abc")))
    (assert-equal (id from-pickle) id)
    (cleanup from-pickle)))

(outbound-group-test bad-pickle
  (let* ((pickle (pickle outbound "abc")))
    (assert-error 'bad-account-key (from-pickle :outbound-group pickle "abcd"))))

(inbound-group-test pickle
  (let* ((pickle (pickle inbound "abc"))  
         (id (id inbound))
         (from-pickle (from-pickle :inbound-group pickle "abc")))
    (assert-equal (id from-pickle) id)
    (cleanup from-pickle)))

(inbound-group-test bad-pickle
  (let* ((pickle (pickle inbound "abc")))
    (assert-error 'bad-account-key (from-pickle :inbound-group pickle "abcd"))))

(inbound-group-test bad-decrypt
  (assert-error 'invalid-base64 (decrypt inbound "oogly")))

(inbound-group-test export
  (let* ((imported
           (import-session :inbound (export-session inbound
                                                    (first-known-index inbound))))
         (encrypted (encrypt outbound "test")))
    (multiple-value-bind (pt n)
        (decrypt imported encrypted)
      (assert-equal n 0)
      (assert-equal pt "test"))))

(inbound-group-test first-index
  (assert-true (integerp (first-known-index inbound))))

(inbound-group-test test-encrypt
  (print "boof")
  (let* ((encrypt (encrypt outbound "test"))
         (decrypt (decrypt inbound encrypt)))
    (assert-equal "test" decrypt)))

(inbound-group-test test-decrypt
  (print "oof")
  (let* ((encrypt (encrypt outbound "test"))
         (decrypt (decrypt inbound encrypt)))
    (assert-equal "test" decrypt)))

(inbound-group-test test-decrypt-twice
  (let* ((encrypt (encrypt outbound "test"))
         (decrypt (decrypt inbound encrypt))
         (encrypt2 (encrypt outbound "test2")))
    (declare (ignore decrypt))
    (multiple-value-bind (dec index)
        (decrypt inbound encrypt2)
      (assert-equal "test2" dec)
      (assert-equal 1 index))))

(inbound-group-test id
  (print "oof")
  (assert-equal (id inbound) (id outbound)))









