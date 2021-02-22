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
  (let* ((pickle (pickle outbound "abc"))  
         (id (id outbound)))
    (assert-error 'bad-account-key (from-pickle :outbound-group pickle "abcd"))))

(inbound-group-test pickle
  (let* ((pickle (pickle inbound "abc"))  
         (id (id inbound))
         (from-pickle (from-pickle :inbound-group pickle "abc")))
    (assert-equal (id from-pickle) id)
    (cleanup from-pickle)))

(inbound-group-test bad-pickle
  (let* ((pickle (pickle inbound "abc"))  
         (id (id inbound)))
    (assert-error 'bad-account-key (from-pickle :inbound-group pickle "abcd"))))

(inbound-group-test bad-decrypt
  (assert-error 'bad-message-version (decrypt inbound "oogly")))

;; (inbound-group-test export
;;   (let ((imported
;;           (import-session :inbound (export-session inbound
;;                                                    (first-known-index inbound)))))
;;importing isn't working for some reason. I don't understand where the
;;invalid-base64 errors come from, there isn't a problem when you pickle/unpickle
;;from base64...

(inbound-group-test first-index
  (assert-true (integerp (first-known-index inbound))))

;; (inbound-group-test test-encrypt
;;   (assert-equal "True" )







