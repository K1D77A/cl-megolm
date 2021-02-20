(in-package #:cl-megolm-tests)

(account-test creation
  (assert-equal 4 (length (identity-keys account))))

;;;next is supposed to be a pickle, haven't fixed that yet


;;(define-test account-pickle ;;we only have passphrase pickling

;;(define-test wrong-passphrase-pickle

(account-test one-time-keys
  (assert-equal 20 (length (second (generate-one-time-keys account 10)))))

(account-test max-one-time-keys
  (assert-equal 100 (max-one-time-keys account)))

(account-test publish-one-time-keys
  (generate-one-time-keys account 10)
  (let ((otk (one-time-keys account)))
    (assert-true otk)
    (assert-equal 20 (length (second otk)))
    (mark-keys-as-published account)
    (assert-false (second (one-time-keys account)))))
    
    
    



