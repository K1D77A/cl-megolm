(in-package #:cl-megolm-tests)

(account-test creation
  (assert-equal 4 (length (identity-keys account))))

(account-test pickle 
  (let* ((pickle (pickle account "abc"))  
         (df-keys (identity-keys account))
         (from-pickle (from-pickle :account pickle "abc")))
    (assert-equal (identity-keys from-pickle) df-keys)
    (cleanup from-pickle)))

(account-test wrong-passphrase-pickle
  (let* ((pickle (pickle account "abc")))
    (assert-error 'bad-account-key (from-pickle :account pickle "abcd"))))

(account-test one-time-keys
  (generate-one-time-keys account 10)
  (assert-equal 20 (length (second (one-time-keys account)))))

(account-test max-one-time-keys
  (assert-equal 100 (max-one-time-keys account)))

(account-test publish-one-time-keys
  (generate-one-time-keys account 10)
  (let ((otk (one-time-keys account)))
    (assert-true otk)
    (assert-equal 20 (length (second otk)))
    (mark-keys-as-published account)
    (assert-false (second (one-time-keys account)))))

(account-test valid-signature
  (let* ((message "its a secret to everybody")
         (sig (sign account message))
         (signing-key (ed25519 account)))
    (assert-true (ed25519-verify-p signing-key message sig))))

(account-test invalid-signature
  (let* ((message "its a secret to everybody")
         (account2 (make-account))
         (sig (sign account message))
         (signing-key (ed25519 account2)))
    (assert-nil (ed25519-verify-p signing-key message sig))
    (cleanup account2)))

(account-test signature-verification-twice
  (let* ((message "its a secret to everybody")
         (sig (sign account message))
         (signing-key (ed25519 account)))
    (assert-true (ed25519-verify-p signing-key message sig))
    (assert-equal sig (sign account message))
    (assert-true (ed25519-verify-p signing-key message sig))
    (assert-equal sig (sign account message))))










