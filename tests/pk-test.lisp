(in-package #:cl-megolm-tests)

(pk-test decryption
  (let* ((plaintext "Its a secret to everyone")
         (encrypted (encrypt encryption plaintext))
         (decrypted (decrypt decryption encrypted)))
    (assert-equal plaintext decrypted)))

(pk-test invalid-decryption
  (let* ((plaintext "Its a secret to everyone")
         (encrypted (encrypt encryption plaintext)))
    (setf (ephemeral encrypted) "oogly")
    (assert-error 'bad-message-mac (decrypt decryption encrypted))))

(pk-test pickling
  (let* ((plaintext "abc")
         (encrypted (encrypt encryption plaintext))
         (pickle (pickle decryption "pass"))
         (unpickled (from-pickle :pk-decrypt pickle "pass")))
    (assert-equal plaintext (decrypt unpickled encrypted))))

(pk-test invalid-pickling
  (let* ((pickle (pickle decryption "pass")))
    (assert-error 'bad-account-key (from-pickle :pk-decrypt pickle ""))))

(pk-signing-test signing
  (let* ((signature (sign signing "abc"))
         (key (public-key signing)))
    (assert-true (ed25519-verify-p key "abc" signature))))






