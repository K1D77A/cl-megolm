(in-package #:cl-megolm)
;;;;copy of ;;;;https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/olm/account.py


(defun gen-account ()
  (let* ((size (%olm:account-size))
         (buf (cffi:foreign-string-alloc (make-string size))))
    (%olm:account buf)))

(defun make-account ()
  "Create a new Olm account. Creates a new account and its matching identity key pair.
Signals 'olm-account-error on failure. If there weren't enough random bytes
signals 'olm-account-not-enough-random."
  (let* ((acc (gen-account))
         (len (%olm:create-account-random-length acc)))
    (cffi:with-foreign-string (ran-buf (random-string len))
      (let ((ret (%olm:create-account acc ran-buf len)))
        (let ((account (make-instance 'account :account acc)))
          (check-error account ret)
          account)))))

(defmethod ed25519 ((account account))
  (let ((identity-keys (identity-keys account)))
    (pkv identity-keys :|ed25519|)))

(defmethod curve ((account account))
  (let ((identity-keys (identity-keys account)))
    (pkv identity-keys :|curve25519|)))

(defmethod pickle ((account account) (passphrase string))
  "Store an Olm account.
Stores an account as a base64 string. Encrypts the account using the
supplied passphrase. Returns a byte object containing the base64
encoded string of the pickled account. Signals 'olm-account-error on
failure."
  (let* ((p-length (%olm:pickle-account-length (account account)))
         (res nil))
    ;; For safety one should probably bind
    ;; cffi:*default-foreign-encoding* here as the next two with-
    ;; macros rely on it.  The default of utf-8 should be fine though.
    (cffi:with-foreign-strings (((foreign-key foreign-key-length) passphrase)
                                (p-buffer (make-string p-length)))
      ;; This stack allocates.  If p-size can be large, then you'll
      ;; need to do an unwind-protect, allocate, free either in your
      ;; own macro or manually.
      (clean-after ((foreign-key foreign-key-length))
        (setf res
              (cffi:with-foreign-pointer-as-string (p-buffer p-length)
                (check-error account
                             (%olm:pickle-account (account account)
                                                  foreign-key
                                                  foreign-key-length
                                                  p-buffer
                                                  p-length))))))
    res))

(defmethod from-pickle ((type (eql :account)) (pickle string) (passphrase string))
  "Load a previously stored olm account.
Loads an account from a pickled base64-encoded string and returns an
Account object. Decrypts the account using the supplied passphrase.
If the passphrase doesn't match the
one used to encrypt the account then the condition signalled for the
exception will be 'bad-account-key. if the base64 couldn't be decoded
then the condition signalled will be 'invalid-base64."
  (let ((ret nil))
    (cffi:with-foreign-strings (((byte-key byte-key-len) passphrase)
                                (pickle-buffer pickle))
      (clean-after ((byte-key byte-key-len))
        (let* ((account (make-instance 'account :account (gen-account)))
               (res (%olm:unpickle-account (account account)
                                           byte-key byte-key-len
                                           pickle-buffer (length pickle))))
          (setf ret account)
          (check-error account res))))
    ret))

(defmethod identity-keys ((account account))
  "Public part of the identity keys of the account."
  (let ((len (%olm:account-identity-keys-length (account account)))
        (out nil))
    (cffi:with-foreign-string (outbuf (make-string len))
      (check-error account
                   (%olm:account-identity-keys (account account) outbuf len))
      (setf out (cffi:foreign-string-to-lisp outbuf)))
    (jojo:parse out)))

(defmethod sign ((account account) (message string))
  "Signs a message with this account.

        Signs a message with the private ed25519 identity key of this account.
        Returns the signature.
        signals olm-account-error on failure."
  (let ((len (%olm:account-signature-length (account account))))
    ;;(cffi:*default-foreign-encoding* :ascii))
    (cffi:with-foreign-strings (((foreign-m foreign-m-length) message)
                                (output (make-string len)))
      (clean-after ((foreign-m foreign-m-length))
        (check-error account
                     (%olm:account-sign (account account)
                                        foreign-m foreign-m-length
                                        output len))
        (cffi:foreign-string-to-lisp output)))))

(defmethod max-one-time-keys ((account account))
  "The maximum number of one-time keys the account can store."
  (check-error account
               (%olm:account-max-number-of-one-time-keys (account account))))

(defmethod mark-keys-as-published ((account account))
  "Mark the current set of one-time keys as being published."
  (check-error account
               (%olm:account-mark-keys-as-published (account account))))

(defmethod generate-one-time-keys ((account account) n)
  "Generate a number of new one-time keys.

        If the total number of keys stored by this account exceeds
        max_one_time_keys() then the old keys are discarded.
        Signals olm-account-error on error."
  (let ((len (%olm:account-generate-one-time-keys-random-length
              (account account) n)))
    (cffi:with-foreign-string (ran (random-string len))
      (check-error account
                   (%olm:account-generate-one-time-keys (account account)
                                                        n ran len)))))

(defmethod one-time-keys ((account account))
  "The public part of the one-time keys for this account."
  (let ((len (%olm:account-one-time-keys-length (account account))))
    (cffi:with-foreign-string (keys (make-string len))
      (check-error account
                   (%olm:account-one-time-keys (account account) keys len))
      (jojo:parse (cffi:foreign-string-to-lisp keys)))))

(defmethod remove-one-time-keys ((account account) (session session))
  "Remove used one-time keys.

        Removes the one-time keys that the session used from the account.
        Raises olm-account-error on failure. If the account doesn't have any
        matching one-time keys then signals 'bad-message-key-id"
  (check-error account
               (%olm:remove-one-time-keys (account account) (session session))))


