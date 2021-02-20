(in-package #:cl-megolm)

;;;;copy of
;;;;https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/olm/pk.py

(defmethod check-error ((pk-encryption pk-encryption) to-check)
  (let ((er (%olm:pk-encryption-last-error (pk-encrypt pk-encryption))))
    (string->condition er)
    pk-encryption))

(defmethod check-error ((pk-decryption pk-decryption) to-check)
  (let ((er (%olm:pk-decryption-last-error (pk-decrypt pk-decryption))))
    (string->condition er)
    pk-decryption))

(defmethod check-error ((pk-signing pk-signing) to-check)
  (let ((er (%olm:pk-signing-last-error (pk-sign pk-signing))))
    (string->condition er)
    pk-signing))

(defun new-pk-message (ephemeral-key mac ciphertext)
  (make-instance 'pk-message :ciphertext ciphertext :mac mac
                             :ephemeral ephemeral-key))

(defun clear-pk-encryption (pk-struct)
  (%olm:clear-pk-encryption pk-struct))

(defun make-pk-encryption (recipient-key)
  "Create a new PK encryption object. Creates a pointer that has to be freed later."
  (let* ((buf (cffi:foreign-string-alloc (make-string (%olm:pk-encryption-size))))
         ;;got remember that buf has to be freed when done with the object
         ;;these are the same pointer, idk why the python devs have done this.
         (pk-enc (%olm:pk-encryption buf)))
    (cffi:with-foreign-string ((byte-key byte-key-len) recipient-key)
      (clean-after ((byte-key byte-key-len))
        (%olm:pk-encryption-set-recipient-key pk-enc byte-key byte-key-len)))
    (make-instance 'pk-encryption :pk-encrypt pk-enc)))

(defmethod encrypt ((pk pk-encryption) (plaintext string))
  "Returns the encrypted pk-message instance.
 Encrypt a plaintext for the recipient set using
  %olm:pk-encryption-set-recipient-key. Writes to the ciphertext, mac, and
  ephemeral_key buffers, whose values should be sent to the recipient. mac is
  a Message Authentication Code to ensure that the data is received and
  decrypted properly. ephemeral_key is the public part of the ephemeral key
  used (together with the recipient's key) to generate a symmetric encryption
  key. If the ciphertext, mac, or
  ephemeral_key buffers were too small then the condition
  will be output-buffer-too-small. If there weren't enough random bytes then
  the condition  olm-input-buffer-too-small will be signalled."
  (with-accessors ((pk-encrypt pk-encrypt))
      pk
    (let ((r-len (%olm:pk-encrypt-random-length pk-encrypt))
          (mac-len (%olm:pk-mac-length pk-encrypt))
          (eph-key-size (%olm:pk-key-length))
          (cipher-len 0)
          (res nil))
      (cffi:with-foreign-strings (((byte-plaintext byte-plaintext-len) plaintext)
                                  (random-buffer (random-string r-len)))
        (clean-after ((byte-plaintext byte-plaintext-len))
          (setf cipher-len (%olm:pk-ciphertext-length pk-encrypt byte-plaintext-len))
          (multiple-value-bind (nc nm ne)
              (with-foreign-strings-as-lisp ((cipher-text (make-string cipher-len))
                                             (mac (make-string mac-len))
                                             (eph (make-string eph-key-size)))
                (check-error pk
                             (%olm:pk-encrypt pk-encrypt
                                              byte-plaintext byte-plaintext-len
                                              cipher-text cipher-len mac
                                              mac-len eph eph-key-size
                                              random-buffer r-len)))
            (setf res (make-instance 'pk-message :ciphertext nc
                                                 :mac nm :ephemeral ne)))))
      res)))

(defun clear-pk-decryption (pk-struct)
  (%olm:clear-pk-decryption pk-struct))

(defun gen-pk-decryption ()
  "Generates a new pk-decryption object. Creates a pointer that has to be freed 
later"
  (let ((buf
          (cffi:foreign-string-alloc (make-string (%olm:pk-decryption-size)))))
    (make-instance 'pk-decryption :public-key nil                   
                                  :pk-decrypt (%olm:pk-decryption buf))))

(defun make-pk-decryption ()
  "Create a new PK Decryption object. If fails signals either 
'olm-input-buffer-too-small or 'output-buffer-too-small"
  (let* ((pk (gen-pk-decryption))
         (key-len (%olm:pk-key-length))
         (random-len (%olm:pk-private-key-length)))
    (cffi:with-foreign-strings  ((random-buf (make-string random-len))
                                 (key-buffer (make-string key-len)))

      (let ((ret (%olm:pk-key-from-private (pk-decrypt pk)
                                           key-buffer key-len
                                           random-buf random-len)))
        (check-error pk ret)
        (setf (public-key pk) (cffi:foreign-string-to-lisp key-buffer))))
    pk))

(defmethod pickle ((pk pk-decryption) (passphrase string))
  "Stores decryption object as a base64 string. Encrypts the object using the
 supplied key. Returns the base64 string."
  (let* ((p-length (%olm:pickle-pk-decryption-length (pk-decrypt pk)))
         (res nil))
    (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
      (clean-after ((foreign-key foreign-key-length))
        (setf res 
              (cffi:with-foreign-pointer-as-string (p-buffer p-length)
                (check-error pk
                             (%olm:pickle-pk-decryption (pk-decrypt pk)
                                                        foreign-key
                                                        foreign-key-length
                                                        p-buffer
                                                        p-length))))))
    res))

;;;an actually functioning from-pickle
(defmethod from-pickle ((type (eql :pk-decrypt)) (pickle string) (passphrase string))
  "Restore a previously stored PkDecryption object.
Creates a PkDecryption object from a pickled base64 string. Decrypts
the pickled object using the supplied passphrase.
If the passphrase doesn't match the one used to encrypt the 
session then the error message for the condition 'bad-account-key is signalled.
 If the base64 the pickle couldn't be decoded then the condition signalled will be
'invalid-base64"
  (let ((ret nil))
    (cffi:with-foreign-strings (((byte-key byte-key-len) passphrase)
                                (pickle-buffer pickle)
                                ((pubkey-buffer pubkey-buffer-len)
                                 (make-string (%olm:pk-key-length))))
      (clean-after ((byte-key byte-key-len))
        (let* ((pk (gen-pk-decryption))
               (res (%olm:unpickle-pk-decryption (pk-decrypt pk)
                                                 byte-key byte-key-len
                                                 pickle-buffer (length pickle)
                                                 pubkey-buffer pubkey-buffer-len)))
          (setf (public-key pk) (cffi:foreign-string-to-lisp pubkey-buffer))
          (setf ret pk)
          (check-error pk res))))
    ret))

(defmethod decrypt ((pk pk-decryption) (pk-message pk-message))
  "Decrypt a previously encrypted pk message."
  (with-accessors ((ephemeral ephemeral)
                   (mac mac)
                   (ciphertext ciphertext))
      pk-message
    (let ((res nil))
      (cffi:with-foreign-strings (((ephemeral-key ephemeral-len) ephemeral)
                                  ((mac-buf mac-buf-len) mac)
                                  ((ciphertext-buf ciphertext-buf-len) ciphertext))
        (let* ((max-pt-len (%olm:pk-max-plaintext-length (pk-decrypt pk)
                                                         ciphertext-buf-len))
               (plaintext-buffer
                 (cffi:foreign-string-alloc (make-string max-pt-len))))
          (unwind-protect
               (clean-after ((plaintext-buffer max-pt-len))
                 (check-error pk
                              (%olm:pk-decrypt (pk-decrypt pk)
                                               ephemeral-key ephemeral-len
                                               mac-buf mac-buf-len
                                               ciphertext-buf ciphertext-buf-len
                                               plaintext-buffer max-pt-len))
                 (setf res (cffi:foreign-string-to-lisp plaintext-buffer)))
            (cffi:foreign-string-free plaintext-buffer))))
      res)))

(defun clear-pk-signing (pk-struct)
  (%olm:clear-pk-signing pk-struct))

(defun make-pk-signing ()
  "Creates a new instance of pk-signing from a randomly generated seed."
  (let* ((seed-len (%olm:pk-signing-seed-length))
         (seed (random-string seed-len))
         (signing (make-instance 'pk-signing))
         (buf (cffi:foreign-string-alloc (make-string (%olm:pk-signing-size))))
         (res nil))
    (setf (pk-sign signing) (%olm:pk-signing buf))
    (cffi:with-foreign-strings ((seed-buffer seed)
                                ((pubkey-buf pubkey-len)
                                 (make-string (%olm:pk-signing-public-key-length))))
      (clean-after ((seed-buffer seed-len))
        (setf res (%olm:pk-signing-key-from-seed
                   (pk-sign signing)
                   pubkey-buf pubkey-len
                   seed-buffer seed-len)))
      (check-error signing res)
      (setf (public-key signing)
            (cffi:foreign-string-to-lisp pubkey-buf)))
    signing))

(defmethod sign ((pk pk-signing) (message string))
  "Sign a message."
  (cffi:with-foreign-strings (((message-buf message-buf-len) message)
                              ((signature-buf signature-buf-len)
                               (make-string (%olm:pk-signature-length))))
    (check-error pk (%olm:pk-sign (pk-sign pk)
                                  message-buf message-buf-len
                                  signature-buf signature-buf-len))
    (cffi:foreign-string-to-lisp signature-buf)))
    








