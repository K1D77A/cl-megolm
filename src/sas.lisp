(in-package #:cl-megolm)
;;;;conversion of
;;;;https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/olm/sas.py

(defclass sas ()
  ((buf
    :accessor buf
    :initarg :buf)
   (sas
    :accessor sas
    :initarg :sas)))

(defmethod check-error ((sas sas) to-check)
  (let ((er (%olm:sas-last-error (sas sas))))
    (string->condition er)
    sas))

(defun make-sas (&optional other-user-pubkey)
  (let* ((buf (cffi:foreign-string-alloc (make-string  (%olm:sas-size))))
         (sas (%olm:sas buf))
         (random-length (%olm:create-sas-random-length sas))
         (random-string (random-string random-length)))
    (let ((obj (make-instance 'sas :sas sas :buf buf)))
      (cffi:with-foreign-string (random random-string)
        (check-error obj (%olm:create-sas (sas obj) random random-length)))
      (when other-user-pubkey
        (set-pubkey sas other-user-pubkey)))))

(defmethod set-pubkey ((sas sas) (pubkey string))
  "Set the public key of the other user.

        This sets the public key of the other user, it needs to be set before
        bytes can be generated for the authentication string and a MAC can be
        calculated."
  (cffi:with-foreign-string ((key keylen) pubkey)
    (check-error sas
                 (%olm:sas-set-their-key (sas sas) key keylen))))

(defmethod pubkey ((sas sas))
  "Get the public key for the SAS object.

        This returns the public key of the SAS object that can then be shared
        with another user to perform the authentication process."
  (let ((len (%olm:sas-pubkey-length (sas sas))))
    (cffi:with-foreign-pointer-as-string (pubkey len)
      (check-error sas (%olm:sas-get-pubkey (sas sas) pubkey len)))))

(defmethod other-key-set-p ((sas sas))
  "Check if the other user's pubkey has been set."
  (= (%olm:sas-is-their-key-set (sas sas)) 1))

(defmethod set-their-public-key ((sas sas) (pubkey string))
  "Set the public key of the other user.

        This sets the public key of the other user, it needs to be set before
        bytes can be generated for the authentication string and a MAC can be
        calculated."
  (cffi:with-foreign-string ((byte-key byte-key-len) pubkey)
    (check-error sas (%olm:sas-set-their-key (sas sas) byte-key byte-key-len))))

(defmethod generate-bytes ((sas sas) (extra-info string) (length integer))
  "Generate bytes to use for the short authentication string."
  (when (< length 1)
    (error "Length needs to be greater than 1"))
  (cffi:with-foreign-pointer-as-string (outbuf length)
    (cffi:with-foreign-string ((byte-extra byte-extra-len) extra-info)
      (check-error sas (%olm:sas-generate-bytes
                        (sas sas)
                        byte-extra byte-extra-len
                        outbuf length)))))

(defmethod calculate-mac ((sas sas) (message string) (extra-info string))
  "Generate a message authentication code based on the shared secret."
  (cffi:with-foreign-pointer-as-string ((mac-buf mac-buf-len)
                                        (%olm:sas-mac-length (sas sas)))
    (cffi:with-foreign-strings (((byte-extra byte-extra-len) extra-info)
                                ((byte-message byte-message-len) message))
      (check-error sas (%olm:sas-calculate-mac (sas sas)
                                               byte-message byte-message-len
                                               byte-extra byte-extra-len
                                               mac-buf mac-buf-len)))))

(defmethod calculate-mac-long-kdf ((sas sas) (message string) (extra-info string))
  "Generate a message authentication code based on the shared secret.

        This function should not be used unless compatibility with an older
        non-tagged Olm version is required."
  (cffi:with-foreign-pointer-as-string ((mac-buf mac-buf-len)
                                        (%olm:sas-mac-length (sas sas)))
    (cffi:with-foreign-strings (((byte-extra byte-extra-len) extra-info)
                                ((byte-message byte-message-len) message))
      (check-error sas (%olm:sas-calculate-mac-long-kdf (sas sas)
                                                        byte-message byte-message-len
                                                        byte-extra byte-extra-len
                                                        mac-buf mac-buf-len)))))




