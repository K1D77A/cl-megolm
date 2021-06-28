(in-package #:cl-megolm)
;;;;conversion of
;;;;https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/olm/sas.py

(defun make-sas (&optional other-user-pubkey)
  (let* ((buf (cffi:foreign-string-alloc (make-string  (%olm:sas-size))))
         (sas (%olm:sas buf))
         (random-length (%olm:create-sas-random-length sas)))
    (let ((obj (make-instance 'sas :sas sas)))
      (cffi:with-foreign-string (random (random-string random-length))      
        (create-sas obj random random-length))
      (when other-user-pubkey
        (check-type other-user-pubkey string)
        (set-their-public-key obj other-user-pubkey))
      obj)))

(defmethod create-sas ((sas sas) buf len)
  (check-error sas (%olm:create-sas (sas sas) buf len)))

(defmethod create-sas ((sas sas) (buf array) len)
  (with-foreign-vector (buf buf)
    (check-error sas (%olm:create-sas (sas sas) buf len))))

(defmethod pubkey ((sas sas))
  "Get the public key for the SAS object.

        This returns the public key of the SAS object that can then be shared
        with another user to perform the authentication process."
  (let ((len (%olm:sas-pubkey-length (sas sas))))
    (cffi:with-foreign-string ((pubkey-buffer pubkey-len) (make-string len))
      (check-error sas (%olm:sas-get-pubkey (sas sas)
                                            pubkey-buffer pubkey-len))
      (cffi:foreign-string-to-lisp pubkey-buffer :count len))))

(defmethod other-key-set-p ((sas sas))
  "Check if the other user's pubkey has been set."
  (= (%olm:sas-is-their-key-set (sas sas)) 1))

(defmethod set-their-public-key ((sas sas) (pubkey string))
  "Set the public key of the other user.

        This sets the public key of the other user, it needs to be set before
        bytes can be generated for the authentication string and a MAC can be
        calculated."
  (with-foreign-vector ((byte-key byte-key-len) (to-bytes pubkey))
    (check-error sas (%olm:sas-set-their-key (sas sas)
                                             byte-key byte-key-len))))

(defmethod generate-bytes ((sas sas) (extra-info string) (length integer))
  "Generate bytes to use for the short authentication string."
  (when (<= length 5)
    (error "Length needs to be greater than or equal to 5"))
  (cffi:with-foreign-string (outbuf (make-string length))
    (with-foreign-vector ((byte-extra byte-extra-len) (to-bytes extra-info))
      (check-error sas
                   (%olm:sas-generate-bytes (sas sas)
                                            byte-extra byte-extra-len
                                            outbuf length))
      (let ((ret (make-array length :element-type '(unsigned-byte 8))))
        (loop :for i :from 0 :below length
              :do (setf (aref ret i)
                        (cffi:mem-aref outbuf :uint8 i)))
        ret))))


(defmethod calculate-mac ((sas sas) (message string) (extra-info string))
  "Generate a message authentication code based on the shared secret."
  (let ((res ()))
    (cffi:with-foreign-string ((mac-buf mac-buf-len)
                               (make-string (%olm:sas-mac-length (sas sas))))
      (with-foreign-vector ((byte-extra byte-extra-len) (to-bytes extra-info))
        (with-foreign-vector ((byte-message byte-message-len) (to-bytes message))
          (let ((ret (%olm:sas-calculate-mac (sas sas)
                                             byte-message byte-message-len
                                             byte-extra byte-extra-len
                                             mac-buf mac-buf-len)))
            (check-error sas ret)
            (setf res (cffi:foreign-string-to-lisp mac-buf
                                                   :count (1- mac-buf-len)))))))
    res))

(defmethod calculate-mac-long-kdf ((sas sas) (message string) (extra-info string))
  "Generate a message authentication code based on the shared secret.

        This function should not be used unless compatibility with an older
        non-tagged Olm version is required."
  (let ((res ()))
    (cffi:with-foreign-string ((mac-buf mac-buf-len)
                               (make-string (%olm:sas-mac-length (sas sas))))
      (with-foreign-vector ((byte-extra byte-extra-len) (to-bytes extra-info))
        (with-foreign-vector ((byte-message byte-message-len) (to-bytes message))
          (let ((ret (%olm:sas-calculate-mac-long-kdf (sas sas)
                                                      byte-message byte-message-len
                                                      byte-extra byte-extra-len
                                                      mac-buf mac-buf-len)))
            (check-error sas ret)
            (setf res (cffi:foreign-string-to-lisp mac-buf
                                                   :count (1- mac-buf-len)))))))
    res))




