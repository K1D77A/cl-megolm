(in-package #:cl-megolm)

(defun gen-utility ()
  (let ((buf (cffi:foreign-string-alloc (make-string (%olm:utility-size)))))
    (make-instance 'utility :utility (%olm:utility buf))))

(defmethod %ed25519-verify ((utility utility) (key string) (message string)
                            (signature string))
  (with-foreign-vector ((key-buf key-len) (to-bytes key))
    (with-foreign-vector ((message-buf message-len) (to-bytes message))
      (with-foreign-vector ((signature-buf signature-len) (to-bytes signature))
        (clean-after ((message-buf message-len))
          (check-error utility
                       (%olm:ed25519-verify (utility utility)
                                            key-buf key-len
                                            message-buf message-len
                                            signature-buf signature-len)))))))

(defmethod %sha256 ((utility utility) (message string))
  (let ((ret nil))
    (with-foreign-vector ((message-buf message-len) (to-bytes message))
      (cffi:with-foreign-string ((hash-buf hash-len)
                                 (make-string (%olm:sha256-length
                                               (utility utility))))
        (check-error utility (%olm:sha256 (utility utility)
                                          message-buf message-len
                                          hash-buf hash-len))
        (setf ret (cffi:foreign-string-to-lisp hash-buf))))
    ret))

(defun sha256 (input-string)
  (let ((util (gen-utility)))
    (unwind-protect (%sha256 util input-string)
      (cleanup util))))

(defun ed25519-verify (key message signature)
  (let ((util (gen-utility)))
    (unwind-protect (%ed25519-verify util key message signature)
      (cleanup util))))

(defun ed25519-verify-p (key message signature)
  (let ((util (gen-utility)))
    (unwind-protect
         (handler-case
             (to-bool  (%ed25519-verify util key message signature) 0 -1)
           (olm-error ()
             nil))
      (cleanup util))))



