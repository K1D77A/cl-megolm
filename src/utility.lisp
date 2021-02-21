(in-package #:cl-megolm)

(defun gen-utility ()
  (let ((buf (cffi:foreign-string-alloc (make-string (%olm:utility-size)))))
    (make-instance 'utility :utility (%olm:utility buf))))

(defmethod %ed25519-verify ((utility utility) (key string) (message string)
                            (signature string))
  (cffi:with-foreign-strings (((key-buf key-len) key )
                              ((message-buf message-len) message)
                              ((signature-buf signature-len) signature))
    (clean-after ((message-buf message-len))
      (check-error utility 
                   (%olm:ed25519-verify (utility utility)
                                        key-buf key-len
                                        message-buf message-len
                                        signature-buf signature-len)))))

(defmethod %sha256 ((utility utility) (message string))
  (cffi:with-foreign-strings (((message-buf message-len) message)
                              ((hash-buf hash-len)
                               (make-string (%olm:sha256-length (utility utility)))))
    (check-error utility (%olm:sha256 (utility utility)
                                      message-buf message-len
                                      hash-buf hash-len))
    (cffi:foreign-string-to-lisp hash-buf)))

(defun sha256 (input-string)
  (let ((util (gen-utility)))
    (unwind-protect (%sha256 util input-string)
      (cleanup util))))

(defun ed25519-verify-p (key message signature)
  (let ((util (gen-utility)))
    (unwind-protect (to-bool (%ed25519-verify util key message signature))
      (cleanup util))))



