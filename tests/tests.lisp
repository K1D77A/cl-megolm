;;;; cl-megolm-tests.lisp

(in-package #:cl-megolm-tests)

(defmacro cleanup-after (object &body body)
  `(unwind-protect (progn ,@body)
     (cleanup ,object)))

(defmacro account-test (name &body body)
  (let ((name (intern (string-upcase (format nil "account-~A" name)))))
    `(define-test ,name
       (let ((account (cl-megolm:make-account)))
         (cleanup-after account
           ;;           (handler-case
           (progn ,@body))))))
             ;;(olm-error ()
               ;;(assert-true nil))))))))
