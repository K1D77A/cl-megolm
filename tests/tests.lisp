;;;; cl-megolm-tests.lisp

(in-package #:cl-megolm-tests)

(defmacro cleanup-after (object &body body)
  `(prog1 (progn ,@body)
     (cleanup ,object)))

(defmacro account-test (name &body body)
  (let ((name (intern (string-upcase (format nil "account-~A" name)))))
    `(define-test ,name
       (let ((account (cl-megolm:make-account )))
         (cleanup-after account
           (progn ,@body))))))
