;;;; cl-megolm-tests.lisp

(in-package #:cl-megolm-tests)

(setf lisp-unit:*print-summary* t)

(defmacro cleanup-after (object &body body)
  `(unwind-protect (progn ,@body)
     (cleanup ,object)))

(defmacro account-test (name &body body)
  (let ((name (intern (string-upcase (format nil "account-~A" name)))))
    `(define-test ,name
       (:tag :account)
       (let ((account (cl-megolm:make-account)))
         (cleanup-after account
           (handler-case
               (progn ,@body)
             (olm-error ()
               (assert-true nil))))))))

(defmacro outbound-group-test (name &body body)
  (let ((name (intern (string-upcase (format nil "outbound-group-~A" name)))))
    `(define-test ,name
       (:tag :session :group :outbound)
       (let ((outbound (make-outbound-group-session)))
         (cleanup-after outbound
           (handler-case
               (progn ,@body)
             (olm-error ()
               (assert-true nil))))))))

(defmacro group-test (name &body body)
  (let ((name (intern (string-upcase (format nil "group-~A" name)))))
    `(define-test ,name
       (:tag :session :group :both)
       (let* ((outbound (make-outbound-group-session))
              (inbound (make-inbound-group-session (session-key outbound))))
         (declare (ignorable inbound outbound))
         (unwind-protect (handler-case
                             (progn ,@body)
                           (olm-error ()
                             (assert-true nil)))
           (progn (cleanup-after outbound
                    (cleanup-after inbound))))))))

(defmacro inbound-group-test (name &body body)
  (let ((name (intern (string-upcase (format nil "inbound-group-~A" name)))))
    `(define-test ,name
       (:tag :session :group :inbound)
       (let* ((outbound (make-outbound-group-session))
              (inbound (make-inbound-group-session (session-key outbound))))
         (declare (ignorable inbound outbound))
         (unwind-protect (handler-case
                             (progn ,@body)
                           (olm-error ()
                             (assert-true nil)))
           (progn (cleanup-after outbound
                    (cleanup-after inbound))))))))
