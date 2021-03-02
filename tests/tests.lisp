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
           (progn (cleanup outbound)
                  (cleanup inbound)))))))

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
           (progn (cleanup outbound)
                  (cleanup inbound)))))))

(defmacro pk-test (name &body body)
  (let ((name (intern (string-upcase (format nil "pk-~A" name)))))
    `(define-test ,name
       (:tag :pk)
       (let* ((decryption (make-pk-decryption))
              (encryption (make-pk-encryption (public-key decryption))))
         (declare (ignorable decryption encryption))
         (unwind-protect (handler-case
                             (progn ,@body)
                           (olm-error ()
                             (assert-true nil)))
           (progn (cleanup decryption)
                  (cleanup encryption)))))))

(defmacro pk-signing-test (name &body body)
  (let ((name (intern (string-upcase (format nil "pk-signing-~A" name)))))
    `(define-test ,name
       (:tag :pk :pk-signing)
       (let* ((signing (make-pk-signing)))
         (declare (ignorable signing))
         (cleanup-after signing
           (handler-case
               (progn ,@body)
             (olm-error ()
               (assert-true nil))))))))

(defmacro sas-test (name &body body)
  (let ((name (intern (string-upcase (format nil "sas-~A" name)))))
    `(define-test ,name
       (:tag :sas)
       (let* ((alice (make-sas))
              (bob (make-sas))
              (%message "test message")
              (%extra-info "extra-info"))
         (declare (ignorable alice bob %message %extra-info))
         (unwind-protect (handler-case
                             (progn ,@body)
                           (olm-error ()
                             (assert-true nil)))
           (progn (cleanup alice)
                  (cleanup bob)))))))

(defmacro session-test (name &body body)
  (let ((name (intern (string-upcase (format nil "session-~A" name)))))
    (alexandria:with-gensyms (to-clean)
      `(define-test ,name
         (:tag :session :notgroup)
         (let* ((alice (make-account))
                (bob (make-account))
                (,to-clean nil));;so the user doesn't have to keep track of
           ;;sessions they generate, they can be automatically deleted.
           (declare (ignorable alice bob))
           (flet ((gen-session ()
                    (let ((a1 (make-account));;alice
                          (a2 (make-account)));;bob
                      (push a1 ,to-clean)
                      (push a2 ,to-clean)
                      (generate-one-time-keys a2 1)
                      (let* ((id (curve a2))
                             (one-time (second
                                        (second
                                         (one-time-keys a2))))
                             (sesh (make-outbound-session a1 one-time id)))
                        (push sesh ,to-clean)
                        (values a1 a2 sesh)))))
             (unwind-protect
                  (handler-case
                      (progn ,@body)
                    (olm-error ()
                      (assert-true nil)))
               (progn (cleanup alice)
                      (cleanup bob)
                      (mapc #'cleanup ,to-clean)))))))))
