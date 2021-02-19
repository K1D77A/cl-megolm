(in-package #:cl-megolm)
;;;;this file contains all of the conditions used and a hash table of strings
;;;;that are used to associate them

(defparameter *conditions* (make-hash-table :test #'equal))

(define-condition olm-error ()
  ())

(define-condition condition-missing (olm-error)
  ((searched-for
    :accessor searched-for
    :initarg :searched-for))
  (:documentation "Signalled when an attempt was made to signal a condition from 
SEARCHED-FOR but none were found.")
  (:report
   (lambda (obj stream)
     (format stream "Condition searched for was missing. SEARCHED-FOR: ~A.~%~
                     To fix this issue define a new condition suing using ~
                     (def-trivial-condition <SEARCHED-FOR> olm-error), where ~
                     SEARCHED-FOR is a nice lispy version of the string, ie _ become
                     - and it is a symbol not a string" (searched-for obj)))))

(define-condition invalid-message-type (olm-error)
  ((message-type
    :accessor message-type
    :initarg :message-type)))

(defun string->condition (string)
  "takes in a string (STRING) and looks in *conditions* for an associated condition
if one is found then that condition is signalled, if not 'condition-missing is 
signalled."
  (unless (string-equal string "SUCCESS")
    (let ((condition (gethash string *conditions*)))
      (if condition 
          (error condition)
          (error 'condition-missing :searched-for string)))))

(defgeneric check-error (object to-check)
  (:documentation "This generic is used to convert between the error strings and
lisp conditions. Firstly it will check if to-check is equal to (%olm:error) 
if so it calls the most applicable method for class"))

(defmethod check-error :around (object to-check)
  "Checks to make sure that TO-CHECK is actually in an error state before evaluating
call-next-method"
  (when (= to-check (%olm:error))
    (call-next-method)))

(defmacro def-trivial-condition (name supers)
  (let ((string (str:replace-all "-" "_" (string-upcase (format nil "~A" name)))))
    `(prog1 (define-condition ,name ,supers ())
       (setf (gethash ,string *conditions*) ',name))))

;; (define-condition pk-encryption-error (olm-error)
;;   ())

;; (define-condition pk-decryption-error (olm-error)
;;   ())

;; (define-condition pk-signing-error (olm-error)
;;   ())

;; (define-condition group-session-error (olm-error)
;;   ())

;; (define-condition account-error (olm-error)
;;   ())

(def-trivial-condition olm-bad-session-key (olm-error))
(def-trivial-condition not-enough-random (olm-error))
(def-trivial-condition output-buffer-too-small (olm-error))
(def-trivial-condition olm-input-buffer-too-small (olm-error))
(def-trivial-condition bad-account-key (olm-error))
(def-trivial-condition bad-message-key-id (olm-error))
(def-trivial-condition olm-group-session-error (olm-error))
(def-trivial-condition bad-message-version (olm-error))
(def-trivial-condition bad-message-format (olm-error))
(def-trivial-condition bad-message-mac (olm-error))
(def-trivial-condition unknown-message-index (olm-error))
(def-trivial-condition invalid-base64 (olm-error))
(def-trivial-condition olm-invalid-base64 (olm-error))
(def-trivial-condition olm-bad-message-version (olm-error))
(def-trivial-condition olm-bad-message-format (olm-error))
(def-trivial-condition olm-bad-message-mac (olm-error))
(def-trivial-condition olm-unknown-message-index (olm-error))
