(in-package #:cl-megolm)
;;;file contains all defined classes


;;;;I could make a metaclass that makes sure that no method is called
;;;;on a cleaned up instance

(defgeneric cleanup (object)
  (:documentation "Used to free the pointer associated with the object. 
Super important to call this when done using an object that needs it."))

(defclass account ()
  ((account
    :accessor account
    :initarg :account)))

(defmethod %check-error ((account account) to-check)
  (let ((er (%olm:account-last-error (account account))))
    (string->condition er)
    account))

(defmethod cleanup ((account account))
  (cffi:foreign-free (account account)))

(defclass pk-message ()
  ((ephermal
    :accessor ephemeral
    :initarg :ephemeral)
   (mac
    :accessor mac
    :initarg :mac)
   (ciphertext
    :accessor ciphertext
    :initarg :ciphertext)))

(defclass pk-encryption ()
  ((pk-encrypt
    :accessor pk-encrypt
    :initarg :pk-encrypt)))

(defmethod %check-error ((pk-encryption pk-encryption) to-check)
  (let ((er (%olm:pk-encryption-last-error (pk-encrypt pk-encryption))))
    (string->condition er)
    pk-encryption))

(defmethod cleanup ((pk-encryption pk-encryption))
  (cffi:foreign-free (pk-encrypt pk-encryption)))

(defclass pk-decryption ()
  ((pk-decrypt
    :accessor pk-decrypt
    :initarg :pk-decrypt)
   (public-key
    :accessor public-key
    :initarg :public-key)))

(defmethod %check-error ((pk-decryption pk-decryption) to-check)
  (let ((er (%olm:pk-decryption-last-error (pk-decrypt pk-decryption))))
    (string->condition er)
    pk-decryption))

(defmethod cleanup ((pk-decryption pk-decryption))
  (cffi:foreign-free (pk-decrypt pk-decryption)))

(defclass pk-signing ()
  ((pk-sign
    :accessor pk-sign
    :initarg :pk-sign)
   (public-key
    :accessor public-key
    :initarg :public-key)))

(defmethod %check-error ((pk-signing pk-signing) to-check)
  (let ((er (%olm:pk-signing-last-error (pk-sign pk-signing))))
    (string->condition er)
    pk-signing))

(defmethod cleanup ((pk-signing pk-signing))
  (cffi:foreign-free (pk-sign pk-signing)))

(defclass sas ()
  ((sas
    :accessor sas
    :initarg :sas)))

(defmethod %check-error ((sas sas) to-check)
  (let ((er (%olm:sas-last-error (sas sas))))
    (string->condition er)
    sas))

(defclass session ()
  ((session
    :accessor session
    :initarg :session)
   (session-key
    :accessor session-key)))

(defmethod %check-error ((session session) to-check)
  (let ((er (%olm:session-last-error (session session))))
    (string->condition er)
    session))

(defmethod cleanup ((session session))
  (cffi:foreign-free (session session)))

(defclass inbound-session (session)
  ())

(defclass outbound-session (session)
  ())

(defclass inbound-group-session (session)
  ())

(defmethod %check-error ((inbound-group-session inbound-group-session) check-it)
  (let ((er (%olm:inbound-group-session-last-error (session inbound-group-session))))
    (string->condition er)
    inbound-group-session))

(defclass outbound-group-session (session)
  ())

(defmethod %check-error ((outbound-group-session outbound-group-session) check-it)
  (let ((er (%olm:outbound-group-session-last-error
             (session outbound-group-session))))
    (string->condition er)
    outbound-group-session))

(defclass %olm-message ()
  ((ciphertext
    :accessor ciphertext
    :initarg :ciphertext)
   (message-type
    :accessor message-type
    :initarg :message-type)))

(defclass olm-message (%olm-message)
  ((message-type
    :initform %olm:*message-type-message*)))

(defclass olm-message-pre-key (%olm-message)
  ((message-type
    :initform %olm:*message-type-pre-key*)))

(defclass utility ()
  ((utility
    :accessor utility
    :initarg :utility)))

(defmethod %check-error ((utility utility) to-check)
  (let ((er (%olm:utility-last-error (utility utility))))
    (string->condition er)
    utility))

(defmethod cleanup ((utility utility))
  (cffi:foreign-free (utility utility)))
