(in-package #:cl-megolm)
;;;file contains all defined classes

(defgeneric cleanup (object)
  (:documentation "Used to free the pointer associated with the object. 
Super important to call this when done using an object that needs it."))

(defclass account ()
  ((account
    :accessor account
    :initarg :account)))

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

(defmethod cleanup ((pk-encryption pk-encryption))
  (cffi:foreign-free (pk-encrypt pk-encryption)))

(defclass pk-decryption ()
  ((pk-decrypt
    :accessor pk-decrypt
    :initarg :pk-decrypt)
   (public-key
    :accessor public-key
    :initarg :public-key)))

(defmethod cleanup ((pk-decryption pk-decryption))
  (cffi:foreign-free (pk-decrypt pk-decryption)))

(defclass pk-signing ()
  ((pk-sign
    :accessor pk-sign
    :initarg :pk-sign)
   (public-key
    :accessor public-key
    :initarg :public-key)))

(defmethod cleanup ((pk-signing pk-signing))
  (cffi:foreign-free (pk-sign pk-signing)))

(defclass sas ()
  ((sas
    :accessor sas
    :initarg :sas)))

(defclass session ()
  ((session
    :accessor session
    :initarg :session)
   (session-key
    :accessor session-key)))

(defmethod cleanup ((session session))
  (cffi:foreign-free (session session)))

(defclass inbound-session (session)
  ())

(defclass outbound-session (session)
  ())

(defclass inbound-group-session (session)
  ())

(defclass outbound-group-session (session)
  ())

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

(defmethod cleanup ((utility utility))
  (cffi:foreign-free (utility utility)))
