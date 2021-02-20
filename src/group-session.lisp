(in-package #:cl-megolm)

;;;;copy of ;;;https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/olm/group_session.py


(defmethod check-error ((inbound-group-session inbound-group-session) check-it)
  (let ((er (%olm:inbound-group-session-last-error (session inbound-group-session))))
    (string->condition er)
    inbound-group-session))

(defmethod check-error ((outbound-group-session outbound-group-session) check-it)
  (let ((er (%olm:outbound-group-session-last-error
             (session outbound-group-session))))
    (string->condition er)
    outbound-group-session))

(defun gen-inbound-group-session ()
  (let* ((size (%olm:inbound-group-session-size)))
    (cffi:with-foreign-string (buf (make-string size))
      (%olm:inbound-group-session buf))))

(defun new-inbound-group-session (session-key)
  "Create a new inbound group session.
Start a new inbound group session, from a key exported from
  an outbound group session. Signals 'olm-invalid-base64 if the session 
key is not valid base64 or 'olm-bad_session_key if the session key is
 invalid."
  (let ((session (gen-inbound-group-session))
        (ret nil))
    (cffi:with-foreign-string ((foreign-key foreign-key-length) session-key)
      (clean-after ((foreign-key foreign-key-length))
        (setf ret (%olm:init-inbound-group-session session foreign-key
                                                   foreign-key-length))))
    (let ((new-session (make-instance 'inbound-group-session :session session)))
      (check-error new-session ret))))

(defmethod pickle ((session inbound-group-session) (passphrase string))
  "Store an inbound group session.

        Stores a group session as a base64 string. Encrypts the session using
        the supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled session."
  (let* ((p-length (%olm:pickle-inbound-group-session-length (session session))))
    (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
      (clean-after ((foreign-key foreign-key-length))
        (cffi:with-foreign-pointer-as-string (p-buffer p-length)
          (check-error session
                       (%olm:pickle-inbound-group-session (session session)
                                                          foreign-key
                                                          foreign-key-length
                                                          p-buffer
                                                          p-length)))))

    session))

;; (defmethod from-pickle ((pickle string) (passphrase string))
;;   "Load a previously stored inbound group session.
;;  Loads an inbound group session from a pickled base64 string and returns
;; an inbound-group-session object. Decrypts the session using the supplied
;; passphrase. If the passphrase doesn't match the one used to encrypt
;;  the session then signals 'olm-inbound-bad-account-key. If the base64
;;  couldn't be decoded then signals 'olm-inbound-invalid-base-64.

;; "
;;   (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
;;     (cffi:with-foreign-string ((pickle-str pickle-len) pickle)
;;       (clean-after ((foreign-key foreign-key-length))
;;         (%olm:unpickle-inbound (setf  (new-account)) foreign-key
;;                                foreign-key-length
;;                                pickle-str pickle-len)))
;;     (check-error acc))))))

(defmethod decrypt ((session inbound-group-session) (cipher-text string))
  "Decrypt a message

        Returns a tuple of the decrypted plain-text and the message index of
        the decrypted message or signals various conditions on failure.
        On failure the potential conditions are:

        olm-invalid-base64 if the message is not valid base64
        olm-bad-message-version if the message was encrypted with an
            unsupported version of the protocol
        olm-bad-message-format if the message headers could not be
            decoded
        olm-bad-message-mac  if the message could not be verified
        olm-unknown-message-index if we do not have a session key
            corresponding to the message's index (i.e., it was sent before
            the session key was shared with us)"
  (let ((max-pt nil)
        (res nil))
    (cffi:with-foreign-string ((ct-buf ct-length) cipher-text)
      (setf max-pt (%olm:group-decrypt-max-plaintext-length (session session)
                                                            ct-buf ct-length))
      (check-error session max-pt))
    (cffi:with-foreign-pointer-as-string (pt-buf max-pt)
      (clean-after ((pt-buf max-pt))
        (cffi:with-foreign-string ((ct-buf ct-b-len) cipher-text)
          (let ((uint (cffi:foreign-alloc :uint32)))
            (check-error session
                         (%olm:group-decrypt (session session) ct-buf
                                             ct-b-len pt-buf max-pt uint))
            (setf res (list (cffi:foreign-string-to-lisp pt-buf) uint))))))
    (values (car res) (second res))))

(defmethod id ((session inbound-group-session))
  "A base64 encoded identifier for this session."
  (let ((id-len (%olm:inbound-group-session-id-length (session session)))
        (res nil))
    (cffi:with-foreign-pointer-as-string (id-buffer id-len)
      (clean-after ((id-buffer id-len))
        (check-error session
                     (%olm:inbound-group-session-id (session session)
                                                    id-buffer id-len))
        (setf res (cffi:foreign-string-to-lisp id-buffer))))
    res))

(defmethod first-known-index ((session inbound-group-session))
  "The first message index we know how to decrypt"
  (%olm:inbound-group-session-first-known-index (session session)))

(defmethod export-session ((session inbound-group-session) message-index)
  "Export an inbound group session

        Export the base64-encoded ratchet key for this session, at the given
        index, in a format which can be used by import_session().

        Signals olm-unknown-message-index if we do not have a session key
            corresponding to the given index (ie, it was sent before the
            session key was shared with us)
"
  (let ((export-len (%olm:export-inbound-group-session-length (session session)))
        (res nil))
    (cffi:with-foreign-pointer-as-string (export-buffer export-len)
      (clean-after ((export-buffer export-len))
        (check-error session
                     (%olm:export-inbound-group-session (session session)
                                                        export-buffer export-len
                                                        message-index))
        (setf res (cffi:foreign-string-to-lisp export-buffer))))
    res))

(defmethod import-session ((type (eql :inbound)) session-key)
  "Create an InboundGroupSession from an exported session key.
Creates an InboundGroupSession with an previously exported session key.
Signals 'olm-invalid-base-64 if the session_key is not valid base64 or
 'olm-bad-session-key if the session_key is invalid"
  (let ((session (gen-inbound-group-session))
        (ret nil))
    (cffi:with-foreign-string ((bk-buf bk-buf-len) session-key)
      (clean-after ((bk-buf bk-buf-len))
        (setf ret (%olm:import-inbound-group-session session bk-buf bk-buf-len))
        (setf session (make-instance 'inbound-group-session :session session))
        (check-error session ret)))
    session))



;;;outbound
(defun gen-outbound-group-session ()
  (let* ((size (%olm:outbound-group-session-size)))
    (cffi:with-foreign-string (buf (make-string size))
      (%olm:outbound-group-session buf))))

(defun new-outbound-group-session ()
  "Create a new outbound group session.
  Start a new outbound group session. Raises OlmGroupSessionError on
  failure."
  (let* ((session (gen-outbound-group-session))
         (len (%olm:init-outbound-group-session-random-length session))
         (ret nil))
    (cffi:with-foreign-string (buffer (make-string len))
      (setf ret (%olm:init-outbound-group-session session buffer len))
      (let ((new-session (make-instance 'outbound-group-session :session session)))
        (check-error new-session ret)))))

(defmethod pickle ((session outbound-group-session) (passphrase string))
  "Store an outbound group session.
Stores a group session as a base64 string. Encrypts the session using
the supplied passphrase. Returns a byte object containing the base64
encoded string of the pickled session."
  (let* ((p-length (%olm:pickle-outbound-group-session-length (session session))))
    (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
      (clean-after ((foreign-key foreign-key-length))
        (cffi:with-foreign-pointer-as-string (p-buffer p-length)
          (check-error session
                       (%olm:pickle-outbound-group-session (session session)
                                                           foreign-key
                                                           foreign-key-length
                                                           p-buffer
                                                           p-length)))))
    
    session))
;;;need to implement, none of unpicklin have worked yet
;; (defmethod from-pickle ((pickle string) (passphrase string))
;;   "Load a previously stored inbound group session.
;;  Loads an inbound group session from a pickled base64 string and returns
;; an InboundGroupSession object. Decrypts the session using the supplied
;; passphrase. If the passphrase doesn't match the one used to encrypt
;;  the session then signals 'olm-inbound-bad-account-key. If the base64
;;  couldn't be decoded then signals 'olm-inbound-invalid-base-64.

;; "
;;   (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
;;     (cffi:with-foreign-string ((pickle-str pickle-len) pickle)
;;       (clean-after ((foreign-key foreign-key-length))
;;         (%olm:unpickle-inbound (setf  (new-account)) foreign-key
;;                                foreign-key-length
;;                                pickle-str pickle-len)))
;;     (check-error acc))))))

(defmethod encrypt ((session outbound-group-session) (plaintext string))
  "Encrypt a message. Returns the encrypted ciphertext."
  (let ((max-pt nil)
        (res nil))
    (cffi:with-foreign-string ((pt-buf pt-length) plaintext)
      (setf max-pt (%olm:group-encrypt-message-length
                    (session session) pt-length))
      (cffi:with-foreign-string (message-buffer (make-string max-pt))
        (clean-after ((pt-buf pt-length))
          (check-error session
                       (%olm:group-encrypt (session session) pt-buf
                                           pt-length message-buffer max-pt))
          (setf res (cffi:foreign-string-to-lisp message-buffer)))))
    res))

(defmethod id ((session outbound-group-session))
  "A base64 encoded identifier for this session."
  (let ((id-len (%olm:outbound-group-session-id-length (session session)))
        (res nil))
    (cffi:with-foreign-pointer-as-string (id-buffer id-len)
      (clean-after ((id-buffer id-len))
        (check-error session
                     (%olm:outbound-group-session-id (session session)
                                                     id-buffer id-len))
        (setf res (cffi:foreign-string-to-lisp id-buffer))))
    res))

(defmethod message-index ((session outbound-group-session))
  "The current message index of the session.
Each message is encrypted with an increasing index. This is the index
for the next message."
  (%olm:outbound-group-session-message-index (session session)))

(defmethod session-key ((session outbound-group-session))
  "The base64-encoded current ratchet key for this session.
Each message is encrypted with a different ratchet key. This function
returns the ratchet key that will be used for the next message."
  (let ((res nil)
        (len (%olm:outbound-group-session-key-length (session session))))
    (cffi:with-foreign-pointer-as-string (buf len)
      (check-error session
                   (%olm:outbound-group-session-key (session session) buf len))
      (setf res (cffi:foreign-string-to-lisp buf)))
    res))
