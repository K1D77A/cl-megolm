(in-package #:cl-megolm)

(defmethod check-error ((session session) to-check)
  (let ((er (%olm:session-last-error (session session))))
    (string->condition er)
    session))

(defmethod print-object ((obj olm-message) stream)
  (print-unreadable-object (obj stream)
    (format stream "~A ~A"
            (case (message-type obj)
              (#.%olm:*message-type-pre-key* "PRE-KEY")
              (#.%olm:*message-type-message* "MESSAGE"))
            (ciphertext obj))))

(defun %make-olm-message (ciphertext message-type)
  (cond ((= message-type %olm:*message-type-message*)
         (make-instance 'olm-message :ciphertext ciphertext
                                     :message-type message-type))
        ((= message-type %olm:*message-type-pre-key*)
         (make-instance 'olm-message-pre-key :ciphertext ciphertext
                                             :message-type message-type))
        (t (error 'invalid-message-type :message-type message-type))))

(defun make-olm-pre-key-message (ciphertext)
  "Create a make Olm prekey message with the supplied ciphertext"
  (%make-olm-message ciphertext %olm:*message-type-pre-key*))

(defun make-olm-message (ciphertext)
  "Create a new Olm message with the supplied ciphertext"
  (%make-olm-message ciphertext %olm:*message-type-message*))

(defmethod clear-session ((session session))
  (%olm:clear-session (session session)))

(defun make-session ()
  (let* ((buf (cffi:foreign-string-alloc (%olm:session-size)))
         (session (%olm:session buf)))
    (make-instance 'session :session session)))

(defmethod pickle ((session session) (passphrase string))
  "Store an Olm session.

        Stores a session as a base64 string. Encrypts the session using the
        supplied passphrase. Returns a byte object containing the base64
        encoded string of the pickled session."
  (let* ((p-length (%olm:pickle-session-length (session session))))
    (cffi:with-foreign-string ((foreign-key foreign-key-length) passphrase)
      (clean-after ((foreign-key foreign-key-length))
        (cffi:with-foreign-pointer-as-string (p-buffer p-length)
          (check-error session
                       (%olm:pickle-session (session session)
                                            foreign-key
                                            foreign-key-length
                                            p-buffer
                                            p-length)))))

    session))

(defmethod from-pickle ((type (eql :session)) (pickle string) (passphrase string))
  "Load a previously stored Olm session.

        Loads a session from a pickled base64 string and returns a Session
        object. Decrypts the session using the supplied passphrase. Raises
        OlmSessionError on failure. If the passphrase doesn't match the one
        used to encrypt the session then the error message for the
        exception will be 'bad-account-key. If the base64 couldn't be decoded
        then the error message will be 'invalid-base64.
"
  (let ((ret nil))
    (cffi:with-foreign-strings (((byte-key byte-key-len) passphrase)
                                (pickle-buffer pickle))
      (clean-after ((byte-key byte-key-len))
        (let* ((session (make-session))
               (res (%olm:unpickle-session (session session)
                                           byte-key byte-key-len
                                           pickle-buffer (length pickle))))
          (setf ret session)
          (check-error session res))))
    ret))

(defmethod encrypt ((session session) (plaintext string))
  "Encrypts a message using the session. Returns the ciphertext as a
        base64 encoded string on success."
  (let ((res nil)
        (message-type nil))
    (cffi:with-foreign-string ((plain-buf plain-length) plaintext)
      (clean-after ((plain-buf plain-length))
        (let ((ran-len (%olm:encrypt-random-length (session session))))
          (setf message-type (%olm:encrypt-message-type (session session)))
          (check-error session message-type)
          (cffi:with-foreign-strings (((cipher-buf cipher-buf-len)
                                       (%olm:encrypt-message-length
                                        (session session) plain-length))
                                      (random-buf ran-len))
            (check-error session (%olm:encrypt (session session)
                                               plain-buf plain-length
                                               random-buf ran-len
                                               cipher-buf cipher-buf-len))
            (setf res (cffi:foreign-string-to-lisp cipher-buf))))))
    (%make-olm-message res message-type)))

(defmethod decrypt ((session session) (message %olm-message))
  "Decrypts a message using the session. Returns the plaintext string
on success. Raises OlmSessionError on failure. If the base64 couldn't
be decoded then the error message will be 'invalid-base64. If the message is for an unsupported version of the protocol the condition signalled
will be 'bad-message-version. if the message couldn't be decoded then
the condition signalled will be 'bad-message-format. if the mac on the
message was invalid then the condition will be 'bad-message-mac
"
  (let ((res nil))
    (cffi:with-foreign-strings (((cipher-buf cipher-buf-len)
                                 (ciphertext message))
                                ((cipher-buf2 cipher-buf-len2);;copied
                                 (ciphertext message)))
      (let ((max-pt-len (%olm:decrypt-max-plaintext-length
                         (session session) (message-type message)
                         cipher-buf cipher-buf-len)))
        (check-error session max-pt-len)
        (cffi:with-foreign-string (plain-buf (make-string max-pt-len))
          (clean-after ((plain-buf max-pt-len))
            (check-error session
                         (%olm:decrypt (session session)
                                       (message-type message)
                                       cipher-buf2 cipher-buf-len2
                                       plain-buf max-pt-len))
            (setf res (cffi:foreign-string-to-lisp plain-buf))))))
    res))

(defmethod id ((session session))
  "An identifier for this session. Will be the same for both
        ends of the conversation."
  (cffi:with-foreign-pointer-as-string ((id-buf id-buf-len)
                                        (%olm:session-id-length (session session)))
    (check-error session (%olm:session-id (session session) id-buf id-buf-len))))

(defmethod matchesp ((session session) (message olm-message-pre-key)
                     (id-key string))
  "Checks if the PRE_KEY message is for this in-bound session.
This can happen if multiple messages are sent to this session before
this session sends a message in reply. Returns True if the session
matches. returns false if the session does not match. raises
olmsessionerror on failure. if the base64 couldn't be decoded then the
condition signalled will be 'invalid-base64. if the message was for an
unsupported protocol version then the condition signalled will be
'bad-message-version. if the message couldn't be decoded then then the
condition signalled will be * 'bad-message-format."
  (cffi:with-foreign-strings (((id-key-buf id-key-buf-len) id-key)
                              ((message-buf message-buf-len) (ciphertext message)))
    (let ((res (%olm:matches-inbound-session-from (session session)
                                                  id-key-buf id-key-buf-len
                                                  message-buf message-buf-len)))
      (check-error session res)
      (to-bool res))))

(defmethod matchesp ((session session) (message olm-message-pre-key) (id-key null))
  ""
  (cffi:with-foreign-string ((message-buf message-buf-len) (ciphertext message))
    (let ((res (%olm:matches-inbound-session (session session)
                                             message-buf message-buf-len)))
      (check-error session res)
      (to-bool res))))




(defmethod make-inbound-session ((account account) (message %olm-message)
                                 (id-key string))
  "Create a new inbound Olm session.

        create a new in-bound session for sending/receiving messages from an
        incoming prekey message. raises olmsessionerror on failure. if the
        base64 couldn't be decoded then condition signalled will be invalid-base64.
        if the message was for an unsupported protocol version then
        the errror message will be bad-message-version. if the message
        couldn't be decoded then then the condition signalled will be
        bad-message-format. if the message refers to an unknown one-time
        key then the condition signalled will be bad-message-key-id.
"
  (cffi:with-foreign-strings (((id-key-buf id-key-buf-len) id-key)
                              ((message-buf message-buf-len) (ciphertext message)))
    (let ((inbound-session (make-instance 'inbound-session
                                          :session (session (make-session)))))
      (check-error inbound-session
                   (%olm:create-inbound-session-from (session inbound-session)
                                                     (account account)
                                                     id-key-buf id-key-buf-len
                                                     message-buf message-buf-len))
      inbound-session)))

(defmethod make-inbound-session ((account account) (message %olm-message)
                                 (id-key string))
  ""
  (cffi:with-foreign-string ((message-buf message-buf-len) (ciphertext message))
    (let ((inbound-session (make-instance 'inbound-session
                                          :session (session (make-session)))))
      (check-error inbound-session
                   (%olm:create-inbound-session (session inbound-session)
                                                (account account)
                                                message-buf message-buf-len))
      inbound-session)))

(defmethod make-outbound-session ((account account)(one-time-key string)
                                  (id-key string))
  (let ((outbound-session (make-instance 'outbound-session
                                         :session (session (make-session)))))
    (cffi:with-foreign-strings  (((id-key-buf id-key-buf-len) id-key)
                                 ((otk-buf otk-buf-len) one-time-key)
                                 ((random-buf random-buf-len)
                                  (%olm:create-outbound-session-random-length
                                   (session outbound-session))))
      (check-error outbound-session
                   (%olm:create-outbound-session (session outbound-session)
                                                 (account account)
                                                 id-key-buf id-key-buf-len
                                                 otk-buf otk-buf-len
                                                 random-buf random-buf-len))
      outbound-session)))

