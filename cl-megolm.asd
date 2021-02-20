;;;; cl-megolm.asd

(asdf:defsystem #:cl-megolm
  :defsystem-depends-on ("cffi-grovel")
  :description "A copy of the python functionality provided as bindings for Olm.
See: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/. Big thanks to
Borodust for creating the initial bindings using Claw."
  :author "K1D77A"
  :license  "MIT"
  :version "0.0.1"
  :serial t
  :depends-on (#:ironclad
               #:claw-olm
               #:jonathan
               #:str
               #:alexandria)
  :components ((:module :src
                :components 
                ((:file "package")
                 (:file "olm")
                 (:file "conditions")
                 (:file "classes")
                 (:file "helpers")
                 (:file "utility")
                 (:file "session")
                 (:file "account") 
                 (:file "group-session")
                 (:file "pk")
                 (:file "sas")))))
