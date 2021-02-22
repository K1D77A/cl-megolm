;;;; cl-megolm.asd

(asdf:defsystem #:cl-megolm
  :description "A copy of the python functionality provided as bindings for Olm.
See: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/python/. Big thanks to
Borodust for creating the initial bindings using Claw."
  :author "K1D77A"
  :license  "MIT"
  :version "0.0.2"
  ;; :in-order-to ((asdf:test-op (asdf:load-op "cl-megolm/tests")))
  ;; :perform (asdf:test-op (o c)
  ;;                        (uiop:symbol-call "" "" "))
  :serial t
  :depends-on (#:ironclad
               #:claw-olm
               #:jonathan
               #:cffi
               #:str
               #:alexandria)
  :components ((:module :src
                :serial t
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

(asdf:defsystem #:cl-megolm/tests
  :description "Tests for cl-megolm"
  :author "K1D77A"
  :license "MIT"
  :depends-on (#:cl-megolm
               #:lisp-unit)
  :components ((:module "tests"
                :serial t
                :components
                ((:file "package")
                 (:file "tests")
                 (:file "account-test")
                 (:file "group-session-test")
                 (:file "pk-test")
                 (:file "sas-test")
                 (:file "session-test")
                 (:file "util-test")))))

