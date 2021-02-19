;;;; cl-megolm-tests.asd

(asdf:defsystem #:cl-megolm-tests
  :description "Test system for cl-megolm"
  :author "Your Name <your.name@example.com>"
  :license  "Specify license here"
  :version "0.0.1"
  :serial t
  :depends-on (#:cl-megolm
               #:lisp-unit)
  :pathname "tests"
  :components ((:file "package")
               (:file "cl-megolm-tests")))
