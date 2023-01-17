;;;; cl-megolm.lisp

(in-package #:cl-megolm)

(cffi:define-foreign-library libolm
  (:unix (:or "libolm.so"
              "libolm.so.3"
              "libolm.so.3.2.4"
              "libolm.so.3.2.14")
   :search-path "/usr/local/lib64/")
  (t (:default "libolm")))

(cffi:use-foreign-library libolm)
