;;;; cl-megolm.lisp

(in-package #:cl-megolm)

(cffi:define-foreign-library libolm
  (:unix (:or "/usr/local/lib/libolm.so"
              "/usr/local/lib/libolm.so.3"
              "/usr/local/lib/libolm.so.3.2.1"))
  (t (:default "libolm")))

(cffi:use-foreign-library libolm)
