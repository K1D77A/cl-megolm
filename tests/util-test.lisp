(in-package #:cl-megolm-tests)

(defun clad-sha256 (input)
  (with-output-to-string (i)
    (s-base64:encode-base64-bytes 
     (ironclad:digest-sequence 
      :sha256
      (to-bytes input)) i)))

(define-test sha256-test
  (:tag :util)
  (let* ((input1 "Its a secret to everyone")
         (input2 "Its a secret to no one")
         (first-hash (sha256 input1))
         (second-hash (sha256 input2))
         (iron-hash (clad-sha256 input1)))
    (assert-true (string= (subseq iron-hash 0 (1- (length iron-hash)));;remove padd
                          first-hash))
    (assert-false (string= first-hash second-hash))))
