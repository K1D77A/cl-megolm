(in-package #:cl-megolm-tests)

(sas-test creation
  (assert-true (pubkey alice))
  (assert-true (pubkey bob)))

(sas-test other-key-setting
  (assert-false (other-key-set-p alice))
  (set-their-public-key alice (pubkey bob))
  (assert-true (other-key-set-p alice)))

(sas-test generating-bytes
  (let ((bob (make-sas (pubkey alice))));;temp override original bob
    (unwind-protect
         (progn 
           (assert-true (other-key-set-p bob))
           (assert-error 'olm-sas-their-key-not-set
                         (generate-bytes alice %extra-info (length %extra-info)))
           (set-their-public-key alice (pubkey bob))
           (assert-error 'simple-error (generate-bytes alice %extra-info 3))
           (let ((ab (generate-bytes alice %extra-info (length %extra-info)))
                 (bb (generate-bytes bob %extra-info (length %extra-info))))
             (assert-true (equalp ab bb))))
      (cleanup bob))))

(sas-test mac-generating
  (assert-error 'olm-sas-their-key-not-set
                (calculate-mac alice %message %extra-info))
  (set-their-public-key alice (pubkey bob))
  (set-their-public-key bob (pubkey alice))
  (let ((am (calculate-mac alice %message %extra-info))
        (bm (calculate-mac bob %message %extra-info)))
    (assert-equal am bm)))

(sas-test cross-language-mac
  (let ((a-private (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-contents
                                  '(#x77 #x07 #x6D #x0A #x73 #x18 #xA5 #x7D
                                    #x3C #x16 #xC1 #x72 #x51 #xB2 #x66 #x45
                                    #xDF #x4C #x2F #x87 #xEB #xC0 #x99 #x2A
                                    #xB1 #x77 #xFB #xA5 #x1D #xB9 #x2C #x2A)))
        (bob-key "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08")
        (message "Hello world!")
        (extra-info "MAC")
        (expected-mac "2nSMTXM+TStTU3RUVTNSVVZUTlNWVlpVVGxOV1ZscFY")
        (a (make-sas)))
    (unwind-protect (progn
                      (create-sas a a-private 32);;changes a
                      (set-their-public-key a bob-key)
                      (let ((mac (calculate-mac a message extra-info)))
                        (assert-true (string= mac expected-mac))))
      (cleanup a))))

(sas-test long-mac-generating
  (assert-error 'olm-sas-their-key-not-set
                (calculate-mac alice %message %extra-info))
  (set-their-public-key alice (pubkey bob))
  (set-their-public-key bob (pubkey alice))
  (let ((am (calculate-mac-long-kdf alice %message %extra-info))
        (bm (calculate-mac-long-kdf bob %message %extra-info))
        (bsm (calculate-mac bob %message %extra-info)))
    (assert-equal am bm)
    (assert-true (string/= am bsm))))

