# cl-megolm
These create usable bindings over the top of the Olm/Megolm library used for encryption on the matrix protocol see [here](https://gitlab.matrix.org/matrix-org/olm/-/tree/master/)

# A few notes

## Memory management

Its important that you run (cleanup <object>) on the instances of the classes

- utility
- inbound-group-session
- outbound-group-session
- session
- sas
- pk-signing
- pk-encryption
- pk-decryption
- account

If you do not run (cleanup ..) on these after you are done with them the memory will not get cleaned up.

## Running the tests

To run the tests for `cl-megolm` run:

(ql:quickload :cl-megolm)
(in-package :cl-megolm)
(asdf:test-system :cl-megolm)

If you find that any of the 71 tests fail, please create an issue and let me know.


# Accounts

## Creating accounts

Instantiate a new account with `(make-account)`.

```lisp
(let ((alice (make-account)))
    (unwind-protect 
       (identity-keys alice)
      (cleanup alice)))
               
(:|ed25519| "nu/bcRm/rSmg1Y16I6RdpjHqGya9dlEVeSlm+RTpjL8" :|curve25519|
 "UCIuApFOW5KD5uQqcXNAALV7gBarVzWZH/XQly6XCQ4")
```
## One Time Keys
Generate one time keys for an account with `(generate-one-time-keys <account> <count>)`.

```lisp
(let ((alice (make-account)))
     (unwind-protect
          (progn 
            (generate-one-time-keys alice 1)
            (one-time-keys alice))
        (cleanup alice)))
(:|curve25519| (:AAAAAQ "9mjvuusuJR3CxPsTApXkkDjmo7uZohcyiF8QZwRDXSY"))
```

Mark them as published with `(mark-keys-as-published <account>)`
```lisp
(let ((alice (make-account)))
   (unwind-protect
      (progn 
        (generate-one-time-keys alice 1)
        (mark-keys-as-published alice)
        (one-time-keys alice))
    (cleanup alice)))
(:|curve25519| NIL)
```
## Pickle accounts
You can pickle accounts with `(pickle <account> <passphrase>)` and unpickle with `(from-pickle :account <passphrase>)` If passphrase is wrong the condition `bad-account-key` is signalled.

# Sessions
Sessions are used to create peer to peer encrypted channels between two accounts.

## Creating Sessions

```lisp
(let* ((alice (make-account))
       (bob (make-account)))
   (unwind-protect
      (progn (generate-one-time-keys bob 1)
             (let ((id-key (curve bob))
                   (one-time (second (second (one-time-keys bob)))))
               (make-outbound-session alice one-time id-key)))
    (progn (cleanup alice)
           (cleanup bob))))
#<OUTBOUND-SESSION {10069C3763}>
```
Its important to remember to run (cleanup ..) on the session you created once you
are done as this frees the foreign pointer and runs the appropriate olm function.

## Encryption and Decryption with Sessions
```lisp
CL-MEGOLM> (let* ((alice (make-account))
                  (bob (make-account)))
             (unwind-protect
                  (progn (generate-one-time-keys bob 1)
                         (let* ((id-key (curve bob))
                                (one-time (second (second (one-time-keys bob))))
                                (session (make-outbound-session
                                          alice one-time id-key))
                                (encrypted (encrypt session "im a message"))
                                (bob-session
                                  (make-inbound-session bob encrypted nil))
                                (decrypted (decrypt bob-session encrypted)))
                           (print (ciphertext encrypted))
                           (print decrypted)
                           (cleanup session);would be better in unwind-protect
                           (cleanup bob-session)))
               (progn (cleanup alice)
                      (cleanup bob))))

"AwogqG666oomJS3QTDzlPOBjrRqBkNa1l3IvekmTrHgHeF4SIG/beUrUuCCYR5OwX5u0QdJpnR8lnQBpfAODx4/fkQB6GiAjSwCQ9FTABplH+1RxPEcYGMrbqPeLMzTvdgYJTedPIiI/Awog2c5GHjNKlFLBh6yAJu5EFAs+Jo75BFZwUkRT68lvN2MQACIQcoDAnBDFfE1C6e8PeyDMIQf7UhYDYS+y" 
"im a message"
```
## Pickling sessions
Pickle session with `(pickle <session> <passphrase>)` unpickle with `(from-pickle :session <pickle> <passphrase>)`

Passphrase can be an empty string like "".

# Group Sessions

Group sessions allow for one-to-many encrypted channels. All participants need to know the group session key in order to participate. Its important to share the key before any messages are encrypted because the key is ratcheted.

## Group session creation

```lisp
CL-MEGOLM> (let* ((alice-g (make-outbound-group-session))
                  (bob-i-g (make-inbound-group-session (session-key alice-g))))
             (cleanup alice-g)
             (cleanup bob-i-g))
NIL
```

## Group encryption and decryption
Its important to note that when decrypt is called with an inbound-group-session
it returns multiple values, the decrypted message and the message index.
```lisp
CL-MEGOLM> (let* ((alice-g (make-outbound-group-session))
                  (bob-i-g (make-inbound-group-session (session-key alice-g))))
             (unwind-protect
                  (let ((encrypt (encrypt alice-g "Im a message")))
                    (print encrypt)
                    (multiple-value-bind (message message-index)
                        (decrypt bob-i-g encrypt)
                      (print message)
                      (print message-index)))
               (progn 
                 (cleanup alice-g)
                 (cleanup bob-i-g))))

"AwgAEhAlVvR9vy7jRlH897toXmVgD9neM5jrkPtBIXJOwOE4R1BOLiuNpsH/zyG7aQ1UBKzXHUFHwiXgHVBjQDHnjAWJ8VzfQUSqOymBH7u+ZVB4qMQqg1XBiGEJ" 
"Im a message" 
0 
```

## Pickling
To pickle group sessions use `(pickle <inbound-group | outbound-group> <passphrase>)` to unpickle
use `(from-pickle <:inbound-group | :outbound-group> <passphrase> )` the keyword will depend on the whether you pickled an inbound group or and outbound group.




# The conditions

All conditions are a subclass of `olm-error`. All the conditions
that will be signalled listed in [src/conditions.lisp](https://github.com/K1D77A/cl-megolm/blob/master/src/conditions.lisp)
If at any point the condition `condition-missing` is signalled, please create an
issue with the stacktrace and I will add the condition.






## License

MIT
