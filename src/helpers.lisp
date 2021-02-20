(in-package #:cl-megolm)

(defmacro clean-after (list-of-vars &body body)
  "Wraps body in an unwind-protect and then takes a list of lists, each list whose car is a pointer to foreign string and the second the length, then 0s the foreign string."
  (let ((code
          (mapcar (lambda (pointer-list)
                    `(let ((len ,(second  pointer-list))
                           (pointer ,(car  pointer-list)))
                       (loop :for i :from 0 :below len
                             :do (setf (cffi:mem-aref pointer :uint8 i) 0))))
                  list-of-vars)))
    `(unwind-protect
          (locally ,@body)
       (progn ,@code))))

(defmacro with-foreign-strings-as-lisp (bindings &body body)
  "This is just a normal 'cffi:with-foreign-strings' however each of the buffer
names you assign ie (mapcar #'first bindings) has (cffi:foreign-string-to-lisp ..)
called on it and the value assigned to a variable and returned as multiple return 
values, so you have to wrap this in a multiple-value-bind. The values are returned
in the same order as the bindings so for example if bindings were the following:
((cipher-text (make-string cipher-len))
(mac (make-string mac-len))
(eph (make-string eph-key-size))) 
 then the final values are returned as cipher-text mac eph."
  (let* ((vars (mapcar (lambda (bind)
                         (list (first bind) (gensym))) bindings)))
    `(let (,@(mapcar (lambda (bind)
                       (list (second bind) nil))
                     vars))
       (cffi:with-foreign-strings ,bindings
         (progn (locally ,@body)
                ,@(mapcar (lambda (bind)
                            `(setf ,(second bind)
                                   (cffi:foreign-string-to-lisp ,(first bind))))
                          vars)))
       (values ,@(mapcar #'second vars)))))

(defun random-string (len)
  (let ((bytes (ironclad:random-data len))
        (str (make-string len)))
    (loop :for i :from 0 :below len
          :do (setf (aref str i) (code-char (aref bytes i))))
    str))

(defmacro %pickle (object object-type accessor password)
  "An example of how common calls like 'pickle' could be written"
  (let* ((type-string object-type)
         (accessor (intern (string-upcase accessor) :cl-megolm))
         (len-fun (intern (string-upcase
                           (format nil "pickle-~A-length" type-string)) :%olm))
         (pickle-fun (intern (string-upcase
                              (format nil "pickle-~A" type-string)) :%olm)))
    (alexandria:with-gensyms (p-length
                              foreign-key
                              foreign-key-length
                              p-buffer)
      `(let ((,p-length (funcall ',len-fun (funcall ',accessor ,object))))
         (cffi:with-foreign-string ((,foreign-key ,foreign-key-length) ,password)
           (clean-after ((,foreign-key ,foreign-key-length))
                        (cffi:with-foreign-pointer-as-string (,p-buffer ,p-length)
                          (funcall ',pickle-fun (funcall ',accessor ,object)
                                   ,foreign-key ,foreign-key-length
                                   ,p-buffer ,p-length))))))))

(defun to-bool (n)
  (cond ((= n 0)
         nil)
        ((= n 1)
         t)
        (t (error "n is neither 0 or 1"))))
