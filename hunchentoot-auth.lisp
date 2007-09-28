;;; file: hunchentoot-auth.lisp
;;;
;;; Copyright (c) 2007 Cyrus Harmon (ch-lisp@bobobeach.com)
;;; All rights reserved.
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

(in-package #:hunchentoot-auth)

(defmacro with-html-page (&body body)
  "Executes BODY inside a cl-who:with-html-output-to-string body,
directing the output to *standard-output* and setting :prologue to t."
  `(with-html-output-to-string (*standard-output* nil :prologue t)
     ,@body))

(defmacro with-html (&body body)
  "Executes BODY inside a cl-who:with-html-output body."
  `(with-html-output (*standard-output*)
     ,@body))

(defun generate-html-login (&key user password)
  (with-html
    (:form :method :post
           "Name: "
           (if user
               (htm (:input :type :text :name "user" :value user))
               (htm (:input :type :text :name "user")))
           (:br)
           "Password: "
           (if password
               (htm (:input :type :password :name "password" :value password))
               (htm (:input :type :password :name "password")))
           (:br)
           (:input :type :submit :value "Submit"))))

(defun login-page (&key
                   (title "Login"))
  (with-html-page
    (:html
     (:head (:title (str title)))
     (:body
      (generate-html-login)))))

(defun parse-host-name-and-port (host-and-port)
  (let ((strings
         (nth-value 1
                    (cl-ppcre:scan-to-strings "^([^:]*)(:([^:]*))?$"
                                              host-and-port))))
    (values (elt strings 0)
            (elt strings 2))))

(defun session-realm-user (realm)
  (let ((hash (session-value 'realm-user-hash)))
    (when hash
      (gethash realm hash))))

(defun (setf session-realm-user) (value realm)
  (let ((hash (session-value 'realm-user-hash)))
    (unless hash
      (setf hash
            (setf (session-value 'realm-user-hash)
                  (make-hash-table))))
    (setf (gethash realm hash) value)))

(defun session-realm-user-authenticated-p (realm)
  (let ((hash (session-value 'realm-user-authenticated-hash)))
    (when hash
      (gethash realm hash))))

(defun (setf session-realm-user-authenticated-p) (value realm)
  (let ((hash (session-value 'realm-user-authenticated-hash)))
    (unless hash
      (setf hash
            (setf (session-value 'realm-user-authenticated-hash)
                  (make-hash-table))))
    (setf (gethash realm hash) value)))

(defmacro with-unique-names ((&rest bindings) &body body)
  "Syntax: WITH-UNIQUE-NAMES ( { var | (var x) }* ) declaration* form*

Executes a series of forms with each VAR bound to a fresh,
uninterned symbol. The uninterned symbol is as if returned by a call
to GENSYM with the string denoted by X - or, if X is not supplied, the
string denoted by VAR - as argument.

The variable bindings created are lexical unless special declarations
are specified. The scopes of the name bindings and declarations do not
include the Xs.

The forms are evaluated in order, and the values of all but the last
are discarded \(that is, the body is an implicit PROGN)."
  ;; reference implementation posted to comp.lang.lisp as
  ;; <cy3bshuf30f.fsf@ljosa.com> by Vebjorn Ljosa - see also
  ;; <http://www.cliki.net/Common%20Lisp%20Utilities>
  `(let ,(mapcar #'(lambda (binding)
                     (check-type binding (or cons symbol))
                     (if (consp binding)
                       (destructuring-bind (var x) binding
                         (check-type var symbol)
                         `(,var (gensym ,(etypecase x
                                          (symbol (symbol-name x))
                                          (character (string x))
                                          (string x)))))
                       `(,binding (gensym ,(symbol-name binding)))))
                 bindings)
         ,@body))

(defmacro with-rebinding (bindings &body body)
  "Syntax: WITH-REBINDING ( { var | (var prefix) }* ) form*

Evaluates a series of forms in the lexical environment that is
formed by adding the binding of each VAR to a fresh, uninterned
symbol, and the binding of that fresh, uninterned symbol to VAR's
original value, i.e., its value in the current lexical environment.

The uninterned symbol is created as if by a call to GENSYM with the
string denoted by PREFIX - or, if PREFIX is not supplied, the string
denoted by VAR - as argument.

The forms are evaluated in order, and the values of all but the last
are discarded \(that is, the body is an implicit PROGN)."
  ;; reference implementation posted to comp.lang.lisp as
  ;; <cy3wv0fya0p.fsf@ljosa.com> by Vebjorn Ljosa - see also
  ;; <http://www.cliki.net/Common%20Lisp%20Utilities>
  (loop for binding in bindings
        for var = (if (consp binding) (car binding) binding)
        for name = (gensym)
        collect `(,name ,var) into renames
        collect ``(,,var ,,name) into temps
        finally (return `(let ,renames
                          (with-unique-names ,bindings
                            `(let (,,@temps)
                              ,,@body))))))

(defmacro authorized-page ((realm
                            user
                            password
                            &key
                            (use-ssl t)
                            ssl-port
                            (login-page-function #'login-page)) &rest body)
  (with-rebinding (realm user password ssl-port)
    `(if (or (not ,use-ssl)
             (ssl-p))
         (if (or (and ,user ,password
                      (check-password ,realm ,user ,password))
                 (session-realm-user-authenticated-p ,realm))
             (progn
               (unless (session-realm-user-authenticated-p ,realm)
                 (setf (session-realm-user ,realm) ,user)
                 (setf (session-realm-user-authenticated-p ,realm) t))
               ,@body)
             (funcall ,login-page-function))
         (progn
           (apply #'redirect (request-uri)
                  :protocol :https
                  (when ,ssl-port
                    (multiple-value-bind (host-name)
                        (parse-host-name-and-port (host))
                      `(:host ,host-name :port ,,ssl-port))))))))

