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

(defun session-user ()
  (session-value 'user))

(defun (setf session-user) (value)
  (setf (session-value 'user) value))

(defun session-user-authenticated-p ()
  (session-value 'user-authenticated-p))

(defun (setf session-user-authenticated-p) (value)
  (setf (session-value 'user-authenticated-p) value))

(defmacro authorized-page ((realm
                            user
                            password
                            &key
                            (login-page-function #'login-page)) &rest body)
  `(if (or (not (realm-use-ssl ,realm))
           (ssl-p))
       (if (or (and ,user ,password
                    (check-password ,realm ,user ,password))
               (session-user-authenticated-p))
           (progn
             (unless (session-user-authenticated-p)
               (setf (session-value 'user) ,user)
               (setf (session-user-authenticated-p) t))
             ,@body)
           (funcall ,login-page-function))
       (progn
         (apply #'redirect (request-uri)
                :protocol :https
                (let ((ssl-port (realm-ssl-port ,realm)))
                  (when ssl-port
                    (multiple-value-bind (host-name)
                        (parse-host-name-and-port (host))
                      `(:host ,host-name :port ,ssl-port))))))))

