;;; file: hunchentoot-auth.lisp
;;;
;;; Copyright (c) 2007 Cyrus Harmon (ch-lisp@bobobeach.com)
;;; All rights reserved.
;;;
;;; This file contains code that is a derivative of work that is:
;;; Copyright (c) 2004-2007, Dr. Edmund Weitz.  All rights reserved.
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

(defparameter *password-file-lock* (make-lock "password-file-lock"))
(defparameter *password-lock* (make-lock "password-lock"))

;;;
;;; defclass realm
;;;
(defclass realm ()
  ((passwords :accessor realm-passwords
              :initform (make-hash-table :test 'equal)
              :documentation "A hash-table for the users and passwords
for this realm. The keys are the user names and the values the md5
hashed password for the user.")
   (password-storage-path :initarg :password-storage-path
                          :accessor realm-password-storage-path
                          :initform nil
                          :documentation "The path to the file to
store the password hash-table in."))
  (:documentation "Objects of this class represent realms for which a
  given user/password scheme should apply."))

(defun read-realm-passwords (realm &key (path (realm-password-storage-path realm)))
  (when (probe-file path)
    (with-lock (*password-file-lock*)
      (setf (realm-passwords realm)
            (cl-store:restore path)))))

(defun store-realm-passwords (realm &key (path (realm-password-storage-path realm)))
  (ensure-directories-exist path)
  (with-lock (*password-file-lock*)
    (cl-store:store (realm-passwords realm) path)))

(defmethod get-password-hash ((realm realm) user)
  (with-lock (*password-lock*)
    (gethash user (realm-passwords realm))))

(defmethod set-password ((realm realm) user password)
  (with-lock (*password-lock*)
    (setf (gethash user (realm-passwords realm))
          (md5:md5sum-sequence (coerce password 'simple-string)))
    (store-realm-passwords realm)))

(defmethod add-user ((realm realm) user password)
  (set-password realm user password))

(defmethod check-password ((realm realm) user password)
  (and password
       (equalp (get-password-hash realm user)
               (md5:md5sum-sequence (coerce password 'simple-string)))))

(defmacro with-html (&body body)
  "Executes BODY inside a cl-who:with-html-output body."
  `(with-html-output (*standard-output*)
     ,@body))

(defun generate-html-login (user password)
  (with-html
    "Please login:"
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