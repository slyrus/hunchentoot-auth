;;; file: realm.lisp
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

(defclass user ()
  ((name :accessor user-name :initarg :name)
   (password :accessor user-password :initarg :password :initform "")
   (password-salt :accessor user-password-salt :initarg :password-salt)))

(defclass group ()
  ((name :accessor group-name :initarg :name)
   (users :accessor group-users :initform (make-hash-table))))

;;; Realm class definition
(defclass realm ()
  ((users :accessor realm-users
              :initform (make-hash-table :test #'equal)
              :documentation "A hash-table for the users and passwords
for this realm. The keys are the user names (strings) and the values are
instances of the class user.")
   (user-storage-path :initarg :user-storage-path
                          :accessor realm-user-storage-path
                          :initform nil
                          :documentation "The path to the file in
which to store the password hash-table.")
   (groups :accessor realm-groups
           :initform (make-hash-table :test #'equal)
           :documentation "A hash-table for the groups for this
realm. The keys are the group names (strings) and the values instances
of the class group")
   (group-storage-path :initarg :group-storage-path
                       :accessor realm-group-storage-path
                       :initform nil
                       :documentation "The path to the file in
which to store the group hash-table."))
  (:documentation "Objects of this class represent realms for which a
  given user/password scheme should apply."))

;;; users and passwords
(defgeneric read-realm-users (realm)
  (:documentation "Read the users for this realm from the password
  file."))

(defgeneric store-realm-users (realm)
  (:documentation "Store the users for this realm in the password
  file."))

(defgeneric set-password (realm user password)
  (:documentation "Sets the password for the specified user in this
  realm."))

(defgeneric add-user (realm user password)
  (:documentation "Adds a new user with the specified password in this
  realm."))

(defgeneric delete-user (realm user)
  (:documentation "Removes the user with the specified name from this realm."))

(defgeneric check-password (realm user password)
  (:documentation "Returns T if the given user/password combination is
  valid in this realm, otherwise returns NIL."))

;;; groups
(defgeneric read-realm-groups (realm)
  (:documentation "Read the groups for this realm from the group
  file."))

(defgeneric store-realm-groups (realm)
  (:documentation "Store the groups for this realm in the group
  file."))

(defgeneric add-group (realm group)
  (:documentation "Adds a new group named group with the specified 
  realm."))

(defparameter *password-file-lock* (make-lock "password-file-lock"))
(defparameter *password-lock* (make-lock "password-lock"))

(defmethod read-realm-users ((realm realm))
  (let ((path (realm-user-storage-path realm)))
    (when (probe-file path)
      (with-lock (*password-file-lock*)
        (setf (realm-users realm)
              (cl-store:restore path))))))

(defmethod store-realm-users ((realm realm))
  (let ((path (realm-user-storage-path realm)))
    (ensure-directories-exist path)
    (with-lock (*password-file-lock*)
      (cl-store:store (realm-users realm) path))))

(defmethod set-password ((realm realm) (user user) password)
  (with-lock (*password-lock*)
    (setf (user-password user)
          (md5:md5sum-sequence
           (concatenate 'simple-string (user-password-salt user) password)))
    (store-realm-users realm)))

(defun random-string (length)
  "Return a random string of the characters [a-zA-Z] of the specified
length."
  (coerce
   (loop for i below length
      collect
      (code-char
       (+ (if (zerop (random 2))
              (char-code #\a)
              (char-code #\A))
          (random 26))))
   'simple-string))

(defun get-realm-user (realm name)
  (gethash name (realm-users realm)))

(defun hash-keys (hash)
  (loop for k being the hash-keys of hash
     collect k))

(defun hash-values (hash)
  (loop for k being the hash-values of hash
     collect k))

(defun get-realm-user-names (realm)
  (hash-keys (realm-users realm)))

(defun get-realm-users (realm)
  (hash-values (realm-users realm)))

(defmethod set-password ((realm realm) (name string) password)
  (let ((user (get-realm-user realm name)))
    (when user
      (set-password realm user password))))

(defmethod add-user ((realm realm) (name string) (password string))
  (let ((user (make-instance 'user :name name :password-salt (random-string 8))))
    (with-lock (*password-lock*)
      (setf (gethash name (realm-users realm)) user)
      (set-password realm user password))
    user))

(defmethod delete-user ((realm realm) (name string))
  (with-lock (*password-lock*)
    (remhash name (realm-users realm))
    (store-realm-users realm)))

(defmethod check-password ((realm realm) (user user) password)
  (and password
       (equalp (user-password user)
               (md5:md5sum-sequence
                (concatenate 'simple-string (user-password-salt user) password)))))

(defmethod check-password ((realm realm) (name string) password)
  (let ((user (get-realm-user realm name)))
    (when user
      (check-password realm user password))))

;;; groups

(defun get-realm-group-names (realm)
  (hash-keys (realm-groups realm)))

(defun get-realm-groups (realm)
  (hash-values (realm-groups realm)))

(defmethod read-realm-groups ((realm realm))
  (let ((path (realm-group-storage-path realm)))
    (when (probe-file path)
      (with-lock (*password-file-lock*)
        (setf (realm-groups realm)
              (cl-store:restore path))))))

(defmethod store-realm-groups ((realm realm))
  (let ((path (realm-group-storage-path realm)))
    (ensure-directories-exist path)
    (with-lock (*password-file-lock*)
      (cl-store:store (realm-groups realm) path))))

(defmethod add-group ((realm realm) (name string))
  (let ((group (make-instance 'group :name name)))
    (setf (gethash name (realm-groups realm)) group)
    (store-realm-groups realm)
    group))

(defmethod add-group-user ((realm realm) (group group) (user user))
  (error "Not yet implemented"))

