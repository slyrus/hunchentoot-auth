
(in-package :cl-user)

(defpackage :hunchentoot-auth-test
  (:nicknames :ht-auth-test)
  (:use :cl :hunchentoot :hunchentoot-auth))

(defpackage :hunchentoot-auth-test-user
  (:nicknames :ht-auth-test-user)
  (:use :cl :hunchentoot :hunchentoot-auth :hunchentoot-auth-test))
