
(in-package :ht-auth-test)

(defvar *test-realm-directory*
  (ch-asdf:asdf-lookup-path "asdf:/hunchentoot-auth-test/test/test-realm"))

(ensure-directories-exist *test-realm-directory*)

(defparameter *test-realm*
  (make-instance 'ht-auth:realm
                 :user-storage-path
                 (merge-pathnames "users.store" *test-realm-directory*)
                 :group-storage-path
                 (merge-pathnames "groups.store" *test-realm-directory*)))

(ht-auth:add-user *test-realm* "alice" "secret1")
(ht-auth:add-user *test-realm* "bob" "secret2")
(ht-auth:add-user *test-realm* "charlie" "secret3")

(ht-auth:get-realm-user-names *test-realm*)

(assert (ht-auth:get-realm-user *test-realm* "alice"))
(assert (null (ht-auth:get-realm-user *test-realm* "alison")))

(assert (ht-auth:check-password *test-realm* "alice" "secret1"))
(assert (null (ht-auth:check-password *test-realm* "bob" "secret3")))

(assert (ht-auth:get-realm-user *test-realm* "charlie"))
(ht-auth:delete-user *test-realm* "charlie")
(assert (null (ht-auth:get-realm-user *test-realm* "charlie")))

