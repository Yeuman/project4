;; Copyright 2018 Intel Corporation
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; PACKAGE: key-store-package
;;
;; This package implements a key-value store that is maintained
;; completely within the intrinsic state of the contract. As such
;; it should not be used for large databases.

(require "hashtab.scm")

(define key-store-package
  (package
   (define-class key-store
     (instance-vars
      (prefix "")
      (table-size 347)
      (store #f))
     (class-vars
      (_ht-set_ (hashtab-package::associator string=?))
      (_ht-get_ (hashtab-package::inquirer string=?))
      (_ht-del_ (hashtab-package::remover string=?))))

   (define-method key-store (initialize-instance . args)
     (if (not store)
         (instance-set! self 'store (hashtab-package::make-hash-table table-size))))

   ;; -----------------------------------------------------------------
   ;; Methods to interogate the store
   ;; -----------------------------------------------------------------
   (define-method key-store (map proc)
     (hashtab-package::hash-map (lambda (k v) (proc k (send self 'get k))) store))

   (define-method key-store (for-each proc)
     (hashtab-package::hash-for-each (lambda (k v) (proc k (send self 'get k))) store))

   ;; -----------------------------------------------------------------
   ;; Methods to interogate the store
   ;; -----------------------------------------------------------------
   (define-method key-store (get-state)
     (let ((result '()))
       (hashtab-package::hash-for-each
        (lambda (key value)
          (set! result (cons (list key (send value 'externalize 'full)) result)))
        store)
       result))

   ;; -----------------------------------------------------------------
   ;; Methods to update the value associated with a value, note that
   ;; value is an instance of the value object and value is an integer
   ;; -----------------------------------------------------------------
   (define-method key-store (exists? key)
     (let ((value (_ht-get_ store key)))
       value))

   (define-method key-store (get key)
     (let ((value (_ht-get_ store key)))
       (assert value "key does not exist" key)
       value))

   (define-method key-store (set key value)
     (let ((oldvalue (_ht-get_ store key)))
       (if oldvalue (_ht-del_ store key))
       (_ht-set_ store key value)))

   (define-method key-store (del key)
     (let ((value (_ht-get_ store key)))
       (assert value "key does not exist" key)
       (_ht-del_ store key)))
   ))

(define key-store key-store-package::key-store)
