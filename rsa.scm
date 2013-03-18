;;; Implementation of RSA for Scheme
;;; 
;;; Implemented by Hrafnkell Eiriksson <he@klaki.net>
;;; Copyright (C) 2001 Hrafnkell Eiriksson
;;;
;;; This program is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU General Public License
;;; as published by the Free Software Foundation; either version 2
;;; of the License, or (at your option) any later version.
;;; 
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;; 
;;; You should have received a copy of the GNU General Public License
;;; along with this program; if not, write to the Free Software
;;; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
;;;
;;; $Id: rsa.scm,v 1.8 2001/05/14 05:57:40 he Exp $

;;; useage: (powmod x b n)
;;; pre:    x b and n are exact integers
;;;         b >= 1
;;; post:   evaluates to  x^b mod n
(define powmod
  (lambda (x b n)
    (do ((z 1))
      ((= b 0) z)
        (begin (if (= 1 (modulo b 2))
                   (set! z (remainder (* z x) n))
               )
               (set! x (modulo (* x x) n))
               (set! b (quotient b 2))
        )
    )
  )
)

;;; useage: (inv-mod x n)
;;; pre:    x and n are positive integers
;;; post:   evaluates to the inverse of x modulo n or #f it does not exist
(define inv-mod
  (lambda (x n)
    (let iterate ((n0 n) 
                  (x0 x) 
                  (t0 0) 
                  (t 1) 
                  (q (quotient n x)) 
                  (r (remainder n x))
                 )
      (cond ((> r 0) (iterate x0                        ; n0   
                              r                         ; x0
                              t                         ; t0
                              (modulo (- t0 (* q t)) n) ; t
                              (quotient x0 r)           ; q
                              (remainder x0 r)          ; r
                     )
            )
            ((= x0 1) (modulo t n))  ;;; x has an inverse modulo n
            (else #f)
      )
    )
  )
)

;;; useage: (genrand bits)
;;; pre:    bits is an exact positive integer
;;; post:   evaluates to a random number in the interval
;;;         [0;2^(quotient bits 8))
(define genrand
  (lambda (bits)
    (do (( b (quotient bits 8) (- b 1)) (ret 0))
      ((= b 0) (if (even? ret) (- ret 1) ret))
        (set! ret (+ (random 256) (* ret 256)))
    )
  )
)

;;; useage: (factor_pow2 n k)
;;; pre:    k is 0
;;;         n is an exact positive integer
;;; post:   finds m and k so that n = (2^k)*m
;;;         evaluates to a list with (m k)
(define factor_pow2
  (lambda (n k)
    (if (= 1 (modulo n 2))
      (list n k)
      (factor_pow2 (/ n 2) (+ k 1))
    )
  )
)


;;; useage: (euler-phi p q)
;;; pre:    p and q are prime
;;; post:   evals to (p-1)*(q-1)
(define euler-phi
  (lambda (p q)
    (* (- p 1) (- q 1))
  )
)

;;; useage: (isprime? n)
;;; pre:    n is a positive exact integer
;;; post:   evals to #t or #f
;;;
;;; Implements the yes-biased Rabin-Miller primality test.
;;; When it says yes (#t) it is allways right
;;; but when it says no (#f) it has less than 1/4 changes of being wrong.
(define isprime?
  (lambda (n)
    (call-with-current-continuation 
      (lambda (return)
        (let* ((mk (factor_pow2 (- n 1) 0))
               (b (powmod (random n) (car mk) n))
              )
          (if (= 1 (modulo b n))
            (return #t)
            (do ((i 0 (+ i 1))) ((= i (cadr mk)) (return #f))
              (if (= (modulo b n) (modulo -1 n))
                (return #t)
                (set! b (powmod b 2 n))
              )
            )
          )
        )
      )
    )
  )
)

;;; useage: (findprime bits)
;;; pre:    bits is an exact integer>0
;;; post:   evaluates to a random number that of size bits that has passed 
;;;         one miller-rabin test
(define findprime
  (lambda (bits)
    (let iterate ((p (genrand bits))
                 )
      (cond ((isprime? p) p)
            (else (iterate (genrand bits)))
      )
    )
  )
)

;;; Key generation stuff:
;;; An RSA private key is: (n p q b a)
;;; An RSA public key is:  (n b)
;;; where p and q are prime numbers, n = p*q, b is a random number from
;;; Z_phi(n) such that gcd(b,phi(n))=1 and a is the inverse of b modulo phi(n)
;;; A key pair is a (public_key . private_key)

;;; useage (find-exponent phi_n)
;;; pre:   phi_n >0 integer
;;; post:  evaluates to a random number b such that (= (gcd b phi_n) 1) => #t
(define find-exponent
  (lambda (phi_n)
    (let iterate ((b (random phi_n))
                 )
      (cond ((= 1 (gcd b phi_n)) b)
            (else (iterate (random phi_n)))
      )
    )
  )
)

;;; useage: (generate-keypair bits)
;;; pre:    bits >0 integer
;;; post:   evaluates to a pair whose car is a public RSA key
;;;         and cdr is a private RSA key
(define generate-keypair 
  (lambda (bits)
    (let* ((p (findprime bits))
           (q (findprime bits))
           (n (* p q))
           (phi_n (euler-phi p q))
           (b (find-exponent phi_n))
           (a (inv-mod b phi_n))
          )
      (cons (list n b) (list n p q a))
    )
  )
)

;;; Encryption/decryption procedures

;;; useage: (encrypt public-key)
;;; post:   evaluates to a procedure taking a single argument.
;;;         The returned procedure evaluates to RSA encrypted version 
;;;         of the cleartext  given as an argument.
(define encrypt
  (lambda (pub_key)
    (lambda (msg) 
      (powmod msg (cadr pub_key) (car pub_key))
    )
  )
)

;;; useage: (decrypt private-key)
;;; post:   evaluates to a procedure taking a single argument.
;;;         The returned procedure evaluates to the cleartext corresponding 
;;;         to the RSA encrypted cyphertext given as an argument
(define decrypt
  (lambda (priv_key)
    (lambda (msg)
      (powmod msg (cadddr priv_key) (car priv_key))
    )
  )
)
