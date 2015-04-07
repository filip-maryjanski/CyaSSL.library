/* ecc.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <cyassl/ctaocrypt/settings.h>

#ifdef HAVE_ECC

#include <cyassl/ctaocrypt/ecc.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/error-crypt.h>

#ifdef HAVE_ECC_ENCRYPT
    #include <cyassl/ctaocrypt/hmac.h>
    #include <cyassl/ctaocrypt/aes.h>
#endif


/* map

   ptmul -> mulmod

*/

#define ECC112
#define ECC128
#define ECC160
#define ECC192
#define ECC224
#define ECC256
#define ECC384
#define ECC521



/* This holds the key settings.  ***MUST*** be organized by size from
   smallest to largest. */

const ecc_set_type ecc_sets[] = {
#ifdef ECC112
{
        14,
        "SECP112R1",
        "DB7C2ABF62E35E668076BEAD208B",
        "DB7C2ABF62E35E668076BEAD2088",
        "659EF8BA043916EEDE8911702B22",
        "DB7C2ABF62E35E7628DFAC6561C5",
        "09487239995A5EE76B55F9C2F098",
        "A89CE5AF8724C0A23E0E0FF77500"
},
#endif
#ifdef ECC128
{
        16,
        "SECP128R1",
        "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC",
        "E87579C11079F43DD824993C2CEE5ED3",
        "FFFFFFFE0000000075A30D1B9038A115",
        "161FF7528B899B2D0C28607CA52C5B86",
        "CF5AC8395BAFEB13C02DA292DDED7A83",
},
#endif
#ifdef ECC160
{
        20,
        "SECP160R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
        "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
        "0100000000000000000001F4C8F927AED3CA752257",
        "4A96B5688EF573284664698968C38BB913CBFC82",
        "23A628553168947D59DCC912042351377AC5FB32",
},
#endif
#ifdef ECC192
{
        24,
        "ECC-192",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
},
#endif
#ifdef ECC224
{
        28,
        "ECC-224",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
},
#endif
#ifdef ECC256
{
        32,
        "ECC-256",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
},
#endif
#ifdef ECC384
{
        48,
        "ECC-384",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
},
#endif
#ifdef ECC521
{
        66,
        "ECC-521",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
},
#endif
{
   0,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL
}
};


ecc_point* ecc_new_point(void);
void ecc_del_point(ecc_point* p);
int  ecc_map(ecc_point*, mp_int*, mp_digit*);
int  ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                              mp_int* modulus, mp_digit* mp);
int  ecc_projective_dbl_point(ecc_point* P, ecc_point* R, mp_int* modulus,
                              mp_digit* mp);
static int ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus,
                      int map);
#ifdef ECC_SHAMIR
static int ecc_mul2add(ecc_point* A, mp_int* kA, ecc_point* B, mp_int* kB,
                       ecc_point* C, mp_int* modulus);
#endif

int mp_jacobi(mp_int* a, mp_int* p, int* c);
int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);
int mp_submod(mp_int* a, mp_int* b, mp_int* c, mp_int* d);

#ifdef HAVE_COMP_KEY
static int ecc_export_x963_compressed(ecc_key*, byte* out, word32* outLen);
#endif

/* helper for either lib */
static int get_digit_count(mp_int* a)
{
    if (a == NULL)
        return 0;

    return a->used;
}

/* helper for either lib */
static mp_digit get_digit(mp_int* a, int n)
{
    if (a == NULL)
        return 0;

    return (n >= a->used || n < 0) ? 0 : a->dp[n];
}


#if defined(USE_FAST_MATH)

/* fast math accelerated version, but not for fp ecc yet */

/**
   Add two ECC points
   P        The point to add
   Q        The point to add
   R        [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R,
                             mp_int* modulus, mp_digit* mp)
{
   fp_int t1, t2, x, y, z;
   int    err;

   if (P == NULL || Q == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != MP_OKAY) {
      return err;
   }

   /* should we dbl instead? */
   fp_sub(modulus, &Q->y, &t1);
   if ( (fp_cmp(&P->x, &Q->x) == FP_EQ) && 
        (get_digit_count(&Q->z) && fp_cmp(&P->z, &Q->z) == FP_EQ) &&
        (fp_cmp(&P->y, &Q->y) == FP_EQ || fp_cmp(&P->y, &t1) == FP_EQ)) {
        return ecc_projective_dbl_point(P, R, modulus, mp);
   }

   fp_copy(&P->x, &x);
   fp_copy(&P->y, &y);
   fp_copy(&P->z, &z);

   /* if Z is one then these are no-operations */
   if (get_digit_count(&Q->z)) {
      /* T1 = Z' * Z' */
      fp_sqr(&Q->z, &t1);
      fp_montgomery_reduce(&t1, modulus, *mp);
      /* X = X * T1 */
      fp_mul(&t1, &x, &x);
      fp_montgomery_reduce(&x, modulus, *mp);
      /* T1 = Z' * T1 */
      fp_mul(&Q->z, &t1, &t1);
      fp_montgomery_reduce(&t1, modulus, *mp);
      /* Y = Y * T1 */
      fp_mul(&t1, &y, &y);
      fp_montgomery_reduce(&y, modulus, *mp);
   }

   /* T1 = Z*Z */
   fp_sqr(&z, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);
   /* T2 = X' * T1 */
   fp_mul(&Q->x, &t1, &t2);
   fp_montgomery_reduce(&t2, modulus, *mp);
   /* T1 = Z * T1 */
   fp_mul(&z, &t1, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);
   /* T1 = Y' * T1 */
   fp_mul(&Q->y, &t1, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);

   /* Y = Y - T1 */
   fp_sub(&y, &t1, &y);
   if (fp_cmp_d(&y, 0) == FP_LT) {
      fp_add(&y, modulus, &y);
   }
   /* T1 = 2T1 */
   fp_add(&t1, &t1, &t1);
   if (fp_cmp(&t1, modulus) != FP_LT) {
      fp_sub(&t1, modulus, &t1);
   }
   /* T1 = Y + T1 */
   fp_add(&t1, &y, &t1);
   if (fp_cmp(&t1, modulus) != FP_LT) {
      fp_sub(&t1, modulus, &t1);
   }
   /* X = X - T2 */
   fp_sub(&x, &t2, &x);
   if (fp_cmp_d(&x, 0) == FP_LT) {
      fp_add(&x, modulus, &x);
   }
   /* T2 = 2T2 */
   fp_add(&t2, &t2, &t2);
   if (fp_cmp(&t2, modulus) != FP_LT) {
      fp_sub(&t2, modulus, &t2);
   }
   /* T2 = X + T2 */
   fp_add(&t2, &x, &t2);
   if (fp_cmp(&t2, modulus) != FP_LT) {
      fp_sub(&t2, modulus, &t2);
   }

   /* if Z' != 1 */
   if (get_digit_count(&Q->z)) {
      /* Z = Z * Z' */
      fp_mul(&z, &Q->z, &z);
      fp_montgomery_reduce(&z, modulus, *mp);
   }

   /* Z = Z * X */
   fp_mul(&z, &x, &z);
   fp_montgomery_reduce(&z, modulus, *mp);

   /* T1 = T1 * X  */
   fp_mul(&t1, &x, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);
   /* X = X * X */
   fp_sqr(&x, &x);
   fp_montgomery_reduce(&x, modulus, *mp);
   /* T2 = T2 * x */
   fp_mul(&t2, &x, &t2);
   fp_montgomery_reduce(&t2, modulus, *mp);
   /* T1 = T1 * X  */
   fp_mul(&t1, &x, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);
 
   /* X = Y*Y */
   fp_sqr(&y, &x);
   fp_montgomery_reduce(&x, modulus, *mp);
   /* X = X - T2 */
   fp_sub(&x, &t2, &x);
   if (fp_cmp_d(&x, 0) == FP_LT) {
      fp_add(&x, modulus, &x);
   }

   /* T2 = T2 - X */
   fp_sub(&t2, &x, &t2);
   if (fp_cmp_d(&t2, 0) == FP_LT) {
      fp_add(&t2, modulus, &t2);
   } 
   /* T2 = T2 - X */
   fp_sub(&t2, &x, &t2);
   if (fp_cmp_d(&t2, 0) == FP_LT) {
      fp_add(&t2, modulus, &t2);
   }
   /* T2 = T2 * Y */
   fp_mul(&t2, &y, &t2);
   fp_montgomery_reduce(&t2, modulus, *mp);
   /* Y = T2 - T1 */
   fp_sub(&t2, &t1, &y);
   if (fp_cmp_d(&y, 0) == FP_LT) {
      fp_add(&y, modulus, &y);
   }
   /* Y = Y/2 */
   if (fp_isodd(&y)) {
      fp_add(&y, modulus, &y);
   }
   fp_div_2(&y, &y);

   fp_copy(&x, &R->x);
   fp_copy(&y, &R->y);
   fp_copy(&z, &R->z);
   
   return MP_OKAY;
}


/**
   Double an ECC point
   P   The point to double
   R   [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mp_int* modulus,
                             mp_digit* mp)
{
   fp_int   t1, t2;
   int      err;

   if (P == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if (P != R) {
      fp_copy(&P->x, &R->x);
      fp_copy(&P->y, &R->y);
      fp_copy(&P->z, &R->z);
   }

   if ((err = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL)) != MP_OKAY) {
      return err;
   }

   /* t1 = Z * Z */
   fp_sqr(&R->z, &t1);
   fp_montgomery_reduce(&t1, modulus, *mp);
   /* Z = Y * Z */
   fp_mul(&R->z, &R->y, &R->z);
   fp_montgomery_reduce(&R->z, modulus, *mp);
   /* Z = 2Z */
   fp_add(&R->z, &R->z, &R->z);
   if (fp_cmp(&R->z, modulus) != FP_LT) {
      fp_sub(&R->z, modulus, &R->z);
   }
   
   /* &t2 = X - T1 */
   fp_sub(&R->x, &t1, &t2);
   if (fp_cmp_d(&t2, 0) == FP_LT) {
      fp_add(&t2, modulus, &t2);
   }
   /* T1 = X + T1 */
   fp_add(&t1, &R->x, &t1);
   if (fp_cmp(&t1, modulus) != FP_LT) {
      fp_sub(&t1, modulus, &t1);
   }
   /* T2 = T1 * T2 */
   fp_mul(&t1, &t2, &t2);
   fp_montgomery_reduce(&t2, modulus, *mp);
   /* T1 = 2T2 */
   fp_add(&t2, &t2, &t1);
   if (fp_cmp(&t1, modulus) != FP_LT) {
      fp_sub(&t1, modulus, &t1);
   }
   /* T1 = T1 + T2 */
   fp_add(&t1, &t2, &t1);
   if (fp_cmp(&t1, modulus) != FP_LT) {
      fp_sub(&t1, modulus, &t1);
   }

   /* Y = 2Y */
   fp_add(&R->y, &R->y, &R->y);
   if (fp_cmp(&R->y, modulus) != FP_LT) {
      fp_sub(&R->y, modulus, &R->y);
   }
   /* Y = Y * Y */
   fp_sqr(&R->y, &R->y);
   fp_montgomery_reduce(&R->y, modulus, *mp);
   /* T2 = Y * Y */
   fp_sqr(&R->y, &t2);
   fp_montgomery_reduce(&t2, modulus, *mp);
   /* T2 = T2/2 */
   if (fp_isodd(&t2)) {
      fp_add(&t2, modulus, &t2);
   }
   fp_div_2(&t2, &t2);
   /* Y = Y * X */
   fp_mul(&R->y, &R->x, &R->y);
   fp_montgomery_reduce(&R->y, modulus, *mp);

   /* X  = T1 * T1 */
   fp_sqr(&t1, &R->x);
   fp_montgomery_reduce(&R->x, modulus, *mp);
   /* X = X - Y */
   fp_sub(&R->x, &R->y, &R->x);
   if (fp_cmp_d(&R->x, 0) == FP_LT) {
      fp_add(&R->x, modulus, &R->x);
   }
   /* X = X - Y */
   fp_sub(&R->x, &R->y, &R->x);
   if (fp_cmp_d(&R->x, 0) == FP_LT) {
      fp_add(&R->x, modulus, &R->x);
   }

   /* Y = Y - X */     
   fp_sub(&R->y, &R->x, &R->y);
   if (fp_cmp_d(&R->y, 0) == FP_LT) {
      fp_add(&R->y, modulus, &R->y);
   }
   /* Y = Y * T1 */
   fp_mul(&R->y, &t1, &R->y);
   fp_montgomery_reduce(&R->y, modulus, *mp);
   /* Y = Y - T2 */
   fp_sub(&R->y, &t2, &R->y);
   if (fp_cmp_d(&R->y, 0) == FP_LT) {
      fp_add(&R->y, modulus, &R->y);
   }
 
   return MP_OKAY;
}

#else /* USE_FAST_MATH */

/**
   Add two ECC points
   P        The point to add
   Q        The point to add
   R        [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                             mp_int* modulus, mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   mp_int x;
   mp_int y;
   mp_int z;
   int    err;

   if (P == NULL || Q == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != MP_OKAY) {
      return err;
   }
   
   /* should we dbl instead? */
   err = mp_sub(modulus, &Q->y, &t1);

   if (err == MP_OKAY) {
       if ( (mp_cmp(&P->x, &Q->x) == MP_EQ) && 
            (get_digit_count(&Q->z) && mp_cmp(&P->z, &Q->z) == MP_EQ) &&
            (mp_cmp(&P->y, &Q->y) == MP_EQ || mp_cmp(&P->y, &t1) == MP_EQ)) {
                mp_clear(&t1);
                mp_clear(&t2);
                mp_clear(&x);
                mp_clear(&y);
                mp_clear(&z);

                return ecc_projective_dbl_point(P, R, modulus, mp);
       }
   }

   if (err == MP_OKAY)
       err = mp_copy(&P->x, &x);
   if (err == MP_OKAY)
       err = mp_copy(&P->y, &y);
   if (err == MP_OKAY)
       err = mp_copy(&P->z, &z);

   /* if Z is one then these are no-operations */
   if (err == MP_OKAY) {
       if (get_digit_count(&Q->z)) {
           /* T1 = Z' * Z' */
           err = mp_sqr(&Q->z, &t1);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&t1, modulus, *mp);

           /* X = X * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&t1, &x, &x);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&x, modulus, *mp);

           /* T1 = Z' * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&Q->z, &t1, &t1);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&t1, modulus, *mp);

           /* Y = Y * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&t1, &y, &y);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&y, modulus, *mp);
       }
   }

   /* T1 = Z*Z */
   if (err == MP_OKAY)
       err = mp_sqr(&z, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* T2 = X' * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&Q->x, &t1, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = Z * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&z, &t1, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* T1 = Y' * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&Q->y, &t1, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* Y = Y - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&y, &t1, &y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&y, 0) == MP_LT)
           err = mp_add(&y, modulus, &y);
   }
   /* T1 = 2T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &t1, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T1 = Y + T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &y, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* X = X - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&x, &t2, &x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&x, 0) == MP_LT)
           err = mp_add(&x, modulus, &x);
   }
   /* T2 = 2T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &t2, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp(&t2, modulus) != MP_LT)
           err = mp_sub(&t2, modulus, &t2);
   }
   /* T2 = X + T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp(&t2, modulus) != MP_LT)
           err = mp_sub(&t2, modulus, &t2);
   }

   if (err == MP_OKAY) {
       if (get_digit_count(&Q->z)) {
           /* Z = Z * Z' */
           err = mp_mul(&z, &Q->z, &z);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&z, modulus, *mp);
       }
   }

   /* Z = Z * X */
   if (err == MP_OKAY)
       err = mp_mul(&z, &x, &z);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&z, modulus, *mp);

   /* T1 = T1 * X  */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &x, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* X = X * X */
   if (err == MP_OKAY)
       err = mp_sqr(&x, &x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&x, modulus, *mp);
   
   /* T2 = T2 * x */
   if (err == MP_OKAY)
       err = mp_mul(&t2, &x, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = T1 * X  */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &x, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);
 
   /* X = Y*Y */
   if (err == MP_OKAY)
       err = mp_sqr(&y, &x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&x, modulus, *mp);

   /* X = X - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&x, &t2, &x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&x, 0) == MP_LT)
           err = mp_add(&x, modulus, &x);
   }
   /* T2 = T2 - X */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   } 
   /* T2 = T2 - X */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   }
   /* T2 = T2 * Y */
   if (err == MP_OKAY)
       err = mp_mul(&t2, &y, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* Y = T2 - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &t1, &y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&y, 0) == MP_LT)
           err = mp_add(&y, modulus, &y);
   }
   /* Y = Y/2 */
   if (err == MP_OKAY) {
       if (mp_isodd(&y))
           err = mp_add(&y, modulus, &y);
   }
   if (err == MP_OKAY)
       err = mp_div_2(&y, &y);

   if (err == MP_OKAY)
       err = mp_copy(&x, &R->x);
   if (err == MP_OKAY)
       err = mp_copy(&y, &R->y);
   if (err == MP_OKAY)
       err = mp_copy(&z, &R->z);

   /* clean up */
   mp_clear(&t1);
   mp_clear(&t2);
   mp_clear(&x);
   mp_clear(&y);
   mp_clear(&z);

   return err;
}


/**
   Double an ECC point
   P   The point to double
   R   [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mp_int* modulus,
                             mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   int    err;

   if (P == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL)) != MP_OKAY) {
      return err;
   }

   if (P != R) {
      err = mp_copy(&P->x, &R->x);
      if (err == MP_OKAY)
          err = mp_copy(&P->y, &R->y);
      if (err == MP_OKAY)
          err = mp_copy(&P->z, &R->z);
   }

   /* t1 = Z * Z */
   if (err == MP_OKAY)
       err = mp_sqr(&R->z, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* Z = Y * Z */
   if (err == MP_OKAY)
       err = mp_mul(&R->z, &R->y, &R->z);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->z, modulus, *mp);

   /* Z = 2Z */
   if (err == MP_OKAY)
       err = mp_add(&R->z, &R->z, &R->z);
   if (err == MP_OKAY) {
       if (mp_cmp(&R->z, modulus) != MP_LT)
           err = mp_sub(&R->z, modulus, &R->z);
   }

   /* T2 = X - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &t1, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   }
   /* T1 = X + T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &R->x, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T2 = T1 * T2 */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &t2, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = 2T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &t2, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T1 = T1 + T2 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &t2, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* Y = 2Y */
   if (err == MP_OKAY)
       err = mp_add(&R->y, &R->y, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp(&R->y, modulus) != MP_LT)
           err = mp_sub(&R->y, modulus, &R->y);
   }
   /* Y = Y * Y */
   if (err == MP_OKAY)
       err = mp_sqr(&R->y, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);
   
   /* T2 = Y * Y */
   if (err == MP_OKAY)
       err = mp_sqr(&R->y, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T2 = T2/2 */
   if (err == MP_OKAY) {
       if (mp_isodd(&t2))
           err = mp_add(&t2, modulus, &t2);
   }
   if (err == MP_OKAY)
       err = mp_div_2(&t2, &t2);
   
   /* Y = Y * X */
   if (err == MP_OKAY)
       err = mp_mul(&R->y, &R->x, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);

   /* X  = T1 * T1 */
   if (err == MP_OKAY)
       err = mp_sqr(&t1, &R->x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->x, modulus, *mp);

   /* X = X - Y */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &R->y, &R->x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->x, 0) == MP_LT)
           err = mp_add(&R->x, modulus, &R->x);
   }
   /* X = X - Y */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &R->y, &R->x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->x, 0) == MP_LT)
           err = mp_add(&R->x, modulus, &R->x);
   }
   /* Y = Y - X */     
   if (err == MP_OKAY)
       err = mp_sub(&R->y, &R->x, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->y, 0) == MP_LT)
           err = mp_add(&R->y, modulus, &R->y);
   }
   /* Y = Y * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&R->y, &t1, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);

   /* Y = Y - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&R->y, &t2, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->y, 0) == MP_LT)
           err = mp_add(&R->y, modulus, &R->y);
   }

   /* clean up */ 
   mp_clear(&t1);
   mp_clear(&t2);

   return err;
}

#endif /* USE_FAST_MATH */

/**
  Map a projective jacbobian point back to affine space
  P        [in/out] The point to map
  modulus  The modulus of the field the ECC curve is in
  mp       The "b" value from montgomery_setup()
  return   MP_OKAY on success
*/
int ecc_map(ecc_point* P, mp_int* modulus, mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   int    err;

   if (P == NULL || mp == NULL || modulus == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL)) != MP_OKAY) {
      return MEMORY_E;
   }

   /* first map z back to normal */
   err = mp_montgomery_reduce(&P->z, modulus, *mp);

   /* get 1/z */
   if (err == MP_OKAY)
       err = mp_invmod(&P->z, modulus, &t1);
 
   /* get 1/z^2 and 1/z^3 */
   if (err == MP_OKAY)
       err = mp_sqr(&t1, &t2);
   if (err == MP_OKAY)
       err = mp_mod(&t2, modulus, &t2);
   if (err == MP_OKAY)
       err = mp_mul(&t1, &t2, &t1);
   if (err == MP_OKAY)
       err = mp_mod(&t1, modulus, &t1);

   /* multiply against x/y */
   if (err == MP_OKAY)
       err = mp_mul(&P->x, &t2, &P->x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&P->x, modulus, *mp);
   if (err == MP_OKAY)
       err = mp_mul(&P->y, &t1, &P->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&P->y, modulus, *mp);
   
   if (err == MP_OKAY)
       mp_set(&P->z, 1);

   /* clean up */
   mp_clear(&t1);
   mp_clear(&t2);

   return err;
}


#ifndef ECC_TIMING_RESISTANT

/* size of sliding window, don't change this! */
#define WINSIZE 4

/**
   Perform a point multiplication 
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
#ifdef FP_ECC
static int normal_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R,
                             mp_int* modulus, int map)
#else
static int ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus,
                      int map)
#endif
{
   ecc_point *tG, *M[8];
   int           i, j, err;
   mp_int        mu;
   mp_digit      mp;
   mp_digit      buf;
   int           first = 1, bitbuf = 0, bitcpy = 0, bitcnt = 0, mode = 0,
                 digidx = 0;

   if (k == NULL || G == NULL || R == NULL || modulus == NULL)
       return ECC_BAD_ARG_E;

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_init(&mu)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
      mp_clear(&mu);
      return err;
   }
  
  /* alloc ram for window temps */
  for (i = 0; i < 8; i++) {
      M[i] = ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ecc_del_point(M[j]);
         }
         mp_clear(&mu);
         return MEMORY_E;
      }
  }

   /* make a copy of G incase R==G */
   tG = ecc_new_point();
   if (tG == NULL)
       err = MEMORY_E;

   /* tG = G  and convert to montgomery */
   if (err == MP_OKAY) {
       if (mp_cmp_d(&mu, 1) == MP_EQ) {
           err = mp_copy(&G->x, &tG->x);
           if (err == MP_OKAY)
               err = mp_copy(&G->y, &tG->y);
           if (err == MP_OKAY)
               err = mp_copy(&G->z, &tG->z);
       } else {
           err = mp_mulmod(&G->x, &mu, modulus, &tG->x);
           if (err == MP_OKAY)
               err = mp_mulmod(&G->y, &mu, modulus, &tG->y);
           if (err == MP_OKAY)
               err = mp_mulmod(&G->z, &mu, modulus, &tG->z);
       }
   }
   mp_clear(&mu);
   
   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(tG, M[0], modulus, &mp);
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(M[0], M[0], modulus, &mp);
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(M[0], M[0], modulus, &mp);

   /* now find (8+k)G for k=1..7 */
   if (err == MP_OKAY)
       for (j = 9; j < 16; j++) {
           err = ecc_projective_add_point(M[j-9], tG, M[j-8], modulus, &mp);
           if (err != MP_OKAY) break;
       }

   /* setup sliding window */
   if (err == MP_OKAY) {
       mode   = 0;
       bitcnt = 1;
       buf    = 0;
       digidx = get_digit_count(k) - 1;
       bitcpy = bitbuf = 0;
       first  = 1;

       /* perform ops */
       for (;;) {
           /* grab next digit as required */
           if (--bitcnt == 0) {
               if (digidx == -1) {
                   break;
               }
               buf    = get_digit(k, digidx);
               bitcnt = (int) DIGIT_BIT; 
               --digidx;
           }

           /* grab the next msb from the ltiplicand */
           i = (int)(buf >> (DIGIT_BIT - 1)) & 1;
           buf <<= 1;

           /* skip leading zero bits */
           if (mode == 0 && i == 0)
               continue;

           /* if the bit is zero and mode == 1 then we double */
           if (mode == 1 && i == 0) {
               err = ecc_projective_dbl_point(R, R, modulus, &mp);
               if (err != MP_OKAY) break;
               continue;
           }

           /* else we add it to the window */
           bitbuf |= (i << (WINSIZE - ++bitcpy));
           mode = 2;

           if (bitcpy == WINSIZE) {
               /* if this is the first window we do a simple copy */
               if (first == 1) {
                   /* R = kG [k = first window] */
                   err = mp_copy(&M[bitbuf-8]->x, &R->x);
                   if (err != MP_OKAY) break;

                   err = mp_copy(&M[bitbuf-8]->y, &R->y);
                   if (err != MP_OKAY) break;

                   err = mp_copy(&M[bitbuf-8]->z, &R->z);
                   first = 0;
               } else {
                   /* normal window */
                   /* ok window is filled so double as required and add  */
                   /* double first */
                   for (j = 0; j < WINSIZE; j++) {
                       err = ecc_projective_dbl_point(R, R, modulus, &mp);
                       if (err != MP_OKAY) break;
                   }
                   if (err != MP_OKAY) break;  /* out of first for(;;) */

                   /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranted */
                   err = ecc_projective_add_point(R,M[bitbuf-8],R,modulus,&mp);
               }
               if (err != MP_OKAY) break;
               /* empty window and reset */
               bitcpy = bitbuf = 0;
               mode = 1;
           }
       }
   }

   /* if bits remain then double/add */
   if (err == MP_OKAY) {
       if (mode == 2 && bitcpy > 0) {
           /* double then add */
           for (j = 0; j < bitcpy; j++) {
               /* only double if we have had at least one add first */
               if (first == 0) {
                   err = ecc_projective_dbl_point(R, R, modulus, &mp);
                   if (err != MP_OKAY) break;
               }

               bitbuf <<= 1;
               if ((bitbuf & (1 << WINSIZE)) != 0) {
                   if (first == 1) {
                       /* first add, so copy */
                       err = mp_copy(&tG->x, &R->x);
                       if (err != MP_OKAY) break;

                       err = mp_copy(&tG->y, &R->y);
                       if (err != MP_OKAY) break;

                       err = mp_copy(&tG->z, &R->z);
                       if (err != MP_OKAY) break;
                       first = 0;
                   } else {
                       /* then add */
                       err = ecc_projective_add_point(R, tG, R, modulus, &mp);
                       if (err != MP_OKAY) break;
                   }
               }
           }
       }
   }

   /* map R back from projective space */
   if (err == MP_OKAY && map)
       err = ecc_map(R, modulus, &mp);

   mp_clear(&mu);
   ecc_del_point(tG);
   for (i = 0; i < 8; i++) {
       ecc_del_point(M[i]);
   }
   return err;
}

#undef WINSIZE

#else /* ECC_TIMING_RESISTANT */

/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
            (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
#ifdef FP_ECC
static int normal_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R,
                             mp_int* modulus, int map)
#else
static int ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus,
                      int map)
#endif
{
   ecc_point    *tG, *M[3];
   int           i, j, err;
   mp_int        mu;
   mp_digit      mp;
   mp_digit      buf;
   int           first = 1, bitbuf = 0, bitcpy = 0, bitcnt = 0, mode = 0,
                 digidx = 0;

   if (k == NULL || G == NULL || R == NULL || modulus == NULL)
       return ECC_BAD_ARG_E;

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_init(&mu)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
      mp_clear(&mu);
      return err;
   }

  /* alloc ram for window temps */
  for (i = 0; i < 3; i++) {
      M[i] = ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ecc_del_point(M[j]);
         }
         mp_clear(&mu);
         return MEMORY_E;
      }
  }

   /* make a copy of G incase R==G */
   tG = ecc_new_point();
   if (tG == NULL)
       err = MEMORY_E;

   /* tG = G  and convert to montgomery */
   if (err == MP_OKAY) {
       err = mp_mulmod(&G->x, &mu, modulus, &tG->x);
       if (err == MP_OKAY)
           err = mp_mulmod(&G->y, &mu, modulus, &tG->y);
       if (err == MP_OKAY)
           err = mp_mulmod(&G->z, &mu, modulus, &tG->z);
   }
   mp_clear(&mu);

   /* calc the M tab */
   /* M[0] == G */
   if (err == MP_OKAY)
       err = mp_copy(&tG->x, &M[0]->x);
   if (err == MP_OKAY)
       err = mp_copy(&tG->y, &M[0]->y);
   if (err == MP_OKAY)
       err = mp_copy(&tG->z, &M[0]->z);

   /* M[1] == 2G */
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(tG, M[1], modulus, &mp);

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = get_digit_count(k) - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   if (err == MP_OKAY) {
       for (;;) {
           /* grab next digit as required */
           if (--bitcnt == 0) {
               if (digidx == -1) {
                   break;
               }
               buf = get_digit(k, digidx);
               bitcnt = (int) DIGIT_BIT;
               --digidx;
           }

           /* grab the next msb from the ltiplicand */
           i = (buf >> (DIGIT_BIT - 1)) & 1;
           buf <<= 1;

           if (mode == 0 && i == 0) {
               /* dummy operations */
               if (err == MP_OKAY)
                   err = ecc_projective_add_point(M[0], M[1], M[2], modulus,
                                                  &mp);
               if (err == MP_OKAY)
                   err = ecc_projective_dbl_point(M[1], M[2], modulus, &mp);
               if (err == MP_OKAY)
                   continue;
           }

           if (mode == 0 && i == 1) {
               mode = 1;
               /* dummy operations */
               if (err == MP_OKAY)
                   err = ecc_projective_add_point(M[0], M[1], M[2], modulus,
                                                  &mp);
               if (err == MP_OKAY)
                   err = ecc_projective_dbl_point(M[1], M[2], modulus, &mp);
               if (err == MP_OKAY)
                   continue;
           }

           if (err == MP_OKAY)
               err = ecc_projective_add_point(M[0], M[1], M[i^1], modulus, &mp);
           if (err == MP_OKAY)
               err = ecc_projective_dbl_point(M[i], M[i], modulus, &mp);
           if (err != MP_OKAY)
               break;
       } /* end for */
   }

   /* copy result out */
   if (err == MP_OKAY)
       err = mp_copy(&M[0]->x, &R->x);
   if (err == MP_OKAY)
       err = mp_copy(&M[0]->y, &R->y);
   if (err == MP_OKAY)
       err = mp_copy(&M[0]->z, &R->z);

   /* map R back from projective space */
   if (err == MP_OKAY && map)
      err = ecc_map(R, modulus, &mp);

   /* done */
   mp_clear(&mu);
   ecc_del_point(tG);
   for (i = 0; i < 3; i++) {
       ecc_del_point(M[i]);
   }
   return err;
}

#endif /* ECC_TIMING_RESISTANT */


/**
   Allocate a new ECC point
   return A newly allocated point or NULL on error 
*/
ecc_point* ecc_new_point(void)
{
   ecc_point* p;
   p = (ecc_point*)XMALLOC(sizeof(ecc_point), 0, DYNAMIC_TYPE_BIGINT);
   if (p == NULL) {
      return NULL;
   }
   XMEMSET(p, 0, sizeof(ecc_point));
   if (mp_init_multi(&p->x, &p->y, &p->z, NULL, NULL, NULL) != MP_OKAY) {
      XFREE(p, 0, DYNAMIC_TYPE_BIGINT);
      return NULL;
   }
   return p;
}

/** Free an ECC point from memory
  p   The point to free
*/
void ecc_del_point(ecc_point* p)
{
   /* prevents free'ing null arguments */
   if (p != NULL) {
      mp_clear(&p->x);
      mp_clear(&p->y);
      mp_clear(&p->z);
      XFREE(p, 0, DYNAMIC_TYPE_BIGINT);
   }
}


/** Returns whether an ECC idx is valid or not
  n      The idx number to check
  return 1 if valid, 0 if not
*/  
static int ecc_is_valid_idx(int n)
{
   int x;

   for (x = 0; ecc_sets[x].size != 0; x++)
       ;
   /* -1 is a valid index --- indicating that the domain params
      were supplied by the user */
   if ((n >= -1) && (n < x)) {
      return 1;
   }
   return 0;
}


/**
  Create an ECC shared secret between two keys
  private_key      The private ECC key
  public_key       The public key
  out              [out] Destination of the shared secret
                   Conforms to EC-DH from ANSI X9.63
  outlen           [in/out] The max size and resulting size of the shared secret
  return           MP_OKAY if successful
*/
int ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen)
{
   word32         x = 0;
   ecc_point*     result;
   mp_int         prime;
   int            err;

   if (private_key == NULL || public_key == NULL || out == NULL ||
                                                    outlen == NULL)
       return BAD_FUNC_ARG;

   /* type valid? */
   if (private_key->type != ECC_PRIVATEKEY) {
      return ECC_BAD_ARG_E;
   }

   if (ecc_is_valid_idx(private_key->idx) == 0 ||
       ecc_is_valid_idx(public_key->idx)  == 0)
      return ECC_BAD_ARG_E;

   if (XSTRNCMP(private_key->dp->name, public_key->dp->name, ECC_MAXNAME) != 0)
      return ECC_BAD_ARG_E;

   /* make new point */
   result = ecc_new_point();
   if (result == NULL) {
      return MEMORY_E;
   }

   if ((err = mp_init(&prime)) != MP_OKAY) {
      ecc_del_point(result);
      return err;
   }

   err = mp_read_radix(&prime, (char *)private_key->dp->prime, 16);

   if (err == MP_OKAY)
       err = ecc_mulmod(&private_key->k, &public_key->pubkey, result, &prime,1);

   if (err == MP_OKAY) {
       x = mp_unsigned_bin_size(&prime);
       if (*outlen < x)
          err = BUFFER_E;
   }

   if (err == MP_OKAY) {
       XMEMSET(out, 0, x);
       err = mp_to_unsigned_bin(&result->x,out + (x -
                                            mp_unsigned_bin_size(&result->x)));
       *outlen = x;
   }

   mp_clear(&prime);
   ecc_del_point(result);

   return err;
}


int ecc_make_key_ex(RNG* rng, ecc_key* key, const ecc_set_type* dp);

/**
  Make a new ECC key 
  rng          An active RNG state
  keysize      The keysize for the new key (in octets from 20 to 65 bytes)
  key          [out] Destination of the newly created key
  return       MP_OKAY if successful,
                       upon error all allocated memory will be freed
*/
int ecc_make_key(RNG* rng, int keysize, ecc_key* key)
{
   int x, err;

   if (key == NULL || rng == NULL)
       return ECC_BAD_ARG_E;

   /* find key size */
   for (x = 0; (keysize > ecc_sets[x].size) && (ecc_sets[x].size != 0); x++)
       ;
   keysize = ecc_sets[x].size;

   if (keysize > ECC_MAXSIZE || ecc_sets[x].size == 0) {
      return BAD_FUNC_ARG;
   }
   err = ecc_make_key_ex(rng, key, &ecc_sets[x]);
   key->idx = x;

   return err;
}

int ecc_make_key_ex(RNG* rng, ecc_key* key, const ecc_set_type* dp)
{
   int            err;
   ecc_point*     base;
   mp_int         prime;
   mp_int         order;
#ifdef CYASSL_SMALL_STACK
   byte*          buf;
#else
   byte           buf[ECC_MAXSIZE];
#endif
   int            keysize;

   if (key == NULL || rng == NULL || dp == NULL)
       return ECC_BAD_ARG_E;

#ifdef CYASSL_SMALL_STACK
   buf = (byte*)XMALLOC(ECC_MAXSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
   if (buf == NULL)
       return MEMORY_E;
#endif

   key->idx = -1;
   key->dp  = dp;
   keysize  = dp->size;

   /* allocate ram */
   base = NULL;

   /* make up random string */
   err = RNG_GenerateBlock(rng, buf, keysize);
   if (err == 0)
       buf[0] |= 0x0c;

   /* setup the key variables */
   if (err == 0) {
       err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z,
                            &key->k, &prime, &order);
       if (err != MP_OKAY)
           err = MEMORY_E;
   }

   if (err == MP_OKAY) {
       base = ecc_new_point();
       if (base == NULL)
           err = MEMORY_E;
   }

   /* read in the specs for this key */
   if (err == MP_OKAY) 
       err = mp_read_radix(&prime,   (char *)key->dp->prime, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&order,   (char *)key->dp->order, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&base->x, (char *)key->dp->Gx, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&base->y, (char *)key->dp->Gy, 16);
   
   if (err == MP_OKAY) 
       mp_set(&base->z, 1);
   if (err == MP_OKAY) 
       err = mp_read_unsigned_bin(&key->k, (byte*)buf, keysize);

   /* the key should be smaller than the order of base point */
   if (err == MP_OKAY) { 
       if (mp_cmp(&key->k, &order) != MP_LT)
           err = mp_mod(&key->k, &order, &key->k);
   }
   /* make the public key */
   if (err == MP_OKAY)
       err = ecc_mulmod(&key->k, base, &key->pubkey, &prime, 1);
   if (err == MP_OKAY)
       key->type = ECC_PRIVATEKEY;

   if (err != MP_OKAY) {
       /* clean up */
       mp_clear(&key->pubkey.x);
       mp_clear(&key->pubkey.y);
       mp_clear(&key->pubkey.z);
       mp_clear(&key->k);
   }
   ecc_del_point(base);
   mp_clear(&prime);
   mp_clear(&order);

#ifdef ECC_CLEAN_STACK
   XMEMSET(buf, 0, ECC_MAXSIZE);
#endif

#ifdef CYASSL_SMALL_STACK
   XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

   return err;
}


/* Setup dynamic pointers is using normal math for proper freeing */
void ecc_init(ecc_key* key)
{
    (void)key;
#ifndef USE_FAST_MATH
    key->pubkey.x.dp = NULL;
    key->pubkey.y.dp = NULL;
    key->pubkey.z.dp = NULL;

    key->k.dp = NULL;
#endif
}


/**
  Sign a message digest
  in        The message digest to sign
  inlen     The length of the digest
  out       [out] The destination for the signature
  outlen    [in/out] The max size and resulting size of the signature
  key       A private ECC key
  return    MP_OKAY if successful
*/
int ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen, 
                  RNG* rng, ecc_key* key)
{
   mp_int        r;
   mp_int        s;
   mp_int        e;
   mp_int        p;
   int           err;

   if (in == NULL || out == NULL || outlen == NULL || key == NULL || rng ==NULL)
       return ECC_BAD_ARG_E;

   /* is this a private key? */
   if (key->type != ECC_PRIVATEKEY) {
      return ECC_BAD_ARG_E;
   }
   
   /* is the IDX valid ?  */
   if (ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   /* get the hash and load it as a bignum into 'e' */
   /* init the bignums */
   if ((err = mp_init_multi(&r, &s, &p, &e, NULL, NULL)) != MP_OKAY) { 
      return err;
   }
   err = mp_read_radix(&p, (char *)key->dp->order, 16);

   if (err == MP_OKAY) {
       /* we may need to truncate if hash is longer than key size */
       word32 orderBits = mp_count_bits(&p);

       /* truncate down to byte size, may be all that's needed */
       if ( (CYASSL_BIT_SIZE * inlen) > orderBits)
           inlen = (orderBits + CYASSL_BIT_SIZE - 1)/CYASSL_BIT_SIZE;
       err = mp_read_unsigned_bin(&e, (byte*)in, inlen);

       /* may still need bit truncation too */
       if (err == MP_OKAY && (CYASSL_BIT_SIZE * inlen) > orderBits)
           mp_rshb(&e, CYASSL_BIT_SIZE - (orderBits & 0x7));
   }

   /* make up a key and export the public copy */
   if (err == MP_OKAY) {
       ecc_key pubkey;
       ecc_init(&pubkey);
       for (;;) {
           err = ecc_make_key_ex(rng, &pubkey, key->dp);
           if (err != MP_OKAY) break;

           /* find r = x1 mod n */
           err = mp_mod(&pubkey.pubkey.x, &p, &r);
           if (err != MP_OKAY) break;

           if (mp_iszero(&r) == MP_YES)
               ecc_free(&pubkey);
           else { 
               /* find s = (e + xr)/k */
               err = mp_invmod(&pubkey.k, &p, &pubkey.k);
               if (err != MP_OKAY) break;

               err = mp_mulmod(&key->k, &r, &p, &s);   /* s = xr */
               if (err != MP_OKAY) break;
           
               err = mp_add(&e, &s, &s);               /* s = e +  xr */
               if (err != MP_OKAY) break;

               err = mp_mod(&s, &p, &s);               /* s = e +  xr */
               if (err != MP_OKAY) break;

               err = mp_mulmod(&s, &pubkey.k, &p, &s); /* s = (e + xr)/k */
               if (err != MP_OKAY) break;

               ecc_free(&pubkey);
               if (mp_iszero(&s) == MP_NO)
                   break;
            }
       }
       ecc_free(&pubkey);
   }

   /* store as SEQUENCE { r, s -- integer } */
   if (err == MP_OKAY)
       err = StoreECC_DSA_Sig(out, outlen, &r, &s);

   mp_clear(&r);
   mp_clear(&s);
   mp_clear(&p);
   mp_clear(&e);

   return err;
}


/**
  Free an ECC key from memory
  key   The key you wish to free
*/
void ecc_free(ecc_key* key)
{
   if (key == NULL)
       return;

   mp_clear(&key->pubkey.x);
   mp_clear(&key->pubkey.y);
   mp_clear(&key->pubkey.z);
   mp_clear(&key->k);
}


#ifdef USE_FAST_MATH
    #define GEN_MEM_ERR FP_MEM
#else
    #define GEN_MEM_ERR MP_MEM
#endif

#ifdef ECC_SHAMIR

/** Computes kA*A + kB*B = C using Shamir's Trick
  A        First point to multiply
  kA       What to multiple A by
  B        Second point to multiply
  kB       What to multiple B by
  C        [out] Destination point (can overlap with A or B)
  modulus  Modulus for curve 
  return MP_OKAY on success
*/
#ifdef FP_ECC
static int normal_ecc_mul2add(ecc_point* A, mp_int* kA,
                             ecc_point* B, mp_int* kB,
                             ecc_point* C, mp_int* modulus)
#else
static int ecc_mul2add(ecc_point* A, mp_int* kA,
                    ecc_point* B, mp_int* kB,
                    ecc_point* C, mp_int* modulus)
#endif
{
  ecc_point*     precomp[16];
  unsigned       bitbufA, bitbufB, lenA, lenB, len, x, y, nA, nB, nibble;
  unsigned char* tA;
  unsigned char* tB;
  int            err = MP_OKAY, first;
  int            muInit    = 0;
  int            tableInit = 0;
  mp_digit mp;
  mp_int   mu;
 
  /* argchks */
  if (A == NULL || kA == NULL || B == NULL || kB == NULL || C == NULL || 
                   modulus == NULL)
    return ECC_BAD_ARG_E;


  /* allocate memory */
  tA = (unsigned char*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  if (tA == NULL) {
     return GEN_MEM_ERR;
  }
  tB = (unsigned char*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  if (tB == NULL) {
     XFREE(tA, NULL, DYNAMIC_TYPE_TMP_BUFFER);
     return GEN_MEM_ERR;
  }
  XMEMSET(tA, 0, ECC_BUFSIZE);
  XMEMSET(tB, 0, ECC_BUFSIZE);

  /* get sizes */
  lenA = mp_unsigned_bin_size(kA);
  lenB = mp_unsigned_bin_size(kB);
  len  = MAX(lenA, lenB);

  /* sanity check */
  if ((lenA > ECC_BUFSIZE) || (lenB > ECC_BUFSIZE)) {
     err = BAD_FUNC_ARG;
  }

  if (err == MP_OKAY) {
    /* extract and justify kA */
    err = mp_to_unsigned_bin(kA, (len - lenA) + tA);

    /* extract and justify kB */
    if (err == MP_OKAY)
        err = mp_to_unsigned_bin(kB, (len - lenB) + tB);

    /* allocate the table */
    if (err == MP_OKAY) {
        for (x = 0; x < 16; x++) {
            precomp[x] = ecc_new_point();
            if (precomp[x] == NULL) {
                for (y = 0; y < x; ++y) {
                    ecc_del_point(precomp[y]);
                }
                err = GEN_MEM_ERR;
                break;
            }
        }
    }
  }

  if (err == MP_OKAY)
    tableInit = 1;

  if (err == MP_OKAY)
   /* init montgomery reduction */
   err = mp_montgomery_setup(modulus, &mp);

  if (err == MP_OKAY)
    err = mp_init(&mu);
  if (err == MP_OKAY)
    muInit = 1;

  if (err == MP_OKAY)
    err = mp_montgomery_calc_normalization(&mu, modulus);

  if (err == MP_OKAY)
    /* copy ones ... */
    err = mp_mulmod(&A->x, &mu, modulus, &precomp[1]->x);

  if (err == MP_OKAY)
    err = mp_mulmod(&A->y, &mu, modulus, &precomp[1]->y);
  if (err == MP_OKAY)
    err = mp_mulmod(&A->z, &mu, modulus, &precomp[1]->z);

  if (err == MP_OKAY)
    err = mp_mulmod(&B->x, &mu, modulus, &precomp[1<<2]->x);
  if (err == MP_OKAY)
    err = mp_mulmod(&B->y, &mu, modulus, &precomp[1<<2]->y);
  if (err == MP_OKAY)
    err = mp_mulmod(&B->z, &mu, modulus, &precomp[1<<2]->z);

  if (err == MP_OKAY)
    /* precomp [i,0](A + B) table */
    err = ecc_projective_dbl_point(precomp[1], precomp[2], modulus, &mp);

  if (err == MP_OKAY)
    err = ecc_projective_add_point(precomp[1], precomp[2], precomp[3],
                                   modulus, &mp);
  if (err == MP_OKAY)
    /* precomp [0,i](A + B) table */
    err = ecc_projective_dbl_point(precomp[1<<2], precomp[2<<2], modulus, &mp);

  if (err == MP_OKAY)
    err = ecc_projective_add_point(precomp[1<<2], precomp[2<<2], precomp[3<<2],
                                   modulus, &mp);

  if (err == MP_OKAY) {
    /* precomp [i,j](A + B) table (i != 0, j != 0) */
    for (x = 1; x < 4; x++) {
        for (y = 1; y < 4; y++) {
            if (err == MP_OKAY)
                err = ecc_projective_add_point(precomp[x], precomp[(y<<2)],
                                               precomp[x+(y<<2)], modulus, &mp);
        }
    } 
  }  

  if (err == MP_OKAY) {
    nibble  = 3;
    first   = 1;
    bitbufA = tA[0];
    bitbufB = tB[0];

    /* for every byte of the multiplicands */
    for (x = -1;; ) {
        /* grab a nibble */
        if (++nibble == 4) {
            ++x; if (x == len) break;
            bitbufA = tA[x];
            bitbufB = tB[x];
            nibble  = 0;
        }

        /* extract two bits from both, shift/update */
        nA = (bitbufA >> 6) & 0x03;
        nB = (bitbufB >> 6) & 0x03;
        bitbufA = (bitbufA << 2) & 0xFF;   
        bitbufB = (bitbufB << 2) & 0xFF;   

        /* if both zero, if first, continue */
        if ((nA == 0) && (nB == 0) && (first == 1)) {
            continue;
        }

        /* double twice, only if this isn't the first */
        if (first == 0) {
            /* double twice */
            if (err == MP_OKAY)
                err = ecc_projective_dbl_point(C, C, modulus, &mp);
            if (err == MP_OKAY)
                err = ecc_projective_dbl_point(C, C, modulus, &mp);
            else
                break;
        }

        /* if not both zero */
        if ((nA != 0) || (nB != 0)) {
            if (first == 1) {
                /* if first, copy from table */
                first = 0;
                if (err == MP_OKAY)
                    err = mp_copy(&precomp[nA + (nB<<2)]->x, &C->x);

                if (err == MP_OKAY)
                    err = mp_copy(&precomp[nA + (nB<<2)]->y, &C->y);

                if (err == MP_OKAY)
                    err = mp_copy(&precomp[nA + (nB<<2)]->z, &C->z);
                else
                    break;
            } else {
                /* if not first, add from table */
                if (err == MP_OKAY)
                    err = ecc_projective_add_point(C, precomp[nA + (nB<<2)], C,
                                                   modulus, &mp);
                else
                    break;
            }
        }
    }
  }

  if (err == MP_OKAY)
    /* reduce to affine */
    err = ecc_map(C, modulus, &mp);

  /* clean up */
  if (muInit)
    mp_clear(&mu);

  if (tableInit) {
    for (x = 0; x < 16; x++) {
       ecc_del_point(precomp[x]);
    }
  }
#ifdef ECC_CLEAN_STACK
   XMEMSET(tA, 0, ECC_BUFSIZE);
   XMEMSET(tB, 0, ECC_BUFSIZE);
#endif
   XFREE(tA, NULL, DYNAMIC_TYPE_TMP_BUFFER);
   XFREE(tB, NULL, DYNAMIC_TYPE_TMP_BUFFER);

   return err;
}


#endif /* ECC_SHAMIR */



/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
   Verify an ECC signature
   sig         The signature to verify
   siglen      The length of the signature (octets)
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   stat        Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key)
{
   ecc_point    *mG, *mQ;
   mp_int        r;
   mp_int        s;
   mp_int        v;
   mp_int        w;
   mp_int        u1;
   mp_int        u2;
   mp_int        e;
   mp_int        p;
   mp_int        m;
   int           err;

   if (sig == NULL || hash == NULL || stat == NULL || key == NULL)
       return ECC_BAD_ARG_E; 

   /* default to invalid signature */
   *stat = 0;

   /* is the IDX valid ?  */
   if (ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   /* allocate ints */
   if ((err = mp_init_multi(&v, &w, &u1, &u2, &p, &e)) != MP_OKAY) {
      return MEMORY_E;
   }

   if ((err = mp_init(&m)) != MP_OKAY) {
      mp_clear(&v);
      mp_clear(&w);
      mp_clear(&u1);
      mp_clear(&u2);
      mp_clear(&p);
      mp_clear(&e);
      return MEMORY_E;
   }

   /* allocate points */
   mG = ecc_new_point();
   mQ = ecc_new_point();
   if (mQ  == NULL || mG == NULL)
      err = MEMORY_E;

   /* Note, DecodeECC_DSA_Sig() calls mp_init() on r and s.
    * If either of those don't allocate correctly, none of
    * the rest of this function will execute, and everything
    * gets cleaned up at the end. */
   XMEMSET(&r, 0, sizeof(r));
   XMEMSET(&s, 0, sizeof(s));
   if (err == MP_OKAY) 
       err = DecodeECC_DSA_Sig(sig, siglen, &r, &s);

   /* get the order */
   if (err == MP_OKAY)
       err = mp_read_radix(&p, (char *)key->dp->order, 16);

   /* get the modulus */
   if (err == MP_OKAY)
       err = mp_read_radix(&m, (char *)key->dp->prime, 16);

   /* check for zero */
   if (err == MP_OKAY) {
       if (mp_iszero(&r) || mp_iszero(&s) || mp_cmp(&r, &p) != MP_LT ||
                                             mp_cmp(&s, &p) != MP_LT)
           err = MP_ZERO_E; 
   }
   /* read hash */
   if (err == MP_OKAY) {
       /* we may need to truncate if hash is longer than key size */
       unsigned int orderBits = mp_count_bits(&p);

       /* truncate down to byte size, may be all that's needed */
       if ( (CYASSL_BIT_SIZE * hashlen) > orderBits)
           hashlen = (orderBits + CYASSL_BIT_SIZE - 1)/CYASSL_BIT_SIZE;
       err = mp_read_unsigned_bin(&e, hash, hashlen);

       /* may still need bit truncation too */
       if (err == MP_OKAY && (CYASSL_BIT_SIZE * hashlen) > orderBits)
           mp_rshb(&e, CYASSL_BIT_SIZE - (orderBits & 0x7));
   }

   /*  w  = s^-1 mod n */
   if (err == MP_OKAY)
       err = mp_invmod(&s, &p, &w);

   /* u1 = ew */
   if (err == MP_OKAY)
       err = mp_mulmod(&e, &w, &p, &u1);

   /* u2 = rw */
   if (err == MP_OKAY)
       err = mp_mulmod(&r, &w, &p, &u2);

   /* find mG and mQ */
   if (err == MP_OKAY)
       err = mp_read_radix(&mG->x, (char *)key->dp->Gx, 16);

   if (err == MP_OKAY)
       err = mp_read_radix(&mG->y, (char *)key->dp->Gy, 16);
   if (err == MP_OKAY)
       mp_set(&mG->z, 1);

   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.x, &mQ->x);
   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.y, &mQ->y);
   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.z, &mQ->z);

#ifndef ECC_SHAMIR
    {
       mp_digit      mp;

       /* compute u1*mG + u2*mQ = mG */
       if (err == MP_OKAY)
           err = ecc_mulmod(&u1, mG, mG, &m, 0);
       if (err == MP_OKAY)
           err = ecc_mulmod(&u2, mQ, mQ, &m, 0);
  
       /* find the montgomery mp */
       if (err == MP_OKAY)
           err = mp_montgomery_setup(&m, &mp);

       /* add them */
       if (err == MP_OKAY)
           err = ecc_projective_add_point(mQ, mG, mG, &m, &mp);
   
       /* reduce */
       if (err == MP_OKAY)
           err = ecc_map(mG, &m, &mp);
    }
#else
       /* use Shamir's trick to compute u1*mG + u2*mQ using half the doubles */
       if (err == MP_OKAY)
           err = ecc_mul2add(mG, &u1, mQ, &u2, mG, &m);
#endif /* ECC_SHAMIR */ 

   /* v = X_x1 mod n */
   if (err == MP_OKAY)
       err = mp_mod(&mG->x, &p, &v);

   /* does v == r */
   if (err == MP_OKAY) {
       if (mp_cmp(&v, &r) == MP_EQ)
           *stat = 1;
   }

   ecc_del_point(mG);
   ecc_del_point(mQ);

   mp_clear(&r);
   mp_clear(&s);
   mp_clear(&v);
   mp_clear(&w);
   mp_clear(&u1);
   mp_clear(&u2);
   mp_clear(&p);
   mp_clear(&e);
   mp_clear(&m);

   return err;
}


/* export public ECC key in ANSI X9.63 format */
int ecc_export_x963(ecc_key* key, byte* out, word32* outLen)
{
#ifdef CYASSL_SMALL_STACK
   byte*  buf;
#else
   byte   buf[ECC_BUFSIZE];
#endif
   word32 numlen;
   int    ret = MP_OKAY;

   /* return length needed only */
   if (key != NULL && out == NULL && outLen != NULL) {
      numlen = key->dp->size;
      *outLen = 1 + 2*numlen;
      return LENGTH_ONLY_E;
   }

   if (key == NULL || out == NULL || outLen == NULL)
      return ECC_BAD_ARG_E;

   if (ecc_is_valid_idx(key->idx) == 0) {
      return ECC_BAD_ARG_E;
   }
   numlen = key->dp->size;

   if (*outLen < (1 + 2*numlen)) {
      *outLen = 1 + 2*numlen;
      return BUFFER_E;
   }

   /* store byte 0x04 */
   out[0] = 0x04;

#ifdef CYASSL_SMALL_STACK
   buf = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
   if (buf == NULL)
      return MEMORY_E;
#endif

   do {
      /* pad and store x */
      XMEMSET(buf, 0, ECC_BUFSIZE);
      ret = mp_to_unsigned_bin(&key->pubkey.x,
                         buf + (numlen - mp_unsigned_bin_size(&key->pubkey.x)));
      if (ret != MP_OKAY)
         break;
      XMEMCPY(out+1, buf, numlen);

      /* pad and store y */
      XMEMSET(buf, 0, ECC_BUFSIZE);
      ret = mp_to_unsigned_bin(&key->pubkey.y,
                         buf + (numlen - mp_unsigned_bin_size(&key->pubkey.y)));
      if (ret != MP_OKAY)
         break;
      XMEMCPY(out+1+numlen, buf, numlen);

      *outLen = 1 + 2*numlen;
   } while (0);

#ifdef CYASSL_SMALL_STACK
   XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

   return ret;
}


/* export public ECC key in ANSI X9.63 format, extended with
 * compression option */
int ecc_export_x963_ex(ecc_key* key, byte* out, word32* outLen, int compressed)
{
    if (compressed == 0)
        return ecc_export_x963(key, out, outLen);
#ifdef HAVE_COMP_KEY
    else
        return ecc_export_x963_compressed(key, out, outLen);
#endif

    return NOT_COMPILED_IN;
}


/* import public ECC key in ANSI X9.63 format */
int ecc_import_x963(const byte* in, word32 inLen, ecc_key* key)
{
   int x, err;
   int compressed = 0;
   
   if (in == NULL || key == NULL)
       return ECC_BAD_ARG_E;

   /* must be odd */
   if ((inLen & 1) == 0) {
      return ECC_BAD_ARG_E;
   }

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                     NULL, NULL) != MP_OKAY) {
      return MEMORY_E;
   }
   err = MP_OKAY;

   /* check for 4, 2, or 3 */
   if (in[0] != 0x04 && in[0] != 0x02 && in[0] != 0x03) {
      err = ASN_PARSE_E;
   }

   if (in[0] == 0x02 || in[0] == 0x03) {
#ifdef HAVE_COMP_KEY
       compressed = 1;
#else
       err = NOT_COMPILED_IN;
#endif
   }

   if (err == MP_OKAY) {
      /* determine the idx */

      if (compressed)
          inLen = (inLen-1)*2 + 1;  /* used uncompressed len */

      for (x = 0; ecc_sets[x].size != 0; x++) {
         if ((unsigned)ecc_sets[x].size >= ((inLen-1)>>1)) {
            break;
         }
      }
      if (ecc_sets[x].size == 0) {
         err = ASN_PARSE_E;
      } else {
          /* set the idx */
          key->idx  = x;
          key->dp = &ecc_sets[x];
          key->type = ECC_PUBLICKEY;
      }
   }

   /* read data */
   if (err == MP_OKAY)
       err = mp_read_unsigned_bin(&key->pubkey.x, (byte*)in+1, (inLen-1)>>1);

#ifdef HAVE_COMP_KEY
   if (err == MP_OKAY && compressed == 1) {   /* build y */
        mp_int t1, t2, prime, a, b;

        if (mp_init_multi(&t1, &t2, &prime, &a, &b, NULL) != MP_OKAY)
            err = MEMORY_E;

        /* load prime */
        if (err == MP_OKAY)
            err = mp_read_radix(&prime, (char *)key->dp->prime, 16);

        /* load a */
        if (err == MP_OKAY)
            err = mp_read_radix(&a, (char *)key->dp->Af, 16);

        /* load b */
        if (err == MP_OKAY)
            err = mp_read_radix(&b, (char *)key->dp->Bf, 16);

        /* compute x^3 */
        if (err == MP_OKAY)
            err = mp_sqr(&key->pubkey.x, &t1);

        if (err == MP_OKAY)
            err = mp_mulmod(&t1, &key->pubkey.x, &prime, &t1);

        /* compute x^3 + a*x */
        if (err == MP_OKAY)
            err = mp_mulmod(&a, &key->pubkey.x, &prime, &t2);

        if (err == MP_OKAY)
            err = mp_add(&t1, &t2, &t1);

        /* compute x^3 + a*x + b */
        if (err == MP_OKAY)
            err = mp_add(&t1, &b, &t1);

        /* compute sqrt(x^3 + a*x + b) */
        if (err == MP_OKAY)
            err = mp_sqrtmod_prime(&t1, &prime, &t2);

        /* adjust y */
        if (err == MP_OKAY) {
            if ((mp_isodd(&t2) && in[0] == 0x03) ||
               (!mp_isodd(&t2) && in[0] == 0x02)) {
                err = mp_mod(&t2, &prime, &key->pubkey.y);
            }
            else {
                err = mp_submod(&prime, &t2, &prime, &key->pubkey.y);
            }
        }

        mp_clear(&a);
        mp_clear(&b);
        mp_clear(&prime);
        mp_clear(&t2);
        mp_clear(&t1);
   }
#endif

   if (err == MP_OKAY && compressed == 0)
       err = mp_read_unsigned_bin(&key->pubkey.y, (byte*)in+1+((inLen-1)>>1),
                                  (inLen-1)>>1);
   if (err == MP_OKAY)
       mp_set(&key->pubkey.z, 1);

   if (err != MP_OKAY) {
       mp_clear(&key->pubkey.x);
       mp_clear(&key->pubkey.y);
       mp_clear(&key->pubkey.z);
       mp_clear(&key->k);
   }

   return err;
}


/* export ecc private key only raw, outLen is in/out size 
   return MP_OKAY on success */
int ecc_export_private_only(ecc_key* key, byte* out, word32* outLen)
{
   word32 numlen;

   if (key == NULL || out == NULL || outLen == NULL)
       return ECC_BAD_ARG_E;

   if (ecc_is_valid_idx(key->idx) == 0) {
      return ECC_BAD_ARG_E;
   }
   numlen = key->dp->size;

   if (*outLen < numlen) {
      *outLen = numlen;
      return BUFFER_E;
   }
   *outLen = numlen; 
   XMEMSET(out, 0, *outLen);
   return mp_to_unsigned_bin(&key->k, out + (numlen -
                                             mp_unsigned_bin_size(&key->k)));
}


/* ecc private key import, public key in ANSI X9.63 format, private raw */
int ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
                           word32 pubSz, ecc_key* key)
{
    int ret = ecc_import_x963(pub, pubSz, key);
    if (ret != 0)
        return ret;

    key->type = ECC_PRIVATEKEY;

    return mp_read_unsigned_bin(&key->k, priv, privSz);
}

/**
   Convert ECC R,S to signature
   r       R component of signature
   s       S component of signature
   out     DER-encoded ECDSA signature
   outlen  [in/out] output buffer size, output signature size
   return  MP_OKAY on success
*/
int ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen)
{
    int err;
    mp_int rtmp;
    mp_int stmp;

    if (r == NULL || s == NULL || out == NULL || outlen == NULL)
        return ECC_BAD_ARG_E;

    err = mp_init_multi(&rtmp, &stmp, NULL, NULL, NULL, NULL);
    if (err != MP_OKAY)
        return err;

    err = mp_read_radix(&rtmp, r, 16);
    if (err == MP_OKAY)
        err = mp_read_radix(&stmp, s, 16);

    /* convert mp_ints to ECDSA sig, initializes rtmp and stmp internally */
    if (err == MP_OKAY)
        err = StoreECC_DSA_Sig(out, outlen, &rtmp, &stmp);

    if (err == MP_OKAY) {
        if (mp_iszero(&rtmp) || mp_iszero(&stmp))
            err = MP_ZERO_E;
    }

    mp_clear(&rtmp);
    mp_clear(&stmp);

    return err;
}

/**
   Import raw ECC key
   key       The destination ecc_key structure
   qx        x component of base point, as ASCII hex string
   qy        y component of base point, as ASCII hex string
   d         private key, as ASCII hex string
   curveName ECC curve name, from ecc_sets[]
   return    MP_OKAY on success
*/
int ecc_import_raw(ecc_key* key, const char* qx, const char* qy,
                   const char* d, const char* curveName)
{
    int err, x;

    if (key == NULL || qx == NULL || qy == NULL || d == NULL ||
        curveName == NULL)
        return ECC_BAD_ARG_E;

    /* init key */
    if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                      NULL, NULL) != MP_OKAY) {
        return MEMORY_E;
    }
    err = MP_OKAY;

    /* read Qx */
    if (err == MP_OKAY)
        err = mp_read_radix(&key->pubkey.x, qx, 16);

    /* read Qy */
    if (err == MP_OKAY)
        err = mp_read_radix(&key->pubkey.y, qy, 16);

    if (err == MP_OKAY)
        mp_set(&key->pubkey.z, 1);

    /* read and set the curve */
    if (err == MP_OKAY) {
        for (x = 0; ecc_sets[x].size != 0; x++) {
            if (XSTRNCMP(ecc_sets[x].name, curveName,
                         XSTRLEN(curveName)) == 0) {
                break;
            }
        }
        if (ecc_sets[x].size == 0) {
            err = ASN_PARSE_E;
        } else {
            /* set the curve */
            key->idx = x;
            key->dp = &ecc_sets[x];
            key->type = ECC_PUBLICKEY;
        }
    }

    /* import private key */
    if (err == MP_OKAY) {
        key->type = ECC_PRIVATEKEY;
        err = mp_read_radix(&key->k, d, 16);
    }

    if (err != MP_OKAY) {
        mp_clear(&key->pubkey.x);
        mp_clear(&key->pubkey.y);
        mp_clear(&key->pubkey.z);
        mp_clear(&key->k);
    }

    return err;
}


/* key size in octets */
int ecc_size(ecc_key* key)
{
    if (key == NULL) return 0;

    return key->dp->size;
}


/* worst case estimate, check actual return from ecc_sign_hash for actual value
   of signature size in octets */
int ecc_sig_size(ecc_key* key)
{
    int sz = ecc_size(key);
    if (sz < 0)
        return sz;

    return sz * 2 + SIG_HEADER_SZ + 4;  /* (4) worst case estimate */
}


#ifdef FP_ECC

/* fixed point ECC cache */
/* number of entries in the cache */
#ifndef FP_ENTRIES
    #define FP_ENTRIES 16
#endif

/* number of bits in LUT */
#ifndef FP_LUT
    #define FP_LUT     8U
#endif

#ifdef ECC_SHAMIR
    /* Sharmir requires a bigger LUT, TAO */
    #if (FP_LUT > 12) || (FP_LUT < 4)
        #error FP_LUT must be between 4 and 12 inclusively
    #endif
#else
    #if (FP_LUT > 12) || (FP_LUT < 2)
        #error FP_LUT must be between 2 and 12 inclusively
    #endif
#endif


/** Our FP cache */
typedef struct {
   ecc_point* g;               /* cached COPY of base point */
   ecc_point* LUT[1U<<FP_LUT]; /* fixed point lookup */ 
   mp_int     mu;              /* copy of the montgomery constant */
   int        lru_count;       /* amount of times this entry has been used */
   int        lock;            /* flag to indicate cache eviction */
                               /* permitted (0) or not (1) */
} fp_cache_t;

/* if HAVE_THREAD_LS this cache is per thread, no locking needed */
static THREAD_LS_T fp_cache_t fp_cache[FP_ENTRIES];

#ifndef HAVE_THREAD_LS
    static volatile int initMutex = 0;  /* prevent multiple mutex inits */
    static CyaSSL_Mutex ecc_fp_lock;
#endif /* HAVE_THREAD_LS */

/* simple table to help direct the generation of the LUT */
static const struct {
   int ham, terma, termb;
} lut_orders[] = {
   { 0, 0, 0 }, { 1, 0, 0 }, { 1, 0, 0 }, { 2, 1, 2 }, { 1, 0, 0 }, { 2, 1, 4 }, { 2, 2, 4 }, { 3, 3, 4 }, 
   { 1, 0, 0 }, { 2, 1, 8 }, { 2, 2, 8 }, { 3, 3, 8 }, { 2, 4, 8 }, { 3, 5, 8 }, { 3, 6, 8 }, { 4, 7, 8 }, 
   { 1, 0, 0 }, { 2, 1, 16 }, { 2, 2, 16 }, { 3, 3, 16 }, { 2, 4, 16 }, { 3, 5, 16 }, { 3, 6, 16 }, { 4, 7, 16 }, 
   { 2, 8, 16 }, { 3, 9, 16 }, { 3, 10, 16 }, { 4, 11, 16 }, { 3, 12, 16 }, { 4, 13, 16 }, { 4, 14, 16 }, { 5, 15, 16 }, 
   { 1, 0, 0 }, { 2, 1, 32 }, { 2, 2, 32 }, { 3, 3, 32 }, { 2, 4, 32 }, { 3, 5, 32 }, { 3, 6, 32 }, { 4, 7, 32 }, 
   { 2, 8, 32 }, { 3, 9, 32 }, { 3, 10, 32 }, { 4, 11, 32 }, { 3, 12, 32 }, { 4, 13, 32 }, { 4, 14, 32 }, { 5, 15, 32 }, 
   { 2, 16, 32 }, { 3, 17, 32 }, { 3, 18, 32 }, { 4, 19, 32 }, { 3, 20, 32 }, { 4, 21, 32 }, { 4, 22, 32 }, { 5, 23, 32 }, 
   { 3, 24, 32 }, { 4, 25, 32 }, { 4, 26, 32 }, { 5, 27, 32 }, { 4, 28, 32 }, { 5, 29, 32 }, { 5, 30, 32 }, { 6, 31, 32 }, 
#if FP_LUT > 6
   { 1, 0, 0 }, { 2, 1, 64 }, { 2, 2, 64 }, { 3, 3, 64 }, { 2, 4, 64 }, { 3, 5, 64 }, { 3, 6, 64 }, { 4, 7, 64 }, 
   { 2, 8, 64 }, { 3, 9, 64 }, { 3, 10, 64 }, { 4, 11, 64 }, { 3, 12, 64 }, { 4, 13, 64 }, { 4, 14, 64 }, { 5, 15, 64 }, 
   { 2, 16, 64 }, { 3, 17, 64 }, { 3, 18, 64 }, { 4, 19, 64 }, { 3, 20, 64 }, { 4, 21, 64 }, { 4, 22, 64 }, { 5, 23, 64 }, 
   { 3, 24, 64 }, { 4, 25, 64 }, { 4, 26, 64 }, { 5, 27, 64 }, { 4, 28, 64 }, { 5, 29, 64 }, { 5, 30, 64 }, { 6, 31, 64 }, 
   { 2, 32, 64 }, { 3, 33, 64 }, { 3, 34, 64 }, { 4, 35, 64 }, { 3, 36, 64 }, { 4, 37, 64 }, { 4, 38, 64 }, { 5, 39, 64 }, 
   { 3, 40, 64 }, { 4, 41, 64 }, { 4, 42, 64 }, { 5, 43, 64 }, { 4, 44, 64 }, { 5, 45, 64 }, { 5, 46, 64 }, { 6, 47, 64 }, 
   { 3, 48, 64 }, { 4, 49, 64 }, { 4, 50, 64 }, { 5, 51, 64 }, { 4, 52, 64 }, { 5, 53, 64 }, { 5, 54, 64 }, { 6, 55, 64 }, 
   { 4, 56, 64 }, { 5, 57, 64 }, { 5, 58, 64 }, { 6, 59, 64 }, { 5, 60, 64 }, { 6, 61, 64 }, { 6, 62, 64 }, { 7, 63, 64 }, 
#if FP_LUT > 7
   { 1, 0, 0 }, { 2, 1, 128 }, { 2, 2, 128 }, { 3, 3, 128 }, { 2, 4, 128 }, { 3, 5, 128 }, { 3, 6, 128 }, { 4, 7, 128 }, 
   { 2, 8, 128 }, { 3, 9, 128 }, { 3, 10, 128 }, { 4, 11, 128 }, { 3, 12, 128 }, { 4, 13, 128 }, { 4, 14, 128 }, { 5, 15, 128 }, 
   { 2, 16, 128 }, { 3, 17, 128 }, { 3, 18, 128 }, { 4, 19, 128 }, { 3, 20, 128 }, { 4, 21, 128 }, { 4, 22, 128 }, { 5, 23, 128 }, 
   { 3, 24, 128 }, { 4, 25, 128 }, { 4, 26, 128 }, { 5, 27, 128 }, { 4, 28, 128 }, { 5, 29, 128 }, { 5, 30, 128 }, { 6, 31, 128 }, 
   { 2, 32, 128 }, { 3, 33, 128 }, { 3, 34, 128 }, { 4, 35, 128 }, { 3, 36, 128 }, { 4, 37, 128 }, { 4, 38, 128 }, { 5, 39, 128 }, 
   { 3, 40, 128 }, { 4, 41, 128 }, { 4, 42, 128 }, { 5, 43, 128 }, { 4, 44, 128 }, { 5, 45, 128 }, { 5, 46, 128 }, { 6, 47, 128 }, 
   { 3, 48, 128 }, { 4, 49, 128 }, { 4, 50, 128 }, { 5, 51, 128 }, { 4, 52, 128 }, { 5, 53, 128 }, { 5, 54, 128 }, { 6, 55, 128 }, 
   { 4, 56, 128 }, { 5, 57, 128 }, { 5, 58, 128 }, { 6, 59, 128 }, { 5, 60, 128 }, { 6, 61, 128 }, { 6, 62, 128 }, { 7, 63, 128 }, 
   { 2, 64, 128 }, { 3, 65, 128 }, { 3, 66, 128 }, { 4, 67, 128 }, { 3, 68, 128 }, { 4, 69, 128 }, { 4, 70, 128 }, { 5, 71, 128 }, 
   { 3, 72, 128 }, { 4, 73, 128 }, { 4, 74, 128 }, { 5, 75, 128 }, { 4, 76, 128 }, { 5, 77, 128 }, { 5, 78, 128 }, { 6, 79, 128 }, 
   { 3, 80, 128 }, { 4, 81, 128 }, { 4, 82, 128 }, { 5, 83, 128 }, { 4, 84, 128 }, { 5, 85, 128 }, { 5, 86, 128 }, { 6, 87, 128 }, 
   { 4, 88, 128 }, { 5, 89, 128 }, { 5, 90, 128 }, { 6, 91, 128 }, { 5, 92, 128 }, { 6, 93, 128 }, { 6, 94, 128 }, { 7, 95, 128 }, 
   { 3, 96, 128 }, { 4, 97, 128 }, { 4, 98, 128 }, { 5, 99, 128 }, { 4, 100, 128 }, { 5, 101, 128 }, { 5, 102, 128 }, { 6, 103, 128 }, 
   { 4, 104, 128 }, { 5, 105, 128 }, { 5, 106, 128 }, { 6, 107, 128 }, { 5, 108, 128 }, { 6, 109, 128 }, { 6, 110, 128 }, { 7, 111, 128 }, 
   { 4, 112, 128 }, { 5, 113, 128 }, { 5, 114, 128 }, { 6, 115, 128 }, { 5, 116, 128 }, { 6, 117, 128 }, { 6, 118, 128 }, { 7, 119, 128 }, 
   { 5, 120, 128 }, { 6, 121, 128 }, { 6, 122, 128 }, { 7, 123, 128 }, { 6, 124, 128 }, { 7, 125, 128 }, { 7, 126, 128 }, { 8, 127, 128 }, 
#if FP_LUT > 8
   { 1, 0, 0 }, { 2, 1, 256 }, { 2, 2, 256 }, { 3, 3, 256 }, { 2, 4, 256 }, { 3, 5, 256 }, { 3, 6, 256 }, { 4, 7, 256 }, 
   { 2, 8, 256 }, { 3, 9, 256 }, { 3, 10, 256 }, { 4, 11, 256 }, { 3, 12, 256 }, { 4, 13, 256 }, { 4, 14, 256 }, { 5, 15, 256 }, 
   { 2, 16, 256 }, { 3, 17, 256 }, { 3, 18, 256 }, { 4, 19, 256 }, { 3, 20, 256 }, { 4, 21, 256 }, { 4, 22, 256 }, { 5, 23, 256 }, 
   { 3, 24, 256 }, { 4, 25, 256 }, { 4, 26, 256 }, { 5, 27, 256 }, { 4, 28, 256 }, { 5, 29, 256 }, { 5, 30, 256 }, { 6, 31, 256 }, 
   { 2, 32, 256 }, { 3, 33, 256 }, { 3, 34, 256 }, { 4, 35, 256 }, { 3, 36, 256 }, { 4, 37, 256 }, { 4, 38, 256 }, { 5, 39, 256 }, 
   { 3, 40, 256 }, { 4, 41, 256 }, { 4, 42, 256 }, { 5, 43, 256 }, { 4, 44, 256 }, { 5, 45, 256 }, { 5, 46, 256 }, { 6, 47, 256 }, 
   { 3, 48, 256 }, { 4, 49, 256 }, { 4, 50, 256 }, { 5, 51, 256 }, { 4, 52, 256 }, { 5, 53, 256 }, { 5, 54, 256 }, { 6, 55, 256 }, 
   { 4, 56, 256 }, { 5, 57, 256 }, { 5, 58, 256 }, { 6, 59, 256 }, { 5, 60, 256 }, { 6, 61, 256 }, { 6, 62, 256 }, { 7, 63, 256 }, 
   { 2, 64, 256 }, { 3, 65, 256 }, { 3, 66, 256 }, { 4, 67, 256 }, { 3, 68, 256 }, { 4, 69, 256 }, { 4, 70, 256 }, { 5, 71, 256 }, 
   { 3, 72, 256 }, { 4, 73, 256 }, { 4, 74, 256 }, { 5, 75, 256 }, { 4, 76, 256 }, { 5, 77, 256 }, { 5, 78, 256 }, { 6, 79, 256 }, 
   { 3, 80, 256 }, { 4, 81, 256 }, { 4, 82, 256 }, { 5, 83, 256 }, { 4, 84, 256 }, { 5, 85, 256 }, { 5, 86, 256 }, { 6, 87, 256 }, 
   { 4, 88, 256 }, { 5, 89, 256 }, { 5, 90, 256 }, { 6, 91, 256 }, { 5, 92, 256 }, { 6, 93, 256 }, { 6, 94, 256 }, { 7, 95, 256 }, 
   { 3, 96, 256 }, { 4, 97, 256 }, { 4, 98, 256 }, { 5, 99, 256 }, { 4, 100, 256 }, { 5, 101, 256 }, { 5, 102, 256 }, { 6, 103, 256 }, 
   { 4, 104, 256 }, { 5, 105, 256 }, { 5, 106, 256 }, { 6, 107, 256 }, { 5, 108, 256 }, { 6, 109, 256 }, { 6, 110, 256 }, { 7, 111, 256 }, 
   { 4, 112, 256 }, { 5, 113, 256 }, { 5, 114, 256 }, { 6, 115, 256 }, { 5, 116, 256 }, { 6, 117, 256 }, { 6, 118, 256 }, { 7, 119, 256 }, 
   { 5, 120, 256 }, { 6, 121, 256 }, { 6, 122, 256 }, { 7, 123, 256 }, { 6, 124, 256 }, { 7, 125, 256 }, { 7, 126, 256 }, { 8, 127, 256 }, 
   { 2, 128, 256 }, { 3, 129, 256 }, { 3, 130, 256 }, { 4, 131, 256 }, { 3, 132, 256 }, { 4, 133, 256 }, { 4, 134, 256 }, { 5, 135, 256 }, 
   { 3, 136, 256 }, { 4, 137, 256 }, { 4, 138, 256 }, { 5, 139, 256 }, { 4, 140, 256 }, { 5, 141, 256 }, { 5, 142, 256 }, { 6, 143, 256 }, 
   { 3, 144, 256 }, { 4, 145, 256 }, { 4, 146, 256 }, { 5, 147, 256 }, { 4, 148, 256 }, { 5, 149, 256 }, { 5, 150, 256 }, { 6, 151, 256 }, 
   { 4, 152, 256 }, { 5, 153, 256 }, { 5, 154, 256 }, { 6, 155, 256 }, { 5, 156, 256 }, { 6, 157, 256 }, { 6, 158, 256 }, { 7, 159, 256 }, 
   { 3, 160, 256 }, { 4, 161, 256 }, { 4, 162, 256 }, { 5, 163, 256 }, { 4, 164, 256 }, { 5, 165, 256 }, { 5, 166, 256 }, { 6, 167, 256 }, 
   { 4, 168, 256 }, { 5, 169, 256 }, { 5, 170, 256 }, { 6, 171, 256 }, { 5, 172, 256 }, { 6, 173, 256 }, { 6, 174, 256 }, { 7, 175, 256 }, 
   { 4, 176, 256 }, { 5, 177, 256 }, { 5, 178, 256 }, { 6, 179, 256 }, { 5, 180, 256 }, { 6, 181, 256 }, { 6, 182, 256 }, { 7, 183, 256 }, 
   { 5, 184, 256 }, { 6, 185, 256 }, { 6, 186, 256 }, { 7, 187, 256 }, { 6, 188, 256 }, { 7, 189, 256 }, { 7, 190, 256 }, { 8, 191, 256 }, 
   { 3, 192, 256 }, { 4, 193, 256 }, { 4, 194, 256 }, { 5, 195, 256 }, { 4, 196, 256 }, { 5, 197, 256 }, { 5, 198, 256 }, { 6, 199, 256 }, 
   { 4, 200, 256 }, { 5, 201, 256 }, { 5, 202, 256 }, { 6, 203, 256 }, { 5, 204, 256 }, { 6, 205, 256 }, { 6, 206, 256 }, { 7, 207, 256 }, 
   { 4, 208, 256 }, { 5, 209, 256 }, { 5, 210, 256 }, { 6, 211, 256 }, { 5, 212, 256 }, { 6, 213, 256 }, { 6, 214, 256 }, { 7, 215, 256 }, 
   { 5, 216, 256 }, { 6, 217, 256 }, { 6, 218, 256 }, { 7, 219, 256 }, { 6, 220, 256 }, { 7, 221, 256 }, { 7, 222, 256 }, { 8, 223, 256 }, 
   { 4, 224, 256 }, { 5, 225, 256 }, { 5, 226, 256 }, { 6, 227, 256 }, { 5, 228, 256 }, { 6, 229, 256 }, { 6, 230, 256 }, { 7, 231, 256 }, 
   { 5, 232, 256 }, { 6, 233, 256 }, { 6, 234, 256 }, { 7, 235, 256 }, { 6, 236, 256 }, { 7, 237, 256 }, { 7, 238, 256 }, { 8, 239, 256 }, 
   { 5, 240, 256 }, { 6, 241, 256 }, { 6, 242, 256 }, { 7, 243, 256 }, { 6, 244, 256 }, { 7, 245, 256 }, { 7, 246, 256 }, { 8, 247, 256 }, 
   { 6, 248, 256 }, { 7, 249, 256 }, { 7, 250, 256 }, { 8, 251, 256 }, { 7, 252, 256 }, { 8, 253, 256 }, { 8, 254, 256 }, { 9, 255, 256 }, 
#if FP_LUT > 9
   { 1, 0, 0 }, { 2, 1, 512 }, { 2, 2, 512 }, { 3, 3, 512 }, { 2, 4, 512 }, { 3, 5, 512 }, { 3, 6, 512 }, { 4, 7, 512 }, 
   { 2, 8, 512 }, { 3, 9, 512 }, { 3, 10, 512 }, { 4, 11, 512 }, { 3, 12, 512 }, { 4, 13, 512 }, { 4, 14, 512 }, { 5, 15, 512 }, 
   { 2, 16, 512 }, { 3, 17, 512 }, { 3, 18, 512 }, { 4, 19, 512 }, { 3, 20, 512 }, { 4, 21, 512 }, { 4, 22, 512 }, { 5, 23, 512 }, 
   { 3, 24, 512 }, { 4, 25, 512 }, { 4, 26, 512 }, { 5, 27, 512 }, { 4, 28, 512 }, { 5, 29, 512 }, { 5, 30, 512 }, { 6, 31, 512 }, 
   { 2, 32, 512 }, { 3, 33, 512 }, { 3, 34, 512 }, { 4, 35, 512 }, { 3, 36, 512 }, { 4, 37, 512 }, { 4, 38, 512 }, { 5, 39, 512 }, 
   { 3, 40, 512 }, { 4, 41, 512 }, { 4, 42, 512 }, { 5, 43, 512 }, { 4, 44, 512 }, { 5, 45, 512 }, { 5, 46, 512 }, { 6, 47, 512 }, 
   { 3, 48, 512 }, { 4, 49, 512 }, { 4, 50, 512 }, { 5, 51, 512 }, { 4, 52, 512 }, { 5, 53, 512 }, { 5, 54, 512 }, { 6, 55, 512 }, 
   { 4, 56, 512 }, { 5, 57, 512 }, { 5, 58, 512 }, { 6, 59, 512 }, { 5, 60, 512 }, { 6, 61, 512 }, { 6, 62, 512 }, { 7, 63, 512 }, 
   { 2, 64, 512 }, { 3, 65, 512 }, { 3, 66, 512 }, { 4, 67, 512 }, { 3, 68, 512 }, { 4, 69, 512 }, { 4, 70, 512 }, { 5, 71, 512 }, 
   { 3, 72, 512 }, { 4, 73, 512 }, { 4, 74, 512 }, { 5, 75, 512 }, { 4, 76, 512 }, { 5, 77, 512 }, { 5, 78, 512 }, { 6, 79, 512 }, 
   { 3, 80, 512 }, { 4, 81, 512 }, { 4, 82, 512 }, { 5, 83, 512 }, { 4, 84, 512 }, { 5, 85, 512 }, { 5, 86, 512 }, { 6, 87, 512 }, 
   { 4, 88, 512 }, { 5, 89, 512 }, { 5, 90, 512 }, { 6, 91, 512 }, { 5, 92, 512 }, { 6, 93, 512 }, { 6, 94, 512 }, { 7, 95, 512 }, 
   { 3, 96, 512 }, { 4, 97, 512 }, { 4, 98, 512 }, { 5, 99, 512 }, { 4, 100, 512 }, { 5, 101, 512 }, { 5, 102, 512 }, { 6, 103, 512 }, 
   { 4, 104, 512 }, { 5, 105, 512 }, { 5, 106, 512 }, { 6, 107, 512 }, { 5, 108, 512 }, { 6, 109, 512 }, { 6, 110, 512 }, { 7, 111, 512 }, 
   { 4, 112, 512 }, { 5, 113, 512 }, { 5, 114, 512 }, { 6, 115, 512 }, { 5, 116, 512 }, { 6, 117, 512 }, { 6, 118, 512 }, { 7, 119, 512 }, 
   { 5, 120, 512 }, { 6, 121, 512 }, { 6, 122, 512 }, { 7, 123, 512 }, { 6, 124, 512 }, { 7, 125, 512 }, { 7, 126, 512 }, { 8, 127, 512 }, 
   { 2, 128, 512 }, { 3, 129, 512 }, { 3, 130, 512 }, { 4, 131, 512 }, { 3, 132, 512 }, { 4, 133, 512 }, { 4, 134, 512 }, { 5, 135, 512 }, 
   { 3, 136, 512 }, { 4, 137, 512 }, { 4, 138, 512 }, { 5, 139, 512 }, { 4, 140, 512 }, { 5, 141, 512 }, { 5, 142, 512 }, { 6, 143, 512 }, 
   { 3, 144, 512 }, { 4, 145, 512 }, { 4, 146, 512 }, { 5, 147, 512 }, { 4, 148, 512 }, { 5, 149, 512 }, { 5, 150, 512 }, { 6, 151, 512 }, 
   { 4, 152, 512 }, { 5, 153, 512 }, { 5, 154, 512 }, { 6, 155, 512 }, { 5, 156, 512 }, { 6, 157, 512 }, { 6, 158, 512 }, { 7, 159, 512 }, 
   { 3, 160, 512 }, { 4, 161, 512 }, { 4, 162, 512 }, { 5, 163, 512 }, { 4, 164, 512 }, { 5, 165, 512 }, { 5, 166, 512 }, { 6, 167, 512 }, 
   { 4, 168, 512 }, { 5, 169, 512 }, { 5, 170, 512 }, { 6, 171, 512 }, { 5, 172, 512 }, { 6, 173, 512 }, { 6, 174, 512 }, { 7, 175, 512 }, 
   { 4, 176, 512 }, { 5, 177, 512 }, { 5, 178, 512 }, { 6, 179, 512 }, { 5, 180, 512 }, { 6, 181, 512 }, { 6, 182, 512 }, { 7, 183, 512 }, 
   { 5, 184, 512 }, { 6, 185, 512 }, { 6, 186, 512 }, { 7, 187, 512 }, { 6, 188, 512 }, { 7, 189, 512 }, { 7, 190, 512 }, { 8, 191, 512 }, 
   { 3, 192, 512 }, { 4, 193, 512 }, { 4, 194, 512 }, { 5, 195, 512 }, { 4, 196, 512 }, { 5, 197, 512 }, { 5, 198, 512 }, { 6, 199, 512 }, 
   { 4, 200, 512 }, { 5, 201, 512 }, { 5, 202, 512 }, { 6, 203, 512 }, { 5, 204, 512 }, { 6, 205, 512 }, { 6, 206, 512 }, { 7, 207, 512 }, 
   { 4, 208, 512 }, { 5, 209, 512 }, { 5, 210, 512 }, { 6, 211, 512 }, { 5, 212, 512 }, { 6, 213, 512 }, { 6, 214, 512 }, { 7, 215, 512 }, 
   { 5, 216, 512 }, { 6, 217, 512 }, { 6, 218, 512 }, { 7, 219, 512 }, { 6, 220, 512 }, { 7, 221, 512 }, { 7, 222, 512 }, { 8, 223, 512 }, 
   { 4, 224, 512 }, { 5, 225, 512 }, { 5, 226, 512 }, { 6, 227, 512 }, { 5, 228, 512 }, { 6, 229, 512 }, { 6, 230, 512 }, { 7, 231, 512 }, 
   { 5, 232, 512 }, { 6, 233, 512 }, { 6, 234, 512 }, { 7, 235, 512 }, { 6, 236, 512 }, { 7, 237, 512 }, { 7, 238, 512 }, { 8, 239, 512 }, 
   { 5, 240, 512 }, { 6, 241, 512 }, { 6, 242, 512 }, { 7, 243, 512 }, { 6, 244, 512 }, { 7, 245, 512 }, { 7, 246, 512 }, { 8, 247, 512 }, 
   { 6, 248, 512 }, { 7, 249, 512 }, { 7, 250, 512 }, { 8, 251, 512 }, { 7, 252, 512 }, { 8, 253, 512 }, { 8, 254, 512 }, { 9, 255, 512 }, 
   { 2, 256, 512 }, { 3, 257, 512 }, { 3, 258, 512 }, { 4, 259, 512 }, { 3, 260, 512 }, { 4, 261, 512 }, { 4, 262, 512 }, { 5, 263, 512 }, 
   { 3, 264, 512 }, { 4, 265, 512 }, { 4, 266, 512 }, { 5, 267, 512 }, { 4, 268, 512 }, { 5, 269, 512 }, { 5, 270, 512 }, { 6, 271, 512 }, 
   { 3, 272, 512 }, { 4, 273, 512 }, { 4, 274, 512 }, { 5, 275, 512 }, { 4, 276, 512 }, { 5, 277, 512 }, { 5, 278, 512 }, { 6, 279, 512 }, 
   { 4, 280, 512 }, { 5, 281, 512 }, { 5, 282, 512 }, { 6, 283, 512 }, { 5, 284, 512 }, { 6, 285, 512 }, { 6, 286, 512 }, { 7, 287, 512 }, 
   { 3, 288, 512 }, { 4, 289, 512 }, { 4, 290, 512 }, { 5, 291, 512 }, { 4, 292, 512 }, { 5, 293, 512 }, { 5, 294, 512 }, { 6, 295, 512 }, 
   { 4, 296, 512 }, { 5, 297, 512 }, { 5, 298, 512 }, { 6, 299, 512 }, { 5, 300, 512 }, { 6, 301, 512 }, { 6, 302, 512 }, { 7, 303, 512 }, 
   { 4, 304, 512 }, { 5, 305, 512 }, { 5, 306, 512 }, { 6, 307, 512 }, { 5, 308, 512 }, { 6, 309, 512 }, { 6, 310, 512 }, { 7, 311, 512 }, 
   { 5, 312, 512 }, { 6, 313, 512 }, { 6, 314, 512 }, { 7, 315, 512 }, { 6, 316, 512 }, { 7, 317, 512 }, { 7, 318, 512 }, { 8, 319, 512 }, 
   { 3, 320, 512 }, { 4, 321, 512 }, { 4, 322, 512 }, { 5, 323, 512 }, { 4, 324, 512 }, { 5, 325, 512 }, { 5, 326, 512 }, { 6, 327, 512 }, 
   { 4, 328, 512 }, { 5, 329, 512 }, { 5, 330, 512 }, { 6, 331, 512 }, { 5, 332, 512 }, { 6, 333, 512 }, { 6, 334, 512 }, { 7, 335, 512 }, 
   { 4, 336, 512 }, { 5, 337, 512 }, { 5, 338, 512 }, { 6, 339, 512 }, { 5, 340, 512 }, { 6, 341, 512 }, { 6, 342, 512 }, { 7, 343, 512 }, 
   { 5, 344, 512 }, { 6, 345, 512 }, { 6, 346, 512 }, { 7, 347, 512 }, { 6, 348, 512 }, { 7, 349, 512 }, { 7, 350, 512 }, { 8, 351, 512 }, 
   { 4, 352, 512 }, { 5, 353, 512 }, { 5, 354, 512 }, { 6, 355, 512 }, { 5, 356, 512 }, { 6, 357, 512 }, { 6, 358, 512 }, { 7, 359, 512 }, 
   { 5, 360, 512 }, { 6, 361, 512 }, { 6, 362, 512 }, { 7, 363, 512 }, { 6, 364, 512 }, { 7, 365, 512 }, { 7, 366, 512 }, { 8, 367, 512 }, 
   { 5, 368, 512 }, { 6, 369, 512 }, { 6, 370, 512 }, { 7, 371, 512 }, { 6, 372, 512 }, { 7, 373, 512 }, { 7, 374, 512 }, { 8, 375, 512 }, 
   { 6, 376, 512 }, { 7, 377, 512 }, { 7, 378, 512 }, { 8, 379, 512 }, { 7, 380, 512 }, { 8, 381, 512 }, { 8, 382, 512 }, { 9, 383, 512 }, 
   { 3, 384, 512 }, { 4, 385, 512 }, { 4, 386, 512 }, { 5, 387, 512 }, { 4, 388, 512 }, { 5, 389, 512 }, { 5, 390, 512 }, { 6, 391, 512 }, 
   { 4, 392, 512 }, { 5, 393, 512 }, { 5, 394, 512 }, { 6, 395, 512 }, { 5, 396, 512 }, { 6, 397, 512 }, { 6, 398, 512 }, { 7, 399, 512 }, 
   { 4, 400, 512 }, { 5, 401, 512 }, { 5, 402, 512 }, { 6, 403, 512 }, { 5, 404, 512 }, { 6, 405, 512 }, { 6, 406, 512 }, { 7, 407, 512 }, 
   { 5, 408, 512 }, { 6, 409, 512 }, { 6, 410, 512 }, { 7, 411, 512 }, { 6, 412, 512 }, { 7, 413, 512 }, { 7, 414, 512 }, { 8, 415, 512 }, 
   { 4, 416, 512 }, { 5, 417, 512 }, { 5, 418, 512 }, { 6, 419, 512 }, { 5, 420, 512 }, { 6, 421, 512 }, { 6, 422, 512 }, { 7, 423, 512 }, 
   { 5, 424, 512 }, { 6, 425, 512 }, { 6, 426, 512 }, { 7, 427, 512 }, { 6, 428, 512 }, { 7, 429, 512 }, { 7, 430, 512 }, { 8, 431, 512 }, 
   { 5, 432, 512 }, { 6, 433, 512 }, { 6, 434, 512 }, { 7, 435, 512 }, { 6, 436, 512 }, { 7, 437, 512 }, { 7, 438, 512 }, { 8, 439, 512 }, 
   { 6, 440, 512 }, { 7, 441, 512 }, { 7, 442, 512 }, { 8, 443, 512 }, { 7, 444, 512 }, { 8, 445, 512 }, { 8, 446, 512 }, { 9, 447, 512 }, 
   { 4, 448, 512 }, { 5, 449, 512 }, { 5, 450, 512 }, { 6, 451, 512 }, { 5, 452, 512 }, { 6, 453, 512 }, { 6, 454, 512 }, { 7, 455, 512 }, 
   { 5, 456, 512 }, { 6, 457, 512 }, { 6, 458, 512 }, { 7, 459, 512 }, { 6, 460, 512 }, { 7, 461, 512 }, { 7, 462, 512 }, { 8, 463, 512 }, 
   { 5, 464, 512 }, { 6, 465, 512 }, { 6, 466, 512 }, { 7, 467, 512 }, { 6, 468, 512 }, { 7, 469, 512 }, { 7, 470, 512 }, { 8, 471, 512 }, 
   { 6, 472, 512 }, { 7, 473, 512 }, { 7, 474, 512 }, { 8, 475, 512 }, { 7, 476, 512 }, { 8, 477, 512 }, { 8, 478, 512 }, { 9, 479, 512 }, 
   { 5, 480, 512 }, { 6, 481, 512 }, { 6, 482, 512 }, { 7, 483, 512 }, { 6, 484, 512 }, { 7, 485, 512 }, { 7, 486, 512 }, { 8, 487, 512 }, 
   { 6, 488, 512 }, { 7, 489, 512 }, { 7, 490, 512 }, { 8, 491, 512 }, { 7, 492, 512 }, { 8, 493, 512 }, { 8, 494, 512 }, { 9, 495, 512 }, 
   { 6, 496, 512 }, { 7, 497, 512 }, { 7, 498, 512 }, { 8, 499, 512 }, { 7, 500, 512 }, { 8, 501, 512 }, { 8, 502, 512 }, { 9, 503, 512 }, 
   { 7, 504, 512 }, { 8, 505, 512 }, { 8, 506, 512 }, { 9, 507, 512 }, { 8, 508, 512 }, { 9, 509, 512 }, { 9, 510, 512 }, { 10, 511, 512 }, 
#if FP_LUT > 10
   { 1, 0, 0 }, { 2, 1, 1024 }, { 2, 2, 1024 }, { 3, 3, 1024 }, { 2, 4, 1024 }, { 3, 5, 1024 }, { 3, 6, 1024 }, { 4, 7, 1024 }, 
   { 2, 8, 1024 }, { 3, 9, 1024 }, { 3, 10, 1024 }, { 4, 11, 1024 }, { 3, 12, 1024 }, { 4, 13, 1024 }, { 4, 14, 1024 }, { 5, 15, 1024 }, 
   { 2, 16, 1024 }, { 3, 17, 1024 }, { 3, 18, 1024 }, { 4, 19, 1024 }, { 3, 20, 1024 }, { 4, 21, 1024 }, { 4, 22, 1024 }, { 5, 23, 1024 }, 
   { 3, 24, 1024 }, { 4, 25, 1024 }, { 4, 26, 1024 }, { 5, 27, 1024 }, { 4, 28, 1024 }, { 5, 29, 1024 }, { 5, 30, 1024 }, { 6, 31, 1024 }, 
   { 2, 32, 1024 }, { 3, 33, 1024 }, { 3, 34, 1024 }, { 4, 35, 1024 }, { 3, 36, 1024 }, { 4, 37, 1024 }, { 4, 38, 1024 }, { 5, 39, 1024 }, 
   { 3, 40, 1024 }, { 4, 41, 1024 }, { 4, 42, 1024 }, { 5, 43, 1024 }, { 4, 44, 1024 }, { 5, 45, 1024 }, { 5, 46, 1024 }, { 6, 47, 1024 }, 
   { 3, 48, 1024 }, { 4, 49, 1024 }, { 4, 50, 1024 }, { 5, 51, 1024 }, { 4, 52, 1024 }, { 5, 53, 1024 }, { 5, 54, 1024 }, { 6, 55, 1024 }, 
   { 4, 56, 1024 }, { 5, 57, 1024 }, { 5, 58, 1024 }, { 6, 59, 1024 }, { 5, 60, 1024 }, { 6, 61, 1024 }, { 6, 62, 1024 }, { 7, 63, 1024 }, 
   { 2, 64, 1024 }, { 3, 65, 1024 }, { 3, 66, 1024 }, { 4, 67, 1024 }, { 3, 68, 1024 }, { 4, 69, 1024 }, { 4, 70, 1024 }, { 5, 71, 1024 }, 
   { 3, 72, 1024 }, { 4, 73, 1024 }, { 4, 74, 1024 }, { 5, 75, 1024 }, { 4, 76, 1024 }, { 5, 77, 1024 }, { 5, 78, 1024 }, { 6, 79, 1024 }, 
   { 3, 80, 1024 }, { 4, 81, 1024 }, { 4, 82, 1024 }, { 5, 83, 1024 }, { 4, 84, 1024 }, { 5, 85, 1024 }, { 5, 86, 1024 }, { 6, 87, 1024 }, 
   { 4, 88, 1024 }, { 5, 89, 1024 }, { 5, 90, 1024 }, { 6, 91, 1024 }, { 5, 92, 1024 }, { 6, 93, 1024 }, { 6, 94, 1024 }, { 7, 95, 1024 }, 
   { 3, 96, 1024 }, { 4, 97, 1024 }, { 4, 98, 1024 }, { 5, 99, 1024 }, { 4, 100, 1024 }, { 5, 101, 1024 }, { 5, 102, 1024 }, { 6, 103, 1024 }, 
   { 4, 104, 1024 }, { 5, 105, 1024 }, { 5, 106, 1024 }, { 6, 107, 1024 }, { 5, 108, 1024 }, { 6, 109, 1024 }, { 6, 110, 1024 }, { 7, 111, 1024 }, 
   { 4, 112, 1024 }, { 5, 113, 1024 }, { 5, 114, 1024 }, { 6, 115, 1024 }, { 5, 116, 1024 }, { 6, 117, 1024 }, { 6, 118, 1024 }, { 7, 119, 1024 }, 
   { 5, 120, 1024 }, { 6, 121, 1024 }, { 6, 122, 1024 }, { 7, 123, 1024 }, { 6, 124, 1024 }, { 7, 125, 1024 }, { 7, 126, 1024 }, { 8, 127, 1024 }, 
   { 2, 128, 1024 }, { 3, 129, 1024 }, { 3, 130, 1024 }, { 4, 131, 1024 }, { 3, 132, 1024 }, { 4, 133, 1024 }, { 4, 134, 1024 }, { 5, 135, 1024 }, 
   { 3, 136, 1024 }, { 4, 137, 1024 }, { 4, 138, 1024 }, { 5, 139, 1024 }, { 4, 140, 1024 }, { 5, 141, 1024 }, { 5, 142, 1024 }, { 6, 143, 1024 }, 
   { 3, 144, 1024 }, { 4, 145, 1024 }, { 4, 146, 1024 }, { 5, 147, 1024 }, { 4, 148, 1024 }, { 5, 149, 1024 }, { 5, 150, 1024 }, { 6, 151, 1024 }, 
   { 4, 152, 1024 }, { 5, 153, 1024 }, { 5, 154, 1024 }, { 6, 155, 1024 }, { 5, 156, 1024 }, { 6, 157, 1024 }, { 6, 158, 1024 }, { 7, 159, 1024 }, 
   { 3, 160, 1024 }, { 4, 161, 1024 }, { 4, 162, 1024 }, { 5, 163, 1024 }, { 4, 164, 1024 }, { 5, 165, 1024 }, { 5, 166, 1024 }, { 6, 167, 1024 }, 
   { 4, 168, 1024 }, { 5, 169, 1024 }, { 5, 170, 1024 }, { 6, 171, 1024 }, { 5, 172, 1024 }, { 6, 173, 1024 }, { 6, 174, 1024 }, { 7, 175, 1024 }, 
   { 4, 176, 1024 }, { 5, 177, 1024 }, { 5, 178, 1024 }, { 6, 179, 1024 }, { 5, 180, 1024 }, { 6, 181, 1024 }, { 6, 182, 1024 }, { 7, 183, 1024 }, 
   { 5, 184, 1024 }, { 6, 185, 1024 }, { 6, 186, 1024 }, { 7, 187, 1024 }, { 6, 188, 1024 }, { 7, 189, 1024 }, { 7, 190, 1024 }, { 8, 191, 1024 }, 
   { 3, 192, 1024 }, { 4, 193, 1024 }, { 4, 194, 1024 }, { 5, 195, 1024 }, { 4, 196, 1024 }, { 5, 197, 1024 }, { 5, 198, 1024 }, { 6, 199, 1024 }, 
   { 4, 200, 1024 }, { 5, 201, 1024 }, { 5, 202, 1024 }, { 6, 203, 1024 }, { 5, 204, 1024 }, { 6, 205, 1024 }, { 6, 206, 1024 }, { 7, 207, 1024 }, 
   { 4, 208, 1024 }, { 5, 209, 1024 }, { 5, 210, 1024 }, { 6, 211, 1024 }, { 5, 212, 1024 }, { 6, 213, 1024 }, { 6, 214, 1024 }, { 7, 215, 1024 }, 
   { 5, 216, 1024 }, { 6, 217, 1024 }, { 6, 218, 1024 }, { 7, 219, 1024 }, { 6, 220, 1024 }, { 7, 221, 1024 }, { 7, 222, 1024 }, { 8, 223, 1024 }, 
   { 4, 224, 1024 }, { 5, 225, 1024 }, { 5, 226, 1024 }, { 6, 227, 1024 }, { 5, 228, 1024 }, { 6, 229, 1024 }, { 6, 230, 1024 }, { 7, 231, 1024 }, 
   { 5, 232, 1024 }, { 6, 233, 1024 }, { 6, 234, 1024 }, { 7, 235, 1024 }, { 6, 236, 1024 }, { 7, 237, 1024 }, { 7, 238, 1024 }, { 8, 239, 1024 }, 
   { 5, 240, 1024 }, { 6, 241, 1024 }, { 6, 242, 1024 }, { 7, 243, 1024 }, { 6, 244, 1024 }, { 7, 245, 1024 }, { 7, 246, 1024 }, { 8, 247, 1024 }, 
   { 6, 248, 1024 }, { 7, 249, 1024 }, { 7, 250, 1024 }, { 8, 251, 1024 }, { 7, 252, 1024 }, { 8, 253, 1024 }, { 8, 254, 1024 }, { 9, 255, 1024 }, 
   { 2, 256, 1024 }, { 3, 257, 1024 }, { 3, 258, 1024 }, { 4, 259, 1024 }, { 3, 260, 1024 }, { 4, 261, 1024 }, { 4, 262, 1024 }, { 5, 263, 1024 }, 
   { 3, 264, 1024 }, { 4, 265, 1024 }, { 4, 266, 1024 }, { 5, 267, 1024 }, { 4, 268, 1024 }, { 5, 269, 1024 }, { 5, 270, 1024 }, { 6, 271, 1024 }, 
   { 3, 272, 1024 }, { 4, 273, 1024 }, { 4, 274, 1024 }, { 5, 275, 1024 }, { 4, 276, 1024 }, { 5, 277, 1024 }, { 5, 278, 1024 }, { 6, 279, 1024 }, 
   { 4, 280, 1024 }, { 5, 281, 1024 }, { 5, 282, 1024 }, { 6, 283, 1024 }, { 5, 284, 1024 }, { 6, 285, 1024 }, { 6, 286, 1024 }, { 7, 287, 1024 }, 
   { 3, 288, 1024 }, { 4, 289, 1024 }, { 4, 290, 1024 }, { 5, 291, 1024 }, { 4, 292, 1024 }, { 5, 293, 1024 }, { 5, 294, 1024 }, { 6, 295, 1024 }, 
   { 4, 296, 1024 }, { 5, 297, 1024 }, { 5, 298, 1024 }, { 6, 299, 1024 }, { 5, 300, 1024 }, { 6, 301, 1024 }, { 6, 302, 1024 }, { 7, 303, 1024 }, 
   { 4, 304, 1024 }, { 5, 305, 1024 }, { 5, 306, 1024 }, { 6, 307, 1024 }, { 5, 308, 1024 }, { 6, 309, 1024 }, { 6, 310, 1024 }, { 7, 311, 1024 }, 
   { 5, 312, 1024 }, { 6, 313, 1024 }, { 6, 314, 1024 }, { 7, 315, 1024 }, { 6, 316, 1024 }, { 7, 317, 1024 }, { 7, 318, 1024 }, { 8, 319, 1024 }, 
   { 3, 320, 1024 }, { 4, 321, 1024 }, { 4, 322, 1024 }, { 5, 323, 1024 }, { 4, 324, 1024 }, { 5, 325, 1024 }, { 5, 326, 1024 }, { 6, 327, 1024 }, 
   { 4, 328, 1024 }, { 5, 329, 1024 }, { 5, 330, 1024 }, { 6, 331, 1024 }, { 5, 332, 1024 }, { 6, 333, 1024 }, { 6, 334, 1024 }, { 7, 335, 1024 }, 
   { 4, 336, 1024 }, { 5, 337, 1024 }, { 5, 338, 1024 }, { 6, 339, 1024 }, { 5, 340, 1024 }, { 6, 341, 1024 }, { 6, 342, 1024 }, { 7, 343, 1024 }, 
   { 5, 344, 1024 }, { 6, 345, 1024 }, { 6, 346, 1024 }, { 7, 347, 1024 }, { 6, 348, 1024 }, { 7, 349, 1024 }, { 7, 350, 1024 }, { 8, 351, 1024 }, 
   { 4, 352, 1024 }, { 5, 353, 1024 }, { 5, 354, 1024 }, { 6, 355, 1024 }, { 5, 356, 1024 }, { 6, 357, 1024 }, { 6, 358, 1024 }, { 7, 359, 1024 }, 
   { 5, 360, 1024 }, { 6, 361, 1024 }, { 6, 362, 1024 }, { 7, 363, 1024 }, { 6, 364, 1024 }, { 7, 365, 1024 }, { 7, 366, 1024 }, { 8, 367, 1024 }, 
   { 5, 368, 1024 }, { 6, 369, 1024 }, { 6, 370, 1024 }, { 7, 371, 1024 }, { 6, 372, 1024 }, { 7, 373, 1024 }, { 7, 374, 1024 }, { 8, 375, 1024 }, 
   { 6, 376, 1024 }, { 7, 377, 1024 }, { 7, 378, 1024 }, { 8, 379, 1024 }, { 7, 380, 1024 }, { 8, 381, 1024 }, { 8, 382, 1024 }, { 9, 383, 1024 }, 
   { 3, 384, 1024 }, { 4, 385, 1024 }, { 4, 386, 1024 }, { 5, 387, 1024 }, { 4, 388, 1024 }, { 5, 389, 1024 }, { 5, 390, 1024 }, { 6, 391, 1024 }, 
   { 4, 392, 1024 }, { 5, 393, 1024 }, { 5, 394, 1024 }, { 6, 395, 1024 }, { 5, 396, 1024 }, { 6, 397, 1024 }, { 6, 398, 1024 }, { 7, 399, 1024 }, 
   { 4, 400, 1024 }, { 5, 401, 1024 }, { 5, 402, 1024 }, { 6, 403, 1024 }, { 5, 404, 1024 }, { 6, 405, 1024 }, { 6, 406, 1024 }, { 7, 407, 1024 }, 
   { 5, 408, 1024 }, { 6, 409, 1024 }, { 6, 410, 1024 }, { 7, 411, 1024 }, { 6, 412, 1024 }, { 7, 413, 1024 }, { 7, 414, 1024 }, { 8, 415, 1024 }, 
   { 4, 416, 1024 }, { 5, 417, 1024 }, { 5, 418, 1024 }, { 6, 419, 1024 }, { 5, 420, 1024 }, { 6, 421, 1024 }, { 6, 422, 1024 }, { 7, 423, 1024 }, 
   { 5, 424, 1024 }, { 6, 425, 1024 }, { 6, 426, 1024 }, { 7, 427, 1024 }, { 6, 428, 1024 }, { 7, 429, 1024 }, { 7, 430, 1024 }, { 8, 431, 1024 }, 
   { 5, 432, 1024 }, { 6, 433, 1024 }, { 6, 434, 1024 }, { 7, 435, 1024 }, { 6, 436, 1024 }, { 7, 437, 1024 }, { 7, 438, 1024 }, { 8, 439, 1024 }, 
   { 6, 440, 1024 }, { 7, 441, 1024 }, { 7, 442, 1024 }, { 8, 443, 1024 }, { 7, 444, 1024 }, { 8, 445, 1024 }, { 8, 446, 1024 }, { 9, 447, 1024 }, 
   { 4, 448, 1024 }, { 5, 449, 1024 }, { 5, 450, 1024 }, { 6, 451, 1024 }, { 5, 452, 1024 }, { 6, 453, 1024 }, { 6, 454, 1024 }, { 7, 455, 1024 }, 
   { 5, 456, 1024 }, { 6, 457, 1024 }, { 6, 458, 1024 }, { 7, 459, 1024 }, { 6, 460, 1024 }, { 7, 461, 1024 }, { 7, 462, 1024 }, { 8, 463, 1024 }, 
   { 5, 464, 1024 }, { 6, 465, 1024 }, { 6, 466, 1024 }, { 7, 467, 1024 }, { 6, 468, 1024 }, { 7, 469, 1024 }, { 7, 470, 1024 }, { 8, 471, 1024 }, 
   { 6, 472, 1024 }, { 7, 473, 1024 }, { 7, 474, 1024 }, { 8, 475, 1024 }, { 7, 476, 1024 }, { 8, 477, 1024 }, { 8, 478, 1024 }, { 9, 479, 1024 }, 
   { 5, 480, 1024 }, { 6, 481, 1024 }, { 6, 482, 1024 }, { 7, 483, 1024 }, { 6, 484, 1024 }, { 7, 485, 1024 }, { 7, 486, 1024 }, { 8, 487, 1024 }, 
   { 6, 488, 1024 }, { 7, 489, 1024 }, { 7, 490, 1024 }, { 8, 491, 1024 }, { 7, 492, 1024 }, { 8, 493, 1024 }, { 8, 494, 1024 }, { 9, 495, 1024 }, 
   { 6, 496, 1024 }, { 7, 497, 1024 }, { 7, 498, 1024 }, { 8, 499, 1024 }, { 7, 500, 1024 }, { 8, 501, 1024 }, { 8, 502, 1024 }, { 9, 503, 1024 }, 
   { 7, 504, 1024 }, { 8, 505, 1024 }, { 8, 506, 1024 }, { 9, 507, 1024 }, { 8, 508, 1024 }, { 9, 509, 1024 }, { 9, 510, 1024 }, { 10, 511, 1024 }, 
   { 2, 512, 1024 }, { 3, 513, 1024 }, { 3, 514, 1024 }, { 4, 515, 1024 }, { 3, 516, 1024 }, { 4, 517, 1024 }, { 4, 518, 1024 }, { 5, 519, 1024 }, 
   { 3, 520, 1024 }, { 4, 521, 1024 }, { 4, 522, 1024 }, { 5, 523, 1024 }, { 4, 524, 1024 }, { 5, 525, 1024 }, { 5, 526, 1024 }, { 6, 527, 1024 }, 
   { 3, 528, 1024 }, { 4, 529, 1024 }, { 4, 530, 1024 }, { 5, 531, 1024 }, { 4, 532, 1024 }, { 5, 533, 1024 }, { 5, 534, 1024 }, { 6, 535, 1024 }, 
   { 4, 536, 1024 }, { 5, 537, 1024 }, { 5, 538, 1024 }, { 6, 539, 1024 }, { 5, 540, 1024 }, { 6, 541, 1024 }, { 6, 542, 1024 }, { 7, 543, 1024 }, 
   { 3, 544, 1024 }, { 4, 545, 1024 }, { 4, 546, 1024 }, { 5, 547, 1024 }, { 4, 548, 1024 }, { 5, 549, 1024 }, { 5, 550, 1024 }, { 6, 551, 1024 }, 
   { 4, 552, 1024 }, { 5, 553, 1024 }, { 5, 554, 1024 }, { 6, 555, 1024 }, { 5, 556, 1024 }, { 6, 557, 1024 }, { 6, 558, 1024 }, { 7, 559, 1024 }, 
   { 4, 560, 1024 }, { 5, 561, 1024 }, { 5, 562, 1024 }, { 6, 563, 1024 }, { 5, 564, 1024 }, { 6, 565, 1024 }, { 6, 566, 1024 }, { 7, 567, 1024 }, 
   { 5, 568, 1024 }, { 6, 569, 1024 }, { 6, 570, 1024 }, { 7, 571, 1024 }, { 6, 572, 1024 }, { 7, 573, 1024 }, { 7, 574, 1024 }, { 8, 575, 1024 }, 
   { 3, 576, 1024 }, { 4, 577, 1024 }, { 4, 578, 1024 }, { 5, 579, 1024 }, { 4, 580, 1024 }, { 5, 581, 1024 }, { 5, 582, 1024 }, { 6, 583, 1024 }, 
   { 4, 584, 1024 }, { 5, 585, 1024 }, { 5, 586, 1024 }, { 6, 587, 1024 }, { 5, 588, 1024 }, { 6, 589, 1024 }, { 6, 590, 1024 }, { 7, 591, 1024 }, 
   { 4, 592, 1024 }, { 5, 593, 1024 }, { 5, 594, 1024 }, { 6, 595, 1024 }, { 5, 596, 1024 }, { 6, 597, 1024 }, { 6, 598, 1024 }, { 7, 599, 1024 }, 
   { 5, 600, 1024 }, { 6, 601, 1024 }, { 6, 602, 1024 }, { 7, 603, 1024 }, { 6, 604, 1024 }, { 7, 605, 1024 }, { 7, 606, 1024 }, { 8, 607, 1024 }, 
   { 4, 608, 1024 }, { 5, 609, 1024 }, { 5, 610, 1024 }, { 6, 611, 1024 }, { 5, 612, 1024 }, { 6, 613, 1024 }, { 6, 614, 1024 }, { 7, 615, 1024 }, 
   { 5, 616, 1024 }, { 6, 617, 1024 }, { 6, 618, 1024 }, { 7, 619, 1024 }, { 6, 620, 1024 }, { 7, 621, 1024 }, { 7, 622, 1024 }, { 8, 623, 1024 }, 
   { 5, 624, 1024 }, { 6, 625, 1024 }, { 6, 626, 1024 }, { 7, 627, 1024 }, { 6, 628, 1024 }, { 7, 629, 1024 }, { 7, 630, 1024 }, { 8, 631, 1024 }, 
   { 6, 632, 1024 }, { 7, 633, 1024 }, { 7, 634, 1024 }, { 8, 635, 1024 }, { 7, 636, 1024 }, { 8, 637, 1024 }, { 8, 638, 1024 }, { 9, 639, 1024 }, 
   { 3, 640, 1024 }, { 4, 641, 1024 }, { 4, 642, 1024 }, { 5, 643, 1024 }, { 4, 644, 1024 }, { 5, 645, 1024 }, { 5, 646, 1024 }, { 6, 647, 1024 }, 
   { 4, 648, 1024 }, { 5, 649, 1024 }, { 5, 650, 1024 }, { 6, 651, 1024 }, { 5, 652, 1024 }, { 6, 653, 1024 }, { 6, 654, 1024 }, { 7, 655, 1024 }, 
   { 4, 656, 1024 }, { 5, 657, 1024 }, { 5, 658, 1024 }, { 6, 659, 1024 }, { 5, 660, 1024 }, { 6, 661, 1024 }, { 6, 662, 1024 }, { 7, 663, 1024 }, 
   { 5, 664, 1024 }, { 6, 665, 1024 }, { 6, 666, 1024 }, { 7, 667, 1024 }, { 6, 668, 1024 }, { 7, 669, 1024 }, { 7, 670, 1024 }, { 8, 671, 1024 }, 
   { 4, 672, 1024 }, { 5, 673, 1024 }, { 5, 674, 1024 }, { 6, 675, 1024 }, { 5, 676, 1024 }, { 6, 677, 1024 }, { 6, 678, 1024 }, { 7, 679, 1024 }, 
   { 5, 680, 1024 }, { 6, 681, 1024 }, { 6, 682, 1024 }, { 7, 683, 1024 }, { 6, 684, 1024 }, { 7, 685, 1024 }, { 7, 686, 1024 }, { 8, 687, 1024 }, 
   { 5, 688, 1024 }, { 6, 689, 1024 }, { 6, 690, 1024 }, { 7, 691, 1024 }, { 6, 692, 1024 }, { 7, 693, 1024 }, { 7, 694, 1024 }, { 8, 695, 1024 }, 
   { 6, 696, 1024 }, { 7, 697, 1024 }, { 7, 698, 1024 }, { 8, 699, 1024 }, { 7, 700, 1024 }, { 8, 701, 1024 }, { 8, 702, 1024 }, { 9, 703, 1024 }, 
   { 4, 704, 1024 }, { 5, 705, 1024 }, { 5, 706, 1024 }, { 6, 707, 1024 }, { 5, 708, 1024 }, { 6, 709, 1024 }, { 6, 710, 1024 }, { 7, 711, 1024 }, 
   { 5, 712, 1024 }, { 6, 713, 1024 }, { 6, 714, 1024 }, { 7, 715, 1024 }, { 6, 716, 1024 }, { 7, 717, 1024 }, { 7, 718, 1024 }, { 8, 719, 1024 }, 
   { 5, 720, 1024 }, { 6, 721, 1024 }, { 6, 722, 1024 }, { 7, 723, 1024 }, { 6, 724, 1024 }, { 7, 725, 1024 }, { 7, 726, 1024 }, { 8, 727, 1024 }, 
   { 6, 728, 1024 }, { 7, 729, 1024 }, { 7, 730, 1024 }, { 8, 731, 1024 }, { 7, 732, 1024 }, { 8, 733, 1024 }, { 8, 734, 1024 }, { 9, 735, 1024 }, 
   { 5, 736, 1024 }, { 6, 737, 1024 }, { 6, 738, 1024 }, { 7, 739, 1024 }, { 6, 740, 1024 }, { 7, 741, 1024 }, { 7, 742, 1024 }, { 8, 743, 1024 }, 
   { 6, 744, 1024 }, { 7, 745, 1024 }, { 7, 746, 1024 }, { 8, 747, 1024 }, { 7, 748, 1024 }, { 8, 749, 1024 }, { 8, 750, 1024 }, { 9, 751, 1024 }, 
   { 6, 752, 1024 }, { 7, 753, 1024 }, { 7, 754, 1024 }, { 8, 755, 1024 }, { 7, 756, 1024 }, { 8, 757, 1024 }, { 8, 758, 1024 }, { 9, 759, 1024 }, 
   { 7, 760, 1024 }, { 8, 761, 1024 }, { 8, 762, 1024 }, { 9, 763, 1024 }, { 8, 764, 1024 }, { 9, 765, 1024 }, { 9, 766, 1024 }, { 10, 767, 1024 }, 
   { 3, 768, 1024 }, { 4, 769, 1024 }, { 4, 770, 1024 }, { 5, 771, 1024 }, { 4, 772, 1024 }, { 5, 773, 1024 }, { 5, 774, 1024 }, { 6, 775, 1024 }, 
   { 4, 776, 1024 }, { 5, 777, 1024 }, { 5, 778, 1024 }, { 6, 779, 1024 }, { 5, 780, 1024 }, { 6, 781, 1024 }, { 6, 782, 1024 }, { 7, 783, 1024 }, 
   { 4, 784, 1024 }, { 5, 785, 1024 }, { 5, 786, 1024 }, { 6, 787, 1024 }, { 5, 788, 1024 }, { 6, 789, 1024 }, { 6, 790, 1024 }, { 7, 791, 1024 }, 
   { 5, 792, 1024 }, { 6, 793, 1024 }, { 6, 794, 1024 }, { 7, 795, 1024 }, { 6, 796, 1024 }, { 7, 797, 1024 }, { 7, 798, 1024 }, { 8, 799, 1024 }, 
   { 4, 800, 1024 }, { 5, 801, 1024 }, { 5, 802, 1024 }, { 6, 803, 1024 }, { 5, 804, 1024 }, { 6, 805, 1024 }, { 6, 806, 1024 }, { 7, 807, 1024 }, 
   { 5, 808, 1024 }, { 6, 809, 1024 }, { 6, 810, 1024 }, { 7, 811, 1024 }, { 6, 812, 1024 }, { 7, 813, 1024 }, { 7, 814, 1024 }, { 8, 815, 1024 }, 
   { 5, 816, 1024 }, { 6, 817, 1024 }, { 6, 818, 1024 }, { 7, 819, 1024 }, { 6, 820, 1024 }, { 7, 821, 1024 }, { 7, 822, 1024 }, { 8, 823, 1024 }, 
   { 6, 824, 1024 }, { 7, 825, 1024 }, { 7, 826, 1024 }, { 8, 827, 1024 }, { 7, 828, 1024 }, { 8, 829, 1024 }, { 8, 830, 1024 }, { 9, 831, 1024 }, 
   { 4, 832, 1024 }, { 5, 833, 1024 }, { 5, 834, 1024 }, { 6, 835, 1024 }, { 5, 836, 1024 }, { 6, 837, 1024 }, { 6, 838, 1024 }, { 7, 839, 1024 }, 
   { 5, 840, 1024 }, { 6, 841, 1024 }, { 6, 842, 1024 }, { 7, 843cc.c
 *
 * C6pyri4cc.c
 *
 * Copyri5cc.c
 *
 * Copyri6cc.c
 *
 * C8pyri7cc.c
 *
 *
   { 5pyri8ht (C) 2006-2014 9ht (C) 2006-201450cc.c
 *
 * Copyr51bute it and/or moecc.c
 *
 * Copyr5ght (C) 2006-lic LwolfSSL Inc.
*
 *5 This file ree soor mo of CyaSSL.
 lic LCyaSSL is fn 2 of e; you can reree Sibute it and/opyr6dify
 * it un*
 *6he terms of t is decc.c
 *
 * C9is dght (C) 200ree softwa6wolfSSL Inc.
20146 This file isNTY; ther version 2 of6the License, NTY; e; you can rety ofany later version7
 *
 * CyaSSL is 7he terms ofndation; e7ecc.c
 *
 * Copyr7icense as publish7d by
 * the Free 7 This file is par7 of CyaSSL.
 *
 *7the License, icense; you can rewill7ibute it anndation; e8dify
 * it under 8he terms of tndatiecc.c
 *
 * C*
 *8icense as publish8d by
 * the Free 8 This file isSA
 * of CyaSSL.
 will8CyaSSL is free so, MA  (at your option)8ibute it and/*
 *9dify
 * it unwill9istributed in the9hope that it will9ght (C) 2006-AVE_EwolfSSL Inc.
10VE_Eoftware Foundatio4VE_E of CyaSSL.
 ftwa9the License, #incle; you can redist9ibute it and/5, 90dify
 * it un6ECC_he terms of the 90ecc.c
 *
 * Copy90be useful,
 * but WI90OUT ANY WARRANTY90without even the90ther version 2 o90
 * MERCHANTABIL90Y or FITNESS FOR90any later versio9ecc.VE_ECC there 91 General Public Locry1ecc.c
 *
 * Cefin1ght (C) 2006-20191wolfSSL Inc.
 *
91/* map

   ptmul 1> mulmod

*/

#de1the License, or
91 (at your option91, write to the Free 92dify
 * it under92on, Inc., 51 Fra92lin Street, Fift92icense as publis92d by
 * the Free92/


#ifdef HAVE_92NFIG_H
    #incl92CyaSSL is free softw92e; you can redis92ibute it and/or 93ts[] = {
#ifdef E3de <cyassl/ctaocr3pt/hmac.h>
    #i31",
        "DB7C3ABF62E35E668076BE3oftware Foundation; 93> mulmod

*/

#de3from
   smallest 3o largest. */

co3C160
#define ECC142
#define ECC224
4istributed in th9 ecc.c
 *
 * C6680ight (C) 2000E0FF77500 wolfSSL Inc.
 *
9* This file is pa9t of CyaSSL.
 *
 9 CyaSSL is f993C2CEo largest. */

coribute it and/   "odify
 * it un6680the terms of>
#endif
9NU General Pub528B8ght (C) 2006-528B8wolfSSL Inc.
A52C5D208B",
        "ither version A52C5FFFFFFE000000A52C5e; you can reecc.9 any later v
        ".
 *
 * CyaSSL7500distributed inFFFFFpt/hmac.h>
    #i be useful,
FF7FFFF        "E87579C1 without even 65FA4E5ED3",
        "f
 * MERCHAN0E0FF77500TY or FITNESS FOR9A PARTICULAR PURP9SE.  See the
 * G9U General Pu698968C95BAFEB13C02DA292s.
 *
 * You s",
  f
#ifdef ECC160
{copy of the 0E0FF77500neral Public L8968CFFFFFFE0000000075his program; i",
  EF573284664698968oftware
 * Fou",
 ion, Inc., 51 FFFFF    "FFFFFFFDFFFF Floor, Bost   "CF5AC8 02110-1301, USA
9*/


#ifdef HAVE_9ONFIG_H
    #incl9de <config.hFFFFFFFis program; if n9t HAVE_ECC the6146/
#include <cyFFFFF/ctaocrypt/s0E0FF77500s.h>

#ifdef H8968ECC

#include ",
  19E59C80E70FA7E9A>
#include <B95FFC8E5ED3",
        "lude <cyassl/c#ifdeFFFFFF99DEF836146>

#ifdef HA>
#endif
10_ENCRYPT
    #e; youde <cyassl/ctFFFFFF    "FFFFFFFDFFF10nclude <cyas00000000f
#ifdef ECC160
10
/* map

   ptFFEFFF of CyaSSL.
 92
#define ECC112
   "FFFFFFFFFFFFFFFFFFFFFFFF10CC160
#define 0B39492
#define ECCFFEFF#define ECC2        0000000001",
     C521



/* Thi5C2A3Dsl/ctaocrypt/ecc.10gs.  ***MUSTree so        "SECP160R1",
 10 from
   small    "BFFFFFFFFFFFFFFFFF10nst ecc_set_23FB4C2ets[] = {
#ifd92
#defhe terms of t92
#defecc.c
 *
 * C#defineFFFC",
     #if FP_LUT > 11ree so1, 0, 0*
 * Cecc., 2048000000FFFFFFFFFFFFFFFF3,    FFFFFFFFFFFFF4FFFF",
        5FFFF",
        6FFFFFFFF00004,95FFFF",
   ree so2,280DFF",
        9AA3A93E7B3EBBD5ecc.FFFFFFFFFFFFF#def9886BC651D06B0FFFFF",
     C3E2"FFFFFFFF0000C3E21000000000000 Thi000000000FF "5AC635D15C19886BC651D06B0C",
       1D06B08AA3A93E7B3EBC3E25769886BC651D06Bets[277037D812DEBC256,
        "4FEFFFFF",
     0000"FFFFFFFF00ree so98C21000000000000"4FE000000000FFFF"4FE     "6B17D1F0000C4247F8BCE6E5"4FE8AA3A93E7B3EB00005769886BC651D5,    "FF",
     6, 7628CAC2FC632551",
      FF",
        ""FFFFFFFF0000   "BF51F5",
},
#endAF87FF",
        "FFFFFFFFFFFFFFFF ECCFFFFFFFFFFFFFF      "FFFFFFFFF28R16B315ECECBB640683FFFF "ECC-384",
 FFFF       "B3312FEB4A7C0F9E162BCEight       "B3312FBCE6FAADA7179E84* Th875AC656398D8A     "6B17D1F6,  Cya000000000FFFFFFFC"40F277037D812DEBribu "ECC-384",
 odifFFFFFFFFFFFFFthe FFFFFFFC7634D8EB4A7C0F9E162BCEDDED2973",
       10000000000006, 
   6B315ECECBB64034D8
        48,
       82542A385502F28AA3A93E7B3EBAD74FFFFFFFFFFFFFFFF.
 *760AB7",
    dist5D9E98BF9292DCFFFFFFF0000007,  be CAC2FC632551",
  F89F000000FFFFFFFF000000000FFFFFFFFFFFFFFFFFFFFFFFFf
 *000000FFFFFFFF40F277037D812DEBA PAFFFFFFFFFFFFFC1F4372DDF581A0DBU Ge6B315ECECBB6406836894FFFFFFFFFFFFFCFE8141120314088F#endFFFFFFFFFFFFFFf
#ifdef ECC384
neraFFFFFFFFFFFFFF5DBF55296C3A545Ehis 760AB7",
    EFFF6B315ECECBB640683oftw "ECC-384",
 ion,FFFFFFFFFFFFFFEB4A7C0F9E162BCE FloFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF*/

FFC",
        C2AEF",
        de <D3B628BA79B9859F7FFFFFFC",
        FFFFFFFFFFFFFFFF/
#i760AB7",
    /ctaEC7E937B1652C0FFFFFFFFFFFFF7500"D3BB1BF073573DF8FFFFFFFFFFFFF5AC83FFFFFFFFFFFFFFFFFFF1",
 "ECC-384",
 ludeFFFFFFFFFFFA5189918EF109E15619>

#277037D812DEB3_ENC6FAADA7179E84Fude 1386409",
     6B503F00",
     1ncluD3B628BA79B9859F71FFFF1386409",
     "51953EB9618E1C91FFE"D9E3ECB662395B45DBF55296C3A545E1B0B7D9E3ECB662395B4C9B8899C47AEB395B0CC53B0F63BCE3FFFF27D2604B",
 53FB521F82  "FFFFFFFF0001C2E00FFFFFFFFFFFF995EF78EB1C71EF320AD71F3B9CAC2FC63013FAD0A2FFA8DE3348B3C182C4247F8BCE6E572C24BD66",
      D998FFFFFFFFFFFFFFFFFF1C2E296",
        72C2E342E2FE1A7F9B_poinCE9DA3113B5F0B8C133576B315ECEid ecc_FFFFFFFFFFFFFFFF1if
#ifdef ECC3 mp_iA2FFA8DE3348B0B39     "ECC-382551",
          "FFFFFF     5769886BC651D06B0FFFFFFFFFFFFFF000007D2604B",
       FFFFFFFF00000000000FFFFFFFFFFFFFFFF1
        "FFFF1C2EFFFFFFFFFFFFCBB6406831FFFFFFFFFFFFFFFFF1FFFFFFFFFFFFFFFFF1FFFFFEFFFFFFFF0001000000000000FFFFFFB1E91386409",
    FA7E23EE7E4988d(mp_E9CD9E3ECB662395BEFE814112031ecc_point*5013875AC65639FFFFBf
#ifdef ECC384
1EC2AEF",
     d(mp_,
               FFFFFFFFFFFFFFd(mp_FFFFFFFFFFFFFFFF181F4372DDF581A72C2248B0A77AECE53FB521F82CCC52973",
      1  "AA87CA22BE8B051378EB1C71EF320AD7146E1D3B628BA79E84F3A2FFA8DE3348B3C1825DBF55296C3A5mp_inULL, NULL, NULL,     "3617DE4ecc_point*2C6F5D9E98BF92ef EC29F8F41DBD289* a, 73E662C97EE72995E00A60B1CE1D7mp_int*AF606B4D3DBAA14B5
#endif
#ifdefecc_eA2FFA8DE3348B3C18,
        "E53FB521F821",
        "1ecc_ekA, ecc_point* B,FFFFFFFFFFFFFFmp_iFFFFFFFFFFFFr lib *E9CD9E3ECB662395BFFFFFFFFFFFFFF(a ==p(ecc_point*, mp_FFFFFFFFFFFF53FB521F82FFFF",
        "11FFFFFFFFFFFFFFFFF1FFFFFFFFFFFFFFFFF1FFFFFFFFFFFF* helpFFFFFFFFFFFFFFnt* FFFFFFFFFFFFFF     del_point(ecc_poiFFFFFFFFFFFFree softw1FFFFFFC",
         "51953EB9618E     A2FFA8DE3348B->usetmod_prime(mp_int489918EF109E15->useC9B8899C47AEB mp_0BD3BB1BF073570B39883D2C34F1EFecc_point*46B503F00",
  DEB33);
int  ecc_projeFFFFFFFFFFFFFF a->FFFFFFFFFFFF        for either lib *1868783BF2F966 moduBD66",
        "15C9B8899C47A79B9859F7271E91386409",
   2    "C6858E06B70424E9CD9E3ECB66239524429C6481390mery_sep[n];
}


#if de2E77EFE75928FE1rojec

/* fast math a256A429BF97E7in
   mp   89918EF109E1561921839296A789A3B    0CC53B0F63BCE3roje27D2604B",
   int* tup()
   return  00FFFFFFFFFFFFz;
  FFFFFFFFFFFFFFFF2F3B9CAC2FC632551",int* A2FFA8DE3348B3C120,
   NULL, NULL,2NULL, NULL, NULL,233A0F4A13945D8)
  296",
        C_BAE342E2FE1A7F9BmultiFFFFFFFFFFFFFBD6633576B315ECECBB6408EE7EAF606B4D3DBAA14B2if
#ifdef ECC3/* sh| modulus == NULL     "ECC-384"/* shBD66",
        "2ecc_point* R,
_cmpFFFFFFFFFFFFFFC_BA        mp_iree softw2FFFFFFFF000000 == F  "1FFFFFFFFFFFF2
        "FFFF     tive_add_point(ecFFFFFFFFFFFFFF     868783BF2F966     BD66",
      BD660000000000000FFFFF&Q-> int ecc_mulmo_EQ)FA7E23EE7E4988dulusCE9DA3113B5F0B8C2EFE81411203140dulus&&
        (fp_cmint map);
#ifd&x);
nt  ecc_projecti2nt ecc_mul2andation; 2FFFFFFFFFFFFFF&x);
 yet */

/**
   281F4372DDF581Aen t248B0A77AECEC1)) {
 &z, NULL)) != MP  "AA87CA22BE8;
   AF606B4D3DBAAC9B846E1D3B628BA79B985FFFFint* c);
int m429C25DBF55296C3A5  fp_40F277037D812DEB2    "3617DE4A9429C_submod(mp_int* a2 mp_int* b, mp_in2* c, mp_int* d);
200A60B1CE1D7E819D7modulBF51F5",
},
#endi
#endif
#ifdef */
 FFF",
        "12,
        "ECC */
                  er for either lib2*/
static int get2FFFFFFFFFFFFFFFFFFFFF2* a)
{
    if  */
FFFFFFFFFFFFFFFFF2turn 0;

    rery_rt1, modulus, *mp)FFFF",
        "12FFFFFFFFFFFFFFFFF2FFFFFFFFFFFFFFFFF2FFFFFFFFFFFFFFFFFF,
       The "b" valueFFFFFFFFFFFFFF*mp);) && fp_cmp(&P->zFFFFFFFFFFFFFF*mp);
*/
int ecc_projeined(USE_FAST_MAT2)

/* fast math a2celerated ve
      fp_489918EF109E15,
   C9B8899C47AEBB6F20BD3BB1BF07357FFFFF342E2FE1A7F9B8EE746B503F00",
  FFFFF "AA87CA22BE8B052FFFFFFFFFFFFFF*mp)FFFFFFFFFFFFFFFFFFuce(&
   /* T2 = X' * ulus  The modulus2of the field the 25C9B8899C47AEBFFFFFFFFFFFFFFFFFFFFFF    "C6858E06B moduCE9DA3113B5F0B8C34429C648139053FB521F83s
*/
int ecc_pFFFFF"51953EB9618E1C93c_point *P, ec modu5DBF55296C3A545E3               modu&P->x, &Q->x) ==35C8A5FB42C7D1BD993F54449579B446817AFus) t1, t2, x, y, z;
3  int    err;

  3if (P == NULL || 34088BE94769FD1d(&x,FP_EQ || fp_cmp(32C4247F8BCE6E5 }
  )) {
        ret3NULL, NULL
}
};


   "296",
        "4F3E342E2FE1A7F9B8EE37EB4A7C0F9E162BCE3nt* p);
int  ep_subAF606B4D3DBAA14B3hould we dbl inst3ad? */
   fp_sub(3e_add_point(ecc_pop_subFFFFEFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF        mp_int;
   ub(&x, &t2, &x);
, &Q->z) == FP_EQ3 &&
        (fp_c3c_point* P, ecc_pop_suFFFFFFFFFFFFFF;
   mp(&t1, modulus) Q)) {
        = Z *, &t1, &t1);
   ipoint(P, R, modul3s, mp);
   }

   3p_copy(&P->x, &x)3 mp_int* modulus,
   fpp_cmp_d(&y, 0) =3int map);
#ifd_mul(ulus, &x);
   }
 nt ecc_mul2add_mul(*/
   if (get_di3it_count(&Q->z)) 3
      /* T1 = Z'3                  ecc3CCC52973",
      3  "AA87CA22BE8B053378EB1C71EF320AD73nt* a, mp_int* p,3int* c);
int mp_s3rtmod_prime(mp_in3* n, mp_int* prim3, mp_int* ret);
inomer2C6F5D9E98BF9292D3C29F8F41DBD289A1437CE9DA3113B5F0B8C3#ifdef HAVE_COulus, Z' */
      fp_m
#endif
#ifdef* X =nt  ecc_projecti3e* out, word32* ou1);
 BD66",
        "3er for either , &xFFFFFFFFFFFFFF* X digit_count(mpmp_d( *mp);
 
   /* X FFFFFFFFFFFFFF
   }AF606B4D3DBAA);
 n a->used;
}

/* hmp_d(ulus, &x);
   }
 FFFFFFFFFFFFFF == F fp_add(&t2, &t2,a, int n)
{
  * X &t2, modulus, );
 FFFFFFFFFFFFFF
   fFFFFFFFFFFFFF9   f &t1, &t1);
      fp3montgomery_redFFFFFt1, modulus, *mp3)

/* fast matomercelerated vers
   }FFFFEFFFFFFFF00003951EC7E937B1652C30BD3BB1BF073573DF3   P        The po
   1 */
   fp_sub(&y3 &t1, &y);
   if 3fp_cmp_d(&y, 0) =3The destinatio(fp_c_reduce(&t2, modu1868783BF2F966= FP_ = T1 * X  */
   CC curve is in
   mp 4f (fp_cmp(&t1,8D8A    "C6858E06B70444E9CD9E3ECB6623954 MP_OKAY on succe4s
*/
int ecc_proj4ctive_add_point(e4c_point *P, ecc_p4int *Q, ecc_point ;
   BD66",
        "4fp_sub(&t1, modul45C8A5FB42C7D1BD99427D2604B",
    poinCE9DA3113B5F0B8C400FFFFFFFFFFFFoubleX */
   fp_sub(&4F3B9CAC2FC632551",312FAFFF",
        "142C4247F8BCE6E5he "b Double an ECC po33A0F4A13945D8he "point* ecc_new_po4nt(void);
void ec4_del_point(ecc_po433576B315ECECBB640AY onfp_copy(&y, &R->yif
#ifdef ECC3dbl_pR->z);
   
   ret     "ECC-384"dbl_p*/
   if (get_di4ecc_point* R,
  erFFFFFFFFFFFFFF fie (get_digit_count(&Q-4igit_count(&Q->z)4, &Q->z) == FP_EQ4 &&
        (fp_c4p(&P->y, &Q->y) =4 FP_EQ || fp_cmp(4P->y, &t1) == FP_4Q)) {
        ret4 Z = Z * X *
   if (f4 int ecc_mulmoy, &FA7E23EE7E4988= mp_ &z, NULL)) != M4EFE81411203140= mp_odulus of the fieint map);
#ifd, NULA2FFA8DE3348B9turnEA2DA725B99B315F3B8B4_point* A, mp_int4 kA, ecc_point* B4 mp_int* kB,
    4248B0A77AECEC1us, *== NULL)
       r  "AA87CA22BE8= Y *;

   if (P != R)46E1D3B628BA79B985us, *C2AEF",
        "rtmod_prime(mp_in4* n, mp_int* prim4    "3617DE4A9R->z2C6F5D9E98BF92mp(&C29F8F41DBD289 fp_s2, NULL, NULL, NU00A60B1CE1D7E819D7DD3ECfp_copy(&y, &R->y
#endif
#ifdef>x, &->x, &R->x);
    ,
        "ECC>x, &;
   if (fp_cmp(&er for either mp(&FFFFFFFFFFFFFF, NUFFFFFFFFFFFFFFFFFF   "Foint(ecc_point *P}

   /* T2 = T2 4 X */
   fp_sub(&4&t1, modulus, != FPnt  ecc_projecti4FFFFFFFFFFFFFF* T2 BD66",
      
   FFFFFFFFFFFFFFFFFFus,  (a == NULL)
    4   return 0;

   4return (n >= a->u4d(&t2, 0) ==* T1 = ;

   if (P != R)modulus, &t2);add(&1);
   }
   /* T2T1 */
   fp_mul(&QT1 = ;
   if (fp_cmp(&c yet */

/**
   4dd two ECC points4;

   /* Y = Y&t1, 2, NULL, NULL, NU &t1, &y);
    if (educe(&t1, modul4FFFFFFFFFFFFFFFFFFT1 =d(&y, modulus,&t1,  fp_copy(&P->y, &/2 */
   if (f if ( &t2);
   }
   /5f (fp_cmp(&t1,8    p_sub(&t2, &x, &5      fp_sub(&9
   429C648139053FB52
    X */
   fp_sub(&5
   fp_add(&t1ontgot1 = Z * Z */
  5cmp(&t1, modulontgo_mul(&t1, &t2, &5fp_sub(&t1, mo>y, 0CC53B0F63BCE3ecc.5F54449579B446817AF2 modFFFFFFF000000000500FFFFFFFFFFFFf (fp     fp_add(&t2,54088BE94769FD1f (fpFFFFFFFFFFFFFFA552C4247F8BCE6E52, &t89918EF109E156195 &t2);
   if (fp_cmp(5296",
        "4F5E342E2FE1A7F9B8EE57EB4A7C0F9E162BCE52);
   }
   /* T25= X + T2 */
   fp5hould we dbl inst5ad? */
   fp_sub(5e_add_point(ecc_po;
   &t1, &t1);
   fp5ecc_point* R,
ub(&FFFFFFFFFFFFFF     48B0A77AECEC196ACigit_count(&Q-      "AA87CA22BE8B053
        "FFFFodulul(&z, &Q->z, &z);
  5   fp_montgomery_5educe(&z, modulus5 *mp);
   }

   /5 Z = Z * X */
   5point(P, R, modul5s, mp);
   }

   5p_copy(&P->x, &x)5 mp_int* modulus,
   5                 5int map);
#ifdef 5CC_SHAMIR
static 5nt ecc_mul2add(ec5_point* A, mp_int5 kA, ecc_point* B5 mp_int* kB,
    5                  ecc5CCC52973",
         "AA87CA22BE8B053378EB1C71EF320AD746  fp_montgomery_r 2Z */
   fp_add(5rtmod_prime(mp_in5* n, mp_int* prim5, mp_int* ret);
in9F7411F4372DDF581A0DB2C29F8F41DBD289;
   ) && fp_cmp(&P->5#ifdef HAVE_CO;
   >x);
   }
   /* X&t1, &t2);
   if 5fp_cmp_d(&t2, 0) 5  /* X = X - T2 */
  5fp_sub(&x, &t2, &5);
   if (fp_cmp_5(&x, 0) == FP_LT)5{
      fp_add(&x51);
   if (fp_cmp5}

   /* T2 = T2 5 X */
   fp_sub(&5n a->used;
}

/* h&R->t1);
   }
   /fp_mFFFFFFFFFFFFFF
   rlus, &R->y);
   }a, int n)
{
  fp_m&t2, modulus, *mp5;
   /* T1 = Z * 51 */
   fp_mul(&z5d(&t2, 0) == FP_LTadd_psqr(&t1, &R->x);
modulus, &t2);, eccy, &t2, &R->y);
 celerated vers, eccto add
   R      montgomery_red     tion of the doubl;
   /* Y = T2 - T1 *51 */
   fp_sub(&y5 &t1, &y);
   if 5fp_cmp_d(&y, 0) =5_LT) {
      fp_a5d(&y, modulus, &y5;
   }
   /* Y = 5/2 */
   if (fp_i5CC curve is in
   6262CC6F5D9E98BF9292DCulus) != FP_LT) {6      fp_sub(&t1,6 MP_OKAY on sushoul&&
        (fp_c6
   fp_add(&t1>y, &nt  ecc_projecti6int *Q, ecc_point *R,6                 6           mp_int6 modulus, mp_digi6* mp)
{
   fp_int6t1, t2, x, y, z;
6  int    err;

  6if (P == NULL || 6 == NULL || R == NULL6|| modulus == NUL60,
   NULL, NULL,6NULL, NULL, NULL,6D_ARG_E;

   if (6err = mp_init_mul6i(&t1, &t2, &x, &6, &z, NULL)) != M6, ecc_point *R, mp_in6* modulus,
      6                 6    mp_digit* mp)6{
   fp_int   t1,6t2;
   int      e6r;

   if (P == N6LL || R == NULL |6 (get_digit_count(dbl_igit_count(&Q- }
  L, NULL)) != MP_6
        "FFFFr == t1);

   if (err FFFFFFFFFFFFFFr ==  /* T2 = Y * Y *6Q)) {
        9  erFFFFFFFFFFFFFFFFFFFF6 int ecc_mulmo->x,FA7E23EE7E4988E0566BE3F82D19181D9C66EFE8141120314088F65013875AC656398D86int map);
#ifdt(&Q-P->y, &t1) == MP_fp_sqr(&R->z, &t1);
 6_point* A, mp_int6 kA, ecc_point* B6 mp_int* kB,
    6* Z */
   fp_mul(6R->z, &R->y, &R->6);
   fp_montgome6y_reduce(&R->z, m62 */
   fp_s err = mp_41E082542A385502F625DBF55296C3A545E63872760AB7",
    6    "3617DE4A96262odulus, &R->y)&t1,C29F8F41DBD289A1477CE9DA3113B5F0B8C0
   /* &t2 = X - T1 *6/**
   Add two EC6&t1, &t2);
   if 6fp_cmp_d(&t2, 0) 6= FP_LT) {
      6p_add(&t2, modulu6, &t2);
   }
   /6 T1 = X + T1 */
 6FFFFFFFFFFFFFFFFFF 66,
  if (err == MP_OFFFFFFFFFFFFFFerr = *mp);

         &t1, modulus, err =P->y, &t1) == MP_FFFFFFFFFFFFFF */
             err =2);
   fp_montgomery_6 (a == NULL)
    6   return 0;

   6return (n >= a->u6&t2, &t2, &t1);
 6 if (fp_cmp(&t1, 6odulus) != FP_LT)6{
      fp_sub(&t6T1 */
   fp_mul(&Q_mul(err = mp_mul(&t1, mp_int z;
   int6   err;

   if (P6;

   /* Y = Yqr(&zmp_copy(&P->x, &x &t1, &y);
    (err_OKAY)
       err
   /* Y = 2Y */
   f6_add(&R->y, &R->y6 &R->y);
   if (f6_cmp(&R->y, modul6s) != FP_LT) {
  7   fp_sub(&R->y, 7odulus, &R->y);
 7 }
   /* Y = Y * 7 */
   fp_sqr(&R->FFFFFFFFFFFFFFFFFFFFFF
   fp_add(&t1, &7, &t1);
   if (fp7cmp(&t1, modulus)7  Double an ECC p7fp_sub(&t1, modul75C8A5FB42C7D1BD997* X = X - T2 */
   fp7t1, t2, x, y, z;
7  int    err;

  7if (P == NULL || 7     fp_add(&x, m7dulus, &x);
   }
7  /* T2 = 2T2 */
7  fp_add(&t2, &t27NULL, NULL
}
};


ecc7point* ecc_new_po7nt(void);
void ec7_del_point(ecc_po7nt* p);
int  ecc_7ap(ecc_point*, mp7int*, mp_digit*);7int  ecc_projecti7e_add_point(ecc_po_sub(*/
   if (get_di7r;

   if (P == N7LL || R == NULL |7(&R->x, 0) == ulus, &z, NULL)) != M7);
   if (err Y)
  educe(&t1, modul7c_point* P, ecc_poduluFFFFFFFFFFFFFF_sub MP_OKAY)
    p_cmp           err =  Z = Z * X */
_sub

   if ((err = m7_init_multi(&t1, 7t2, NULL, NULL, N7 mp_int* modulus,
&t1, &y, &t1, &y);
   P->z, &z);

   /*7if Z is one then 7nt ecc_mul2addrr == err = mp_montgomit_count(&Q->z    81F4372DDF581A);
                   _subR->z, &R->y, &rr =  "AA87CA22BE8 if (_OKAY)
       er72 */
   fp_sub if ( MP_OKAY) {
     25DBF55296C3A5_sub(r = mp_copy(&P->7, mp_int* ret);
inrr =odulus, &R->y)_subC29F8F41DBD289ulus,educe(&t2, modulu#ifdef HAVE_COulus,&t1, &t1, &t1);
 
#endif
#ifdef_add(A2FFA8DE3348Becc.7e* out, word32* ouFFFF1",
        "1FFF7er for either  != FFFFFFFFFFFFFFFFFFdigit_count(mp    e) {
      fp_add7= mp_montgomery_r7duce(&t1, modulus7n a->used;
}

/* help7 /* Y = Y * T1r ==  &t1, &t1);
   if == MP_OKAY)
    ereturn   MP_OKAY 7 (a == NULL)
    7   return 0;

   7return (n >= a->u7                     7 mp_int* modulus,7mp_digit* mp)
{
 7 mp_int t1;
   mp7int t2;
   mp_int7rr == MP_OKAY)
  7 mp_int z;
   int7   err;

   if (P7   P        The po    46B503F00",
     7   "1FFFFFFFFFFFF7FFFFFFFFFFFFFFFFF7The destinatio modu &t1);
   if (err &R->y);
   if (f7_cmp(&R->y, modul7CC curve is in
   mp 8d(&y, modulus, &y8odulus, &R->y)     ) && fp_cmp(&P->8 MP_OKAY on succe8s
*/
int ecc_proj8ctive_add_point(e8c_point *P, ecc_p8urn MP_OKAY;
}


/**
8  Double an ECC p8fp_sub(&t1, modul85C8A5FB42C7D1BD998  [out] The desti8ation of the doub8e
   modulus  The8modulus of the fi8 == NULL || R == NULL8|| modulus == NUL80,
   NULL, NULL,8NULL, NULL, NULL,8D_ARG_E;

   if (8err = mp_init_mul8i(&t1, &t2, &x, &8, &z, NULL)) != M833576B315ECECBB640, *mp&&
        (fp_c8int*, mp_digit*);8int  ecc_projecti8     "ECC-384")
   cmp(&R->y, modul8ecc_point* R,
;

 FFFFFFFFFFFFFFwill (get_digit_count((errT) {
      fp_add8&R->x, modulus, &8->x);
   }
   /* 8 = mp_copy(&P-== MP  if (err == MP_Op(&t1, modulus) !8 MP_LT)
         8rn ecc_projective_dbl8point(P, R, modul8s, mp);
   }

   * eccry_reduce(&t2,
   fp_copy(&P->y4 wolAY)
       err rr == MP_OKAY)
  if Z is one then * Cya MP_OKAY)
       er if (err == MP_OKit_count(&Q->zor modifry_reduce(&t2,248B0A77AECEC1he GNU G MP_OKAY) {
   X */
   if (err =      err = mp_su SoftP->z, &R->z);
   eithe      err = mp_omery_reduce(&t2,cmp_d(&x, 0) =ion) anyry_reduce(&t2,mp_add(&x, modulu distr == MP_OKAY) {}
   /* Y = Y * l be  MP_OKAY)
       e/**
   Add two EC; witd(&t2, modulus, - X */
   if (er= FP_LT) {
      ITY o = T2 - X */
  , &x, &t2);
   if T1 = X + T1 */
 NU Ge
   }
   /* T2 = T1);
   if (fp_cmpls.
 p_d(&t2, 0) == add(&x, modulus, ub(&t1, modulus, enera = mp_add(&t2,  {
       if (mpthis   if (err == Modulus) != Mthe Free Softwry_reduce(&t2,FFFFFFFFFFFFFFFranklinrr = mp_sub(&t&t2, &t2, &t1), MA 021= mp_montgomerymery_reduce(&R->CONFI  if (err == MT1 */
   fp_mul(&Qif

/* iT2 - T1 */
   i /* T1 = T1 * X     err;

   ifassl/ctaerr == MP_OKAY)_d(&t2, 0) == MP_ &t1, &y);
   <cyassl/ (err == MP_OKh>
#ix, &z);
   if (err(&y, modulus, &y)clude= MP_OKAY) {
   if (err == MP_OK1, &t1, &t1);
   C_ENC03F00",
      ulus) != FP_LT) {rypt/FFFFFFFFFFFFFF */
   fp_sqr(&R->ocrypt/a (err == MP_OKA &t2);
   } 
    -> m       err = mp(&t1, modulus) !ne EC       err = mp, &x, &t2);
   i192
#rr = mp_sub(&
#deft_digit_count(&Q-e ECCBB1BF073573DF88  "1FFFFFFFFFFFFFif (P == NULL || ngs.  clean up */
  py(&x, &R->x);
    /* T2 = 2T2 */
 to lf (err == MP_OKFFFFFFFFFFFFFFFFFcc_sets[FFFFFFFFFFFFFFi(&t1, &t2, &x, &4,
  f (err == MP_Ont* p);
int  eDB7C2ABF double
   R   mery_reduce(&R->"DB7Cmp_add(&y, mo076BE
       err = mp_c);
   if ( (fp_cmE891103F00",
       Double an ECC poi(&R->x, 0) == ",
     y_setup()
   reMP_LT)
         8",
 modulus  The mc_point* P, ecc_po7500"
},ojective_dbl_pomp_clear(&y);
   Q)) {
        ret128R1t] The destina int ecc_mulmoFFFFFFFFnt t2;
   int  }
   /* Y = Y * FFFFF= mp_mul(&t2, &y,,
   mp_int t1;
   m&x, &t2, &x);
  CEE5Ent t2;
   int  mp_clear(&y);
   modulus) != MP_LT     nt t2;
   int mp_sub(&t1, modulC5B86     err = mp_sub8395B NULL, NULL)) !err == MP_OKAY)
dif
#P_OKAY) {
        modulus  The mif (err == MP_,
                err =p_clear(&z);
FFFFFFF7F
       err = mp_c   if (err == MP_FFFFFr = mp_copy(&P-success
*/
int ec= Y*Y */
   fp_sqCF89F/* t1 = Z * Z *   return ECC_BAD, modulus, *mp);
1F4C8| modulus == NULL p_add(&t2, modulu88EF5t] The destina T1 = X + T1 */
      &t1, modulus, *if (P != R) {
   FFFFFFFFFFFFFF
},
#end          err 2, &x, &t2);
   if (f    "&t1, modulus, *mp_clear(&y);
   add(&t2, modulus,FEFFFt] The destinaT2 = T2 - X */
  FFFFF  if (err == MP= NULL || R == NUd(&t2, 0) == FP_LT4210519E  if (err == MP   modulus  The m mp_int t1;
      "FFF  if (mp_cmp(&R MP_OKAY)
      6BC9B, modulus) !=    err;

   ifEB03090F6if (err == MP_OKAY   err = mp_montg     OKAY)
       err == MP_OKAY) {
 The destinatio94811",
, &t2);
   if (P_LT)
           (&y))
        "ECC-224, &R->z);
   if (FFFFFFwo ECC points
FFFFF;
   }
   /* T1 }
   /* Y = Y *      ";
   }
   /* T1 z, &R->y, &R->z)FFFFFF&R->x, &t1);
    if (err == MP_OK50A850_add(&t2, modulus, &p_clear(&z);

  943235          err =   if (err == FFFFFFFFFsub(&t1, moduluserr == MP_OKAY)
    /* clean up 70E0CBD6B       if (mp_cmF3B9CAC2FC632551",80D6115C1     err = mp_mu mp_copy(&P->y, C22DFEt1, &t2, &t2);
   modulus, &R->z)",
},
       if (mp_cmE342E2FE1A7F9B 32,
      err = mp_a",
      d_point(ecc_point*0 &x, &t2);
   ght (CFFFFFFFFFFFFFFFF10    mp_digit* wolfSS
        "ECC-5210- Y */
   fp_sub(10R->x, &R->y, &R->10);
   if (fp_cmp_10 (get_digit_count(lus, dulus, mp_digit* m0p);
int  ecc_proje0ctive_dbl_point(ec0 = mp_copy(&P-   if  for either lib *0educe(&z, modulus10 *mp);
   }

   /10, &z);

   /* if Z is10one then these ar10FA7E23EE7E4988E05106BE3F82D19181D9C610EFE8141120314088F105013875AC656398D810->z)) {
         10 /* T1 = Z' * Z' 10fp_sqr(&R->z, &t1);
 10_point* A, mp_int*0 kA, ecc_point* B,0 mp_int* kB,
     0* Z */
   fp_mul(10R->z, &R->y, &R->10);
   fp_montgome10y_reduce(&R->z, m10 = X * T1 */
     err =if (err == MP_, modr == MP_OKAY)
mp);
 lus, &R->y);
   }
    "3617DE4A9, mododulus, &R->y);
 10 }
 
   return MP10OKAY;
}

#else /*10LT)
           err  err AF606B4D3DBAA14B5Eexport_x963_compre0ssed(ecc_key*, byt0,
        "ECC == MPBD66",
        "11);
   if (fp_cmp_10(&x, 0) == FP_LT)10 if (err == MP_OKAY)
10}
   /* T2 = X + 10= mp_montgomery_r10duce(&t1, modulus10 *mp);

         10 /* Y = Y * T1 */10           if (er10 == MP_OKAY)
    102);
   fp_montgomery_10 (a == NULL)
     0   return 0;

    0return (n >= a->us0&t2, &t2, &t1);
 10 if (fp_cmp(&t1, 10odulus) != FP_LT)10{
      fp_sub(&t10T1 */
   fp_mul(&Q->y10 &t1, &t1);
   fp10montgomery_reduce10&t1, modulus, *mp10;

   /* Y = Y - 101 */
   fp_sub(&y10 &t1, &y);
   if 10fp_cmp_d(&y, 0) =10 FP_LT) {
      fp_ad10 the double
   mod0ulus  The modulus 0of the field the E01, &t1, &t1);
   1B71E91386409",
C0045C>z, &R->z);
   }104E9CD9E3ECB662D998F4429C648139053FB521F8228AF606B4D3DBAA14B55E77EFE75928FE1DC1227A2FFA8DE3348B3C18856A429BF97E7E31C2EE5BD66",
        "111839296A789A3BC00455C8A5FB42C7D1BD998F5AY)
       err = mp_17273E662C97EE72 mp_adX  = T1 * T1 */
 D0761353C7086A2D998F5 mp_clear(&t2);
10",
},
#endif
{D998F5omery_reduce(&t21 NULL, NULL, NU;
   NULL, NULL
}
};


BD17271E91386409",
    int(void);
void->y, m_OKAY)
       errint* p);
int  e->y, m761353C7086A272C24                 1
int  ecc_proje  if e_add_point(ecc_po->y, mx, 0) == MP_LT)
  (&P->x, &Q->x) ==1                 if eturn   MP_OKAY o1odulus, mp_digi* Y = r = mp_sub(&R->x1ective_dbl_poiny, 0)  if (err == MP_OKAY)1* R, mp_int* moif (er,
   NULL, NULL, N MP_LT)
         1_digit* mp);
stif (e

   if ((err = m1p_int* k, ecc_p }

  if (P != R) {
  1, mp_int* modulus,
moduluif (err == MP_OKA int map);
#ifd }

  r(&t1, &R->x);
  int ecc_mul2add }

  mp_cmp_d(&R->y, 0)
           err =1, mp_int* kB,
    i                   )
  _point* C, mp_iC3E27   err = mp_cold the_sub(&R->x, &R->y,  if (err == Mld the for either lib *qrtmod_prime(mpturn  x, 0) == MP_LT)
  
      fp_add(&R->y, 1p_submod(mp_int6650",   "C6858E06B7040t* c, mp_int* dif (eUSE_FAST_MATH */
1KEY
static int  int   mp_mul(&R->y, &t1* T2 = T2 - X */
1te* out, word32* outLenn);
#endif

/* helpper for either lib  */
static int get__digit_count(mp_intt* a)
{
    if (a === NULL)
        reeturn 0;

    returrn a->used;
}

/* h   ret,
},
#endif
{
   0,,
   NULL, NULL, NR->x, &R->y);
   i a, int n)
{
  LL, NUs, &R->y);
   }

 = MP_OKAY)
      1 return (n >= a  [in                     1>dp[n];
}


#if (P =mp_digit* mp)
{
 1H)

/* fast matLL, NU  if (mp_cmp_d(&R-rr == MP_OKAY)
  1cc yet */

/**
, mod   err;

   if (P1
   P        The po&t1, 46B503F00",
     1  The point to f (errback to normal */
 }
   }

   /* Z 1f the double
  )
    tive jacbobian poi_cmp(&R->y, modul1ECC curve is in
   ecc_poulus, &y);
   }
1e from montgomeif (erdel_point(ecc_poin */
   err = mp_s1ss
*/
int ecc_pntgoment*, mp_digit*);
i== MP_OKAY) {
   1oint *Q, ecc_point >x, mo
           err =            mp_ mp_i   if (err == MP_1t* mp)
{
   fp_mp_mon mp_clear(&t1);
    int    err;
e(&P->1, &R->x, &t1);
 Q == NULL || R == N (er || modulus == ecc_pb" value from mon1      return EC_point, int n)
{
    if(err = mp_init_ ecc_dY - T2 */
   if (y, &z, NULL)) ! mp_i, ecc_point *R, mp_in1 err;
   }

    changmodulus, &t1);

 ead? */
   fp_sefine tmod_prime(mp_int1);
   if ( (fpefine );

   /* Z = 2Z1 FP_EQ) && 
   e(&P- (get_digit_count(&Q-1>z) && fp_cmp(&P->1z, &Q->z) == FP_EQ1) &&
        (fp_c1mp(&P->y, &Q->y) =1= FP_EQ || fp_cmp(1&P->y, &t1) == FP_1EQ)) {
        ret1urn ecc_projective_cc_maprr == MP_OKAY)
  us, mp);
   }

CC
sta  
   if (err == MLL, NULL)) != MP_1, &y);
   fp_co* k, emery_reduce(&R->1 if Z is one th
   /fp_sqr(&R->z, &t1)eld terr = mp_sub(&x, 1git_count(&Q->z_int*r == MP_OKAY) {
 1 * Z' */
      *G, ecdel_point(ecc_poin          err = m1_reduce(&t1, mo      = X * T1 */
     *G, ec               (1=r == MP_OKAY)
   1;
      fp_mont[8];
 t] Destination formp_add(&x, modulu1/* T1 = Z' * T1t = 1,err == MP_OKAY)
 z, &t1, &t1);
     _int*(&y, &x);
   fp_m1(&t1, modulus, ;

        err = mp_mul(,
        "ECC;

   projective)
   retp_sub(&t2, &x,ctive_out] The point tos, *mp);
   }

   /;

   == MP_OKAY)
    1qr(&z, &t1);
  ry_sett(&P->z, 1);

   /&t1, modulus, ry_set     err = mp_mon T1 */
   fp_mup_initodulus, *mp);

     fp_montgomery_red      err = mp_invmp_cleFFFFFFFFFFFFFFFFF1T1 */
   fp_muleld t&t2, &t2, &t1), moduAF606B4D3DBAA14B5(&t1, modulus, rn errA2FFA8DE3348B3C18 T1 */
   fp_mul(&Q, modu              mp__montgomery_redeld t   err;

   if_int*;

   /* Y = Y_pointe ECC curve is in
   "1FFFFFFFFFFFF1(fp_cmp_d(&y, 0;

  >x);
   if (err == MP_d(&y, modulus, &y)1;
   }
   /* T1 = 12T1 */
   fp_add(&1t1, &t1, &t1);
   1if (fp_cmp(&t1, mo1dulus) != FP_LT) {1
      fp_sub(&t1,1 modulus, &t1);
   py of (&R->x, &R->y, &R/
   fp_add(&t1_point               (1_cmp(&t1, modul_point
           err = fp_sub(&t1, mo == Nntgomery_reduce(&P/* X = X - T2 */
        lus)) != MP_OKAY)
   if (fp_cmp_err ==_E;

   /* tG = G 4088BE94769FD16650odulus, &x);
  p_copyr == MP_OKAY) {
  NULL, NULL, NULL, , &t2);
   if (fp_cpy of
/* size of slidinP_LT) {
      f      ();
   if (tG == Nnt* p);
int  ecc_m = X + T2 */
  dulus,if (k == NULL || ;
   if (fp_cmp = mpr == MP_OKAY)
       e{
      fp_sub(      duce(&R->y, modul  }

   /* if Z == N Y - T2 */
   if (digit_count(&Q-r = mpp)
#endif
{
   ec * Z' */
       = mp ecc_point *R, mp_int1    fp_montgome
   mpL || modulus == N, *mp);
   }

    
  t] Destination fofp_mul(&z, &x,  = mp   err;

   if (P1_reduce(&z, mod   is, *mp);

   /* T1 rojecttive_dbl_point(ecc(&R->y, modulus) !  fp_montgomeryb, whrr = mp_init_m_pointBD66",
        "1 * X */
   fp_sb, whcc_point *R, mp_intgomery_reduce(&x, t(ecc_e ECC curve is inT2 = T2 * x */
 (8+k)   digidx = 0;

 2);
   fp_montg (8+k)gomery */
   if (e   mu;
   mp_digitT1 = T1 * X  */(tG, fp_mul(&t1, &x, &t1);1
   fp_montgomery_1reduce(&t1, modulu1s, *mp);
 
   /* X1 = Y*Y */
   fp_sq1r(&y, &x);
   fp_m1ontgomery_reduce(&1x, modulus, *mp);
1   /* X = X - T2 */up sli      err = mp_copp_sub(&t2, &x, &t1d(&x, 0) == FP_   =  * Z */
   if (er1, modulus, &x); - 1;
    err = mp_add(- X */
   fp_su &mp)   err = mp_montgomeryp_cmp_d(&t2, 0)up slus, *mp);

   /* g_add(&t2, modul = bitrr == MP_OKAY)
    err = mp_invmod(& fp_sub(&t2, &xigidx = mp_montgomery_s_d(&t2, 0) == FP_LT      ding window */
   )
       err = mp_ }
   /* T2 = Tk;
           err = ecc_ < 8; i++) {
 k;
   mp_sub(&t1, modul(&t2, modulus,  &mp)   P        The poup sl   err = mp_montg1t1, &y);
   if  */
  r == MP_OKAY) {
1P_LT) {
      f */
  {
       mode   = _d(&t2, 0) == MP_1Y/2 */
   if (f  /* g mp_add(&t2, modulus,dd(&y, modulus, lea);
   }
   fp_d      [0], modulus, &mpcopy(&x, &R->x)      1, &R->x, &t1);
 y);
   fp_copy(e doub {
       if (mp_cturn MP_OKAY;
}


/atic i              mp_oint
   P   Thed(mp_idulus, &mp);
       [out] The ded(mp_i*G, ecc_point *R,  (err == MP_OKAY)
 modulus of the== 0  == NULL || R == NULL1n
   mp       Tntinuer == MP_OKAY) {
 tgomery_setup()}

   duce(&R->y, modulon success
*/
i== 0 i(&t1, &t2, &x, &1_point(ecc_poin      WINSIZE 4

/**
   Pert* modulus,
      1                  1     mp_digit* mp)1
{
   fp_int   t1,1 t2;
   int      e1rr;

   if (P == N1ULL || R == NULL |1| modulus == NULL | *R, mhe ltiplicand */
return ECC_BAD_first buf >> (DIGIT_BIT) {
      fp_cofirst {
       mode   =   fp_copy(&P->       MP_OKAY)
      1opy(&P->z, &R->z);
e addpoint(P, R, modul1p_init_multi(&t) breay(&M[bitbuf-8]->x,
   fp_copy(&P->y1OKAY) {
      rcopy(&MP_OKAY) break;

 

/**
  Map a proj fp_sqr(&R->z, &t1)z, &R-                 /it_count(&Q->z)) 1 *mp);
   /* Z      * Z' */
      fp_1&R->z, &R->y, &s fill    err = mp_add(ry_reduce(&R->z>y);
   int           i, j,= 2Z */
   fp_aas reqL || modulus == Nz);
   if (fp_c     /                            first = _sub(&R->z, moddulus,         /* if theLT)
           err_dbl_p        if (err !=L || modulus =  }
       err = mp_mon== FP_LT) {
     }
  uf-8]->y, &R->y);
p_sub(&t2, &x,>y);
* init montgom& i ==P_OKAY) {
       iic int*G, ecc_point *R, = NULL)
        reFP_LT) {
      as re&t1, modulus,    err*/
               montgomery_reduce1fp_mul(&t1, &t2     err = mp_mul(&t2, &y,1reduce(&t2, mod   }
 == -1) {
        = 2T2 */
   fp_     y_reduce(&t2, mod1  if (fp_cmp(&t                       iR->z, modulus) !=11, modulus, &t1);
   }1
   /* T1 = T1 + T12 */
   fp_add(&t11, &t2, &t1);
   if1 (fp_cmp(&t1, modu1lus) != FP_LT) {
 1     fp_sub(&t1, m1odulus, &t1);
   }1

   /* Y = 2Y */
 y > 0)            } else       /* skip leap_cmp(&R->y, mo(j = 0mp_sub(&t1, modul    fp_sub(&R->(j =modulus, &R->y)irst =, &t2, &t1);
 mp_cY */
   fp_sqr(&R->mp_inb(modulus, &Q->y,1gomery_reduce(&);
   {
       mode   =   /* T2 = Y * );
   projective)
   re &t2);
   fp_mo     s, &t1);
   }
   /odulus, *mp);
   /*);
     
   if (err == fp_isodd(&t2))                for (j =odulus, &t2);
            err = mp_mon&t2);
   /* Y =/
    odulus, *mp);

   R->y, &R->x, &R->y));
  rr = mp_add(&R      window, don't(err ![0], modulus, &mp = T1 * T1 */
 (err !1) {
             AY)
                 {
       if (mp_clus, *mp);
   /* X (err !uf-8]->y, &R->y);&R->x, &R->y, & mp_comery_setup()
ecc_pr(&R->x, 0) == ->z);
       err = ecc_pr
       }
   }       l(&t1, &t2, &the tX = X - Y */
   fp_)
  (&R->x, &R->y, ecc_p=8..15 */
   //* the              mp__LT) {
      fpecc_p int ecc_mulmod(mp&R->x);
   }

 if

ine ECC curve is in 
   fp_sub(&R->y, e_add_BCE6FAADA7179E84F3(&R->y, modulus) !) == FP_LT) {
    if       return MEMOdulus, &R->y);
   if duce(&R->y, modul */
   fp_mul(&);
    return err;
   }ecc_ppoint* C, mp_int* m              s, &mpnt mp_jacobi(mp_int }
               int* c);
int mp_sqrrtmod_prime(mp_int** n, mp_int* prime,t(M[j-9], tG, M[j-8], modulus, &R->y)mp_in
{
   mp_int tCC_TIMhe ltiplicand */
 USE_FAST_MATH CC_TIM modulus, &mp);
  if (err == MP_OKAY   The point to      MP_OKAY)
       eecc_pl(&t1, &y, &y);
 1   [out] The detinat*/
static int get_le
   modulus  modulu                if= NULL)
        reis in
   mp    );
     err = mp_montgomerytgomery_setup()ether tmod_prime(mp_int*R->x, &R->y);
   iecc_projective__int* c_point *R, mp_inP, ecc_point* Qt norm 0) {
            d(&t2, 0) == FP_LTtinatmontgomery_reduce1 mp_digit* mp)
      */
              _int t2;
   mp_      eturn MP_OKAY on sc yet */

/**
   A    err;

   if     grab the next msb from|| R == NULL ||t *R,  bitcpy = bitbuf p == NULL)
    us,
                  if              /* o mp_init_multi(u;
           err = mp_c         if (mode tLen)d(&y, modulus, &y1   }
   
   /*  = 0, e ECC curve is in? */
   err = m = 0,                   &t1);

   if ((k == */
                  if ( (mp_cmp(&P = 0, BD66",
        "1 && 
          RG_E;5C8A5FB42C7D1BD998->z) && mp_cmp(ontgomhe ltiplicand */
Q) &&
         modulubuf >> (DIGIT_BIT>y) == MP_EQ || mp_cmp1(&P->y, &t1) == MP1_EQ)) {
          1      mp_clear(&t11);
               1 mp_clear(&t2);
  1              mp_c1lear(&x);
        1        mp_clear(&ytgomer modulus, &mp);
 _clear(&z);

  s)) !={
       mode   =ecc_projective_s)) !=projective)
   reus, mp);
           */
   if (err == 1= MP_OKAY)
       e);

#i= 0, mode = 0,
      map      BooleaMP_OKAY)
      s)) !k to affine or not &y);
   if (er     }i = 0; i < 3; i++) projective)
   rez, &z);

   /* if Ztgome*/
#ifdef FP_ECC
se no-operationsc_new_ MP_OKAY) {
      ecc_point *G, ecc_(get_digit_coun   err         /* first  /* T1 = Z' * ULL)  {
                   _sqr(&Q->z, &t1
   /*if (err == MP_OKA == MP_OKAY)
       led so double as r_montgomery_red== MP_    err = mp_add();

           ULL)  = X * T1 */
         erow temps */
  for ) {
       if (mp1  err = mp_mul(if (ermp_sub(&t1, modul    if (err == ULL) 
{
   mp_int ttab */       err = ecc_pmery_reduce(&x, modtLen)EY
static int ecc_eexport_x963_compressp_init(&mu)) != MPOKAY) {
       if               eerr = (err = mp_montgome(&t2, modulus, &t2  if (err == MP_OKArr = urve is in
   map  = mp_montgomer  if (urn err;
   }

  /add_point(R,M[bitb  /* Y = Y * T1_projei = 0; i < 3; i++)add(&t2, modulus,1           err = mp_mu1l(&t1, &y, &y);
  1         if (err =1= MP_OKAY)
       1        err = mp_m1ontgomery_reduce(&1y, modulus, *mp);
1       }
   }

   1/* T1 = Z*Z */
   iuf = 0n err;
   }
   if c yet */

/**
   A&z, &t1);
   if= MP_ == 2 && bitcpy >     err = mp_mo      , &mu, modulus, &t          for (j = /* T2 = X' * T1 */helperp_init(&mu)) != MP;
   }
   /* Y = 1_mul(&Q->x, &t1 == 0)(err = mp_montgom MP_OKAY)
     eturn   }
   /* X =       MP_OKAY) {
     us, *mp);

   /* T1nt) DIurn 0;

    return (err == MP_OKAY)
    err = mp_mu      i = 0; i < 3; i++f (err == MP_OK      mp_sub(&t1, modulontgomery_reducULL)t1, modulus, *mp);
get_dit_count(k) - 1;
 /
   if (err ==      buf >> (DIGIT_BIT= mp_mul(&Q->y,      
   if (err == MPr == MP_OKAY)
 _pointuf-8]->y, &R->y);mery_reduce(&t1, mo                if (err = Y - T1 */
      &m[0], modulus, &mp       err = mp    &m         for (j = if (err == MP_ojecti {
       if (mp_c_cmp_d(&y, 0) == MP_int* et_digit(mp_int* aerr == MP_OKAY)
  s, &y);
   }
        Y - T2 */
   if ( (err == MP_OKA  }

  bitcpy = bitbuf d(&t1, &t1, &t1    &  /* calc the M tab, w {
       if (m mode - 1)) & 1;
        projective)
   re  err = mp_sub( mode   err = ecc_proje  }
   /* T1 = ], M[1if (err == MP_OKAYLL || modulus == NULL1 = mp_add(&t1, &y,1 &t1);
   if (err 1== MP_OKAY) {
    1   if (mp_cmp(&t1,1 modulus) != MP_LT1)
           err =1 mp_sub(&t1, modul1us, &t1);
   }
   /eturn        }

        y, &mu, modulus, &       err = mp               /* first if (err == MP_      omery_reduce(&t2,_cmp_d(&x, 0) =, &mp), mp_int* ret);
in     FP_LT) {
      fp1s, &x);
   }
  if (er       }

        #ifdef HAVE_COif (erP_OKAY)
                               if (err == M      MP_OKAY)
       eif (er_projective_dbl_poCC_BAD_ARG_E;

    err = mp_sub(&      * Z */
   if    /* if (err == MP_OKAYrst  = 1;

   r = mpl(&t1, &t2, &t2);
err = mp_add(&t2, &if (et1);
   }
   /* T1= MP_OKAY) {
  y, &R-modulus,
         tcnt == 0) {
 y, &R_ECC
static in     P_OKAY)
       /* ma       err = ecc_pif (err == MP_OKAY)[0]->z err = ecc_projectmode = 1;
     ecc_mM[2], modulus, &mp)nt = (int) DIG ecc_modulus, *mp);

   z, &Q->z, &z);
tG);
 
   }

   /* T2he t MP_OKAY)
         elperif (err == MP_OKAYmery_reduce(&z,

#end                   }
   }

   /*

#endA2FFA8DE3348B3C18err == MP_OKAY)nt* a,n err;
   }
   if&z, &x, &z);
   if   if ((a == NULL)
         }
   /* X = X -mery_reduce(&z,->useery_reduce(&P->x, * T1 = T1 * X  XMALLO        err = eccKAY)
       erry, &mp_mul(&t1, &x, &t1);
1   if (err == MP_O1KAY)
       err = 1mp_montgomery_redu1ce(&t1, modulus, *1mp);

   /* X = X 1* X */
   if (err 1== MP_OKAY)
      1 err = mp_sqr(&x, &NULL, */
              OKAY)
       erXFREE(_projective_dbl_puce(&x, modulusXFREE           if (err= T2 * x */
   id ecc[0], modulus, &mp      err = mp_mul(XMEMSP_OKAY)
       err(err == MP_OKAY (p !=ULL;
   }
   retury by
   G    The b, modulus, *mp)      if (err == MP_OKA */
   if (err _TYPE            err = mp_cmp_mul(&t1, &x,(p, 0,KAY) {
      XFREE         if (err !r = mp_montgome not
  NULL) {
      ret MP_OKAY)
       1 = Y*Y */
   if preva copy of G incase R==err = mp_sqr(&yXFREE_point();
   if (tMP_OKAY)
      tic iecc_point *G, ecc_reduce(&x, modu /* -1         /* first X - T2 */
   i prevfp_sqr(&R->z, &t1)ndex -ECC point from memint(M[1], M[2], morr == MP_OKAY)  prev248B0A77AECEC1urn 1;t* p)
{
   /* prevy, &mu, moduluecret l(&t1, &t2, &t2);
 &x);
   }
   /* T2XMEMSint* c);
int mp_sqrr == MP_OKAY)
The pun err;
   }
   ift2, &x, &t2);
 MATH)
init_multi(&p->x, rr == MP_OKAY)
   mp_d(&t2, 0) ==tic imode = 0,
            mp_add(&t2, modforms ber to check
  ret == NULL || R == N   if (err == Mlting ECC point from memCC_BAD_ARG_E;

   2);
   if (err  prevP_OKAY) {
       if (1mp_cmp_d(&t2, 0) =1= MP_LT)
         1  err = mp_add(&t21, modulus, &t2);
 1  }
   /* T2 = T2 1* Y */
   if (err 1== MP_OKAY)
      1 err = mp_mul(&t2,  wordT2 = T2 - X */
  1== MP_OKAY)
     if (t* p)
{
   /* prev&t2, &t2, &t1)  if (         for (j = Y = T2 - T1 */       {
       if (mp_cY)
       err = mp_ion, b         [out] Desc yet */

/**
   AY) {
       if   if  == 2 && bitcpy > P_LT)
         ate_ke    err = mp_add(dulus, &y);
   t    0; j < bitcpy; j++) {
err == MP_OKAY)RG_E;
 ecc_point*     re   mp_digit      berr = mp_add(&ynts
          if (first   if (err == M

   i       err = ecc_pmp_div_2(&y, &y);

   Add            word3)
       err = 
          err = mp_mon  if (err == MP
     ult;
   mp_int   p_copy(&y, &R->int()mery_reduce(&t2, m1OKAY)
       err = nts
  [0], modulus, &mp   /* clean up t(&pril(&t1, &t2, &t2);
   mp_clear(&t2t(&pri {
       if (mp_c  mp_clear(&y);
   errodulus, *mp);
he t return err;
}


/* modu
/* size of slidinint
   P   The  MP_OKkey* public_key,   [out] The des MP_OK       &mp);
    e
   modulus  Tlt, &p2         x = 0;
ld the ECC curve is MP_OKn err;
   }
   ifb" value from m;
   , DYNAMIC_TYPE_BIGreturn   MP_OKAn < x) MP_OKAY) {
     cc_projective_dKAY) {         for (j =, ecc_point *R, mp_int1* modulus,
       1                  1    mp_digit* mp)
1{
   mp_int t1;
  1 mp_int t2;
   int1    err;

   if (P1 == NULL || R == N1ULL || modulus == NsignedAXNAME) != 0)
     the domain paramsD_ARG_E;

   if   mp_ ecc_point*     ri(&t1, &t2, NUL   mp_ T1 = 2T2 */
   i != MP_OKAY) {

   ers, &t1);
   }
   /* X1  if (P != R) {signeap)
#endif
{
   ec&P->x, &R->x);
*outl(&x, &t2, &x);
  1KAY)
          key (i(RNG* rng, ecc_keycmp_d(&x, 0) == M1rr == MP_OKAY)
     20 t          first = P->z, &R->z);
 f succn = x;
   }

   mp(err == MP_OKAY)
1MP_OKAY)
      pon erif (err == MP_OKA&t1);
   if (er
   erKAY)
               br= mp_montgomeryated mmp_sub(&t1, modul *mp);

   /* Znewly
   if (err == MP_r == MP_OKAY)
      rme)) != MP_OKAY) {->x);
   if (err ==;
   if (err == MP__ARG_E_E;

   /* make net(&mu)) != MP_OKAY(&R->z, modulus ecc_se_type* dp);

/**
 _ECC
static in ecc_sP_OKAY)
      E || ec, &t2, &t1);
   if&R->z, &R->z);
   i acti       buf    = ge       if (mp_c_ex(rnr == MP_OKAY) {
  nt = (int) DIGIT_B err = mp_sub(&dx = x (key == NULL || r  }

           /*X - T1 */
   if (er 20 t) {
           /* err = mp_sub(&R;
   e, 0, x);
       er    i, j, err;;
   e_E;

   /* make ne   ecc_is_vali#ifdefodulus, *mp);

    = mp_add(&t2, modulus2 &t2);
   }
   /* 21 = X + T1 */
   i2 (err == MP_OKAY)
2      err = mp_add2&t1, &R->x, &t1);
2  if (err == MP_OK2Y) {
       if (mp_2mp(&t1, modulus) !== NULL MP_OKAY)
      2= mp_sub(&t1, m= (bymery_reduce(&t2, m2* T2 = T1 * T2 C_MAXS       err = ecc_2Y)
       err =ULL)
  = 0;
            2   if (err == MP_OK     projective_add_po2tgomery_reduce(  = dpSTACK
   buf = (by- ++bitcpy));
  = drr = mp_add(&R= (by window, don'ttring  if (buf == NULL)
 33576B315ECECBB640/* mak || rng == NULL ||ive_dbl_point(M[12
           errg, buf, mp_copy(&P->y, 2 &t1);
   }
   g, buf, for (i = 0; i < 2f (err == MP_OK&R->x) (get_digit_count(  = df (err == MP_Or == dx is valid or      l(&t1, &t2, &t2);2t1, modulus) !=      up the key variable (err == MP_OKr = MEMime, (char *)priv2* Y = 2Y */
   if (mp_subIZE, NULL, DYNAMIC_   err;

   ifulus, &, &t2, &t1);
   i2if (err == MP_Oulus, &;
#endif

   key->i the domain pa&R->x);up the key var, &t2,(&t1, modulu#endifdix(&prime,   (char *)key->dp->prime};

/* find a hole and free as required, return -1 if no MP_OKfound */
static int(err _MP_O(void)
{ree unsigned x;ree ordeerr =y, z
    for (z = -1, y = INT_MAX, x = 0; x <0000ENTRIES; x++) rr ==OKAYif (fp_cache[x].lru_count < y &&      err = mpock == 0== MP_OKAY)   &bas 
    rr == M, (c     err = mp_read_raf (err ==}ree }
ree /* decrease all*)ked_radix(->dp->Gx, 16);
   if (err == MP_OKAY 
       err = mp_read_rad> 3->Gy, 16);
  --      err = mp_read_ra)f (err =;
   if (err =
    entry z        
  z >= 0&base->y, (chz].g== MP_OKAYmp_clear(&cmp(&key->k,muf base poecc_del_point      err >k, &f (err =, &key->k);
   = NULL }
   /* rr = mp_read_un(1U<<000001)(err == MP_OKAY)(&key->k, &order, &key->k);
LUT[x]  }
   /* /* make the puprime,ic key */
   if;
    /* make the pup_read_raddp->
   if  read_radz;
} if (determine
   a bOKAYis already in the   errKAY) if so, where*)key->dp->order, 16p_cl(key-&orde* g(err ==orde 
     (err == MP_OKAYsigned_bin(&key->k, (byte*)buf, keysize);g !c key &bas (err == MP MP_mp           lear->x, &CLEA)y->dMP_EQ;
   mp_clear(&order);

#ifdef ECC_CLEyN_STACy
   XMEMSET(buf, 0, ECC_MAXSIZE);
#endif

#ifdefzN_STACz
   XMEMSEc_mulmod(&keybreak base point */
{ 
    xy->d6);
   if == MP_OKAY->dp-1MP_OKAY) {
      x/* cleanad == newmp_cletoey.x);
    )key->dp->ordeadd_= MP_(ordeidx,&key-&orde *ubkey.z) MP_OKAY) , y;f (err =allocatemp_cleAY) 0010      e    err idlear(=&key-new &order  }
   
       err NULL;

 c key == MP_OKAYead_radGEN_MEM_ERRMP_OKAY (err =copy x
    yAY) { 
    ( MP_opy(STACK,           NULL;
ACK
 ! XMEMOKAY) || (err ==e length of t CYAigest
  out      y[out] The destination for the signatu_BUFigest
  out      z[out] The des== MP_OKAYkey->k, &order, &key->kNULL;
  }
   /* make theNULL;

  key */
   ift
  in        The messag(err == MP *oue dig (err == MP_OKAY)
       err = ecc_mulmod(&y.z.dp = NULL;AY)
       key->k.dp = NULL;
L;
#endif
}


/**
  SAY)
     a message digesn, 
    , (c0; y < x; yecc_mulmod(&keyy
  return    MP_OKAY if succesprimy, 1);
   if (y)
{
   mp_int       y      key->type pe = ECC_PRy
  return    MP_OKAY if successful
*/
iny)
{
   mp_int   gerr == MP ECC_BAD_ARG_E;

y.z.dp = NULL;  if (err != MP_OKte* in, word32 inlen, byte* oetup dynamic ubkey.z.dp = NULL;  if (err != MPY) {
       The de/* cleanbuildey.x)0010by spacingey.x)bits ofey.x)input it #modulus/0000010into apart 
 *rr = T    lgorithm hash s patternsubkeinMP_OK bigbit order it first mak big) 
 r = != Mlm int
   /*  &e, NUL,ey.xnr;
  two= mp_read_radix(&p,
    so on
oid)key;
#ifndehash _lutT_MATH
   mp_ey->p the bid to digiuncapd to truncau)
{dx) ! NULL;
    ke, err,P_OKlen, lut_gapMP_OKto tru tmp_ARG_E 
  to trit(&tmp[out] The desDX validt
  in        The me (err =sanity checkkey)make surecountY) { 
tabllear(of correct size,valid_ishould compile outkey)a NOPrunctruvoid)     Then = of() > orders) /en = rr = mp_read_[0]))KAY)
       err== MP_OKAY)err = BAD_FUNC_ARGMP_OKAY) {else {>idx) !rr =getts = mp
    rhar *upkey)next multipBIT_000000010_SIZE;= MP_OKA =p);
 MP_OKAY_bin_n = ( the bi) << 3_validx
      re MP_OKA%0000001_validpoint== MP_OKAY MP_OKA+s is 0010- if (err}    if ount_bi
   }

   /* make up  if (erdowney.x)muits)
   till nte downength oy.z.dp = NULL;mu, sizMP_OKAY) { digest to sp_cle_SIZE;
   till t] The dest MP_OKA  The lemulmod) {
           eCLEAN_rr = te if h NULL || rng    err {
           eprim1]   [out] The destin  mp_clear(KAY) break;

           /* fiyd r = x1 mod n */
           err = mp_mod(&pubkey.pubkeyt] The max size a       if (err != MP_OKAY) break;

     zd r = x1 mod n */
           err = mp_mod(&pubkey.pubkey     A private ECC key
 ey);
  MP_MULMOD_E;  mp_clp dynamic *outlif (erZE * ) 
   err = mp_= MPies->pubkeyrr = mp_1>Gx, 16);ke u&key->k, (byte*)butille size, may be all err;
}


/* Setu  The length o mp_mod(&pubkey.pub<<(x-1)key.n */
           err  = mp_mod(&pubkey.pub<<xkey.x, &p, &r);
           if (or the sign = mp_add(&e, &s, &s);       y       /* s = e +  xr */
               if (erre(&pubkey);
           else         err = mp_mod(&s, &p, &s);       z       /* s = e +  xr */
               if (err     A private Gy, 16);
         if INIT_Ef (err == MP;
}


/* Setupo */
   (err == MPDX valid ?/* now dous)
  == MP_OKgnums */timk, &r, &pint           err;

  ount_bitf (in == NULL || out      till n key-rojective_dbLL || outlen == NULL || keif (e       /* s = e +  xrCC_BAD_ARG_E;
   }
   
== MP_OKAYcate if hash)[out] The dest
   }

   /* st
           
    ->z, 1);
   G_E;

   /* iamice);

          )
     err = key->k, , NULL)) !eAY) { 
of hamm bigweight &r, &p, &s);   2>Gx, c copy *(err == MP_OKAY) 
  err != MP_OKAY) break;
   ar(&p);
   mp_c        err;

  (1UL      err = (in == NULL || ouULL)
       return;

   mp_cleaear(&p);
   mp_clear 
  n(&e, (bytey].ham != T_MA)x) continue= NULL || rng mp_iszero(&s) == MPMP_NOperformey.x)init      }
    store as SEQUENCE { r, s -- f US&order)
       err = StoreECC_DSA_ig(out, outlen, &r_MATH
    #defp */aAY)
       err = StoreECC_DSA_oint to multiply
  kA       What to bultiple A by
  B        Second point to multiplyy);

   mp_clear(&r);
   mp_clear(&s);
   mp_cr(&p);
   mp_cleare);

   r break;

    Free an ECC kp from memory
baBIT_SIaff
   as a key)ZE * ->pubkaddition faster &r, &p, &s);   /* s = (&key->pubkey.y  if (key == NULL)
       return;

   mp_clear(&key-);

   rest tnvert z_BIT_ormal from montgomerinlen   ubkey);
     t ecc_mul2_reducerr = mp_mod(&s, &p, if (e;

   mp_cl*mpcc_m C, mp_int*iodulusi/
void e== NULL)
           if ulmod(&key-);
       veak;

           /*_point* B, mp_int* )
       err = StoreECC_DS            ecc_point* B)t* C, mp_ip_int* modulus)
#endif
{
  ec an ECCsquar           }
    c_point* sqr precomp[16];
  unsigned       bitbufA to byIDX validnsigned char* tA;
  unsigned char* tB;
 fix x   err = MP_OKAY, firs break;

           /*_point* he dter thbitbufA, bitbufB, lenA, lenB, len, x, y, nA, nB, nibble;x  unsigned char* tA;
  unsigned char* tB;
 r ==1/z^3/* argchks */
  if (A == NULL  || kt            muInit    = 0;
  int         eInit = 0;
  mp_digit mp;
  mp_int   mu;
 
 2add(ecc_poi*/
  if (A == NULL || kA == NULL || B ==  CYA || kB == NULL || C == NULL || 
                   modulus == yFFER);
  if (tA == NULL) {
     return GEN_M    KAY) { 
er) != MP_LT)
           , nB, nibble;
  uOKAY on  MP_LT)
  _BUFFER);
p_int* modulus)
#endif
{
;
   }

   /* ge       c_po_LT)nup &r, &p, &s)   mp_clear(&ky->pubkey.y);
   mp_clea == NULL || outlen == NULL || key == NULL |==NULL)
       return ECC_BAD_ARn too return    MP_OKAY if successful
*/ECC_PRIVATEKEY) {
      return ECC_G_E;
   }
   
   /* is the IDX v XMEMSET(tA, 0, ECC_BUFS ecc_mak0, ECC_BUFSIZE);

  ead_raderr/* cleanendif

#a;
 
edt* A, mECCE * mo *)key->dp->ordeaccel_fA ==  may need to trunck   key->pubkeRd to truncate if h)
       err = StoreECC_Dsh is longer t
   map(err#dec_mulKB_SIZE   M
FFF0def CYASSL_SMALL_STACK/
       wordchar* kb;
# */
point();
         kb[128]if ((&pri      err =  
     MP_OKAY)mp_rrderBits = mp_cbitpos_count_bi,    rets(&p);

     tnt* C, uncate down tokyte size, may be all that's       ecc_f       if it's smallerBihankB == NU we(erry, key->dp);_rshb(&e, CYASSL_BIT_k) >p_rshb(&e, CYASSL_BIT_SIZE - (&order) != MP
   Y) {  s;
   mp_inte down tY) { (&r);
   mp_clear(&s);
 0, ECC_BUFSkey->type !=
                balid_idxnit(&muf (err =Y) { 
M_ERR;
  , (c_rshb(&e, CYASSL_BIT_SIZE - (*/
   if (err == MP_    setsECC_n =  = ecc_mulmod(&key 
  yey* ( MP_OKAY)ry_calc_normaliz)r;
}


/* Setup dyn
  if (err normoffs);
we     okey.x)521P_OKAcurvy, key->lus);

  == 66) --if (err =  
         c_point* ey->_radixp_montg   keyalc_norm &preco16r(&r);
   mp_clear(&s);
   MP_LT)
  montgo;
   mp_cle);

  if (err == MP_OKAt and justifyit(&mu);
  if (errk must be less      }
    }
);

  if (errorder);k, _montgomery_seLT(&mu, modulus);

d(&A->y, &eak; if (err ULL,kr(&r);
   mp_clear(&s);
   mp&precomp[1]->z);

  if (p_mulmod(&A->z, &mu, modulus, f (err == MP_OKAY)
  eturn MP_OK      if (mp_iszer length  if err == MP_Oe);

   ulmod(&A->z, &mu, mod      if (mp_isecomp [i,0](A + B) tut, word_key_ex(rngr == MP_OKAY && (CYASSL_BIT_SIZE * inlen) > orderBits)
          mp_rshb(&e, CYASSL_BIT_SIZE - (orderBits  0x7));
   }

   /* make up a ey and export the public copy */
   if (rr == M_OKAY) {
       ecc_key pubp_iszero(&s)  if (ey.x)k valBIT_SIZE;
   _rshb(&e, CYASSL_BIT_     >N_MEM_(+) {
   - 2/* init montgo
  if (err == MP_Oead_radBUFFERcc_freee_key_ex(rngstornt(p*/     precomp[x] = ecc_new_poinkb f (err == M      )X= ecOC (err ==,onst , DYNAMIC_TYPE_TMP_t(precNULL;
#end     a messctive_add_poinMEMORYcc_f       ecc_XMEMSET(kb00000+) {
  NULL;
#endd(&A->y, &toshb(&e, CYASS, &m, kbr(&r);
   mp_clear(&s);rr = ecc_projectivn too */
  
  if (errle    reverse    so      littl == dian&precomp[1->dp->    muInit = 1;

  if (err == MP     - proper               errecc_prowh_BIT((err == MPx, 1yclear(&s);
  &baskb[x];    ni{
    yibble urn Eread_r  bitb++x; --yOKAY)
    err = mp_ma_poiist* A, mwx);
n start, yipe>x);

  if    ret  /*/
   if (err == ount_bi-/* s  if ; x--clear(&s);
   (kA)xtract00000010into ic in, prpey->T_SIZby(A + B) t
   if= MPffset_clear(&key->k) sig== 4) {
  y.x)y bytCC_SHAMIR

/** ecc_d   if (err == MPigned_bin&basrr;

  xr */
  key);
   }

   /* stz |= ((kb[ ecc_d>>3] >> ( ecc_d&7)) & 1(orde[0];
    = tB[x];
     +;; ) {
  ;ak;
      y*_OKAY) {+   kbut &key-or evera if )
       err = StoreECC_DSA_SfB = (bicc_inilp_re each loo= mp_uns
   returbble */
              ordeder, ret
        /* i 
  !e */
);
   }

   /* store as SEQUENCE { r, s -- integer } R, llocbitbufA, bitbufB, lenA, lenB, len if this isn't the first */
        iear(&r);
   mp_clear(&s);
   mp_cler(&p);
   mp_clear(&e);

   retif both zero, if initcontinue */
, otherwiset to s       if ((nA == 0) &&&basz);
   }

   /* store as SEQUENCE { r, s -- sing ShamiR,_BUFSIZE) || (lenB z]     2) & 0xFF;   
        bitbufB = (bitrst */
        if    mp_clear(&r);
   mp_clear(&s);
   mp_clele twice */
            if (err =o */
      );
   }

   /* store a      err = mp_mod(&s, &p, z== NULLR   [out] The destination fo

               err = mp_mulmod(&s, & if  CYARout] The max size and resul

               err = mp_mulmod(&rr =   err =R, &p, &pubkey.k);
         reak;

          if (ecc_is_valid_i not both zero */
        if ((nA != 0) ||  }
     ands */          if (err == Message digdp);
           if (err !=      }
ecc_pro 1; x < 4; x++) {
        fo        p Rulmod(ic in { r, s --l2add(eprecomp[1<<2]-apc_mulmod(&key- SEQUENCEmaprr =  break;
                 if (mp_iszer      if  /* ge>z, 1);
   if     precomp[x] = ecc_new_poinXFREE 4; x(err == MP_OKAY) {
    /* precom   for (#un pre+) {
  tract and justify kB    preECC_SHAMIRB */
    if (err == MP_OKAY)
        err = mp_to_unsigned_bin(k2addT_MATH
 1or (x idx2ul(&t2t the first */
        if (nB) + tA- lenB) + tBnt(C, C, modulus, &mp);
      ;

    /* allocate the table *) {
        f; x < 16; x++) {
            precomp[x] = ecc_new_point();
            [2     precomp[x] == NULL) {
  2]               for (y = 0; y < x; ++y) {
                    ecc_del_point(precomp, zA, zBts(&p);

    ka_BUFSIZE);
#enbts(&p);

    reduct* truncate down == timp[xa0](A ; x++)YNAMIC_   err = GEN_MEM_ERR;
                break;
            }
        }
    }
  }

  if (err == MP_OKAY)
    tableInitA = 1;

  if (err == MP_OKAY)
   /* init monerr == MP_OKAY)
    muInit = 1;

  if (err == MP_OKAY)
    err = mp_montgomery_calc_normalization(&mu, modulus);

  if (err == MP_OKAY)
    /* copy ones ... */
    err = mp_mulmod(&A->x, &mu, modulus, &precomp[1]->x);

  if (err == MP_OKAY)
    err = mp_mulmod(&A->y, & = mp_montgo= MP_OKAY)
    err = mp_mulmod(&A->tkbu, modulus, &precomp[1]-a>z);

  if (err == MP_OKAY)
   
         ** Computes kA, &mu, modulus, &precomp[1]->y);
  if (err == MP_OKAY)
    err = mp_mulmod(&A->   The corresponding public ECC key
   rulmod(&A->z, &mu, modulus, err == MP_OKAY)
    err = mp_muAlmod(&B->x, &mu, modulus, &precomp[1<<2]->x);
  Aif (err == MP_OKAY)
    err = mp_mulmod(&B->y, &mus;
   mp_0](A arecomp[1<<2]->y);
  if (err == MP_OKAY)
  The corresposponding public ECC key
   rmulmod(&B->z, &mu, modulus, &precomp[1<<2]->z);

  if (err == MP_OKAY)
    /* precomp [i,s;
 ic ECC key
 e */
    err = ecc_projective_dbl_point(precomp[1], p     return Emodulus, reak;
            }
        }
    }
  }

  if (err == MP_OKAY)
    tableInitBw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
   Verify an ECC signature
   sig         The signature to verify
   siglen      The length of the signature (octets)
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   stat        Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key)
{
   ecc_point  Blmod(&B->x, &mu, modulus, &precomp[1<<2]->x);
  Bif (err == MP_OKAY)
    err = mp_mulmod(&B->y, &mu the end. NULL, mp_int        u2;
   mp_int        e;
   mp_int        p;
   mp_int        m;
   int           err;

   if (sig == NULL || hash == NULL || stat == NULL || key == NULL)
   the   mp_int   e */
    err = ecc_projective_dbl_point(precomp[1], pey->dp->order if su the IDXf (err == MP_OKAY)
    err = ecc_projective_add_point(precomp[1], precomp[2], precomp[3],
                                   modulus, &mp);
  if (err == MP_OKAY)
    /* precomp [0,i](A + B) table */
    err = ecc_projective_dbl_point(precomp[1<<2], prrecomp[2<<2], modulus, &map);

  if (err == MP_OKAination for th            precomp[xbp);

  if (err == MP_OKA OKAY)
                 ECC key
        e;
   mp_int   dd_point(precomp[1<<2], precomp[2<<2], precomp[3<<2],
                    [0= 3;            modulus, &mp);

  if (err == MP_OKAY) {
    /* precomp [i,j](A      B) table (i != 0, j != 0) */
    for (x = 1; x < 4;[0] x++) {
        for (y = 1; y < 4; y++) {
         a   ie*)in,err == MP_OKAY)
                ned int orderBits = mp_count_bit_project mp_r(err == MP_OKAY) {
    /* precomp [at, ecc_key* key)
e_key_ex(rngint(precomp[x], precomp[(y<<2)],
                                         precomp[xa+(y<<2)], o */
       if (err    } 
  }  

  if (err == MP_OK {
    0] nibble  err        er  first&w, & = 1;
    bifA = tA[0];
  if successrecomp[2<<2],b size, may be all that's needed */
 1     if ( (CYASSL_BIT_SIZE * hashlen) > orderBits)
           hashlen = (orderB* fi a message digesT_SIZE * hashlen) > orderBits)
           mp_rshb(&e, CYAS!= 0) */
 T_SIZIT_SIZE;
       err = 1p_read_unsigned_bin(&e, hash, hashlen);

       /* mby sti1l need bit truncation too */
        err = mcc_projective_add                                precomp[xb+(y<<2)], modulus, &mp);
 The corre    } 
  }  

  if (err == MP_OKAY) {
    1err = mp_, &mQbkey.z, &  firstCC_SH = 1;
    bitbufA = tA[0];
    bitbufB = tB[0];

    /* for every byte of the multiplicands */
    for (x = -1;; ) {
        /* grab a nibble */
        if (++nibble == 4) {
            ++x; if (x == len) brea       err = m;
    fA = tA[x];
            bitbufB = tB[x];
            nibble  = 0;
     A    B   }

        /* extract two bits from Aboth, shi0]ift/update */
        nA = (bitbufA >> 6) & 0x03;
 zBboth, shi1      if (err == MP_OKAY)
           err = ecc_proje       nB = (bitbufBfB >> 6) & 0x03;
        bitbufA = (bitbufA << 2) & 0xFF;   
        bitbufB = (bititbufB << 2) & 0xFF;   

        /* if both zero, if first, continue */
        if ((nA == 0) && (nB == 0) && (first == 1)) {
            continue;
        }

        /* double twice, only if this isn't the first */
        if (first == 0) {
            /* double twice */
            if (err == MP_OKAY)
                err = ecc_projective_dbl_point(C, C, modulus);
   }

   /* store zAclear(&s);
   mp_cle (err == MP_OKAY)
                err = ecc_project1     ifAAY)
       err = StoreECC_DSA_Sr(&u2);
   mp_clear(&p* if not first,need bit truncation to  err = mp_copy(&precomp[nA + (nB(nB<<2)]->y, &C->y<<2)]->y, &C->yecc_dBl_point(mQ);

   mp_clear(&r);
   mp_clear(&s);
   mp_clear(&v);
   mp_2     ifB;
   mp_clear(&u1);
   mp_clear(&u2);
   mp_clear(&p);
   mp_clear(&e);
   mp_clear(&m);

   return err;
}


/* export public ECC key in ANSI X9.63 forma      if (mp_iszero   ecc_del_point(mQ);

   mp_            err = mp_add(&eclear(&w);f first, copy from table */
                          err = mp_mulmod   *outLen =y, &C->xP_OKAY)
                    err = m
   }

   if (key == NULL ||<<2)]->x, & &C->x);

                if (err == MP_OMP_OKAY)
                    err = mp_coy->k);
}


#ifdef USE_ublic ECC key in ANSI->y);

                if (eNSI X9.63 format */
int &baseands *>dp->Gy, 16);
   rmat */
int ecc_export_x963(ecc_mp_clear(&r);
   mp_clear(&s);
   mp_cleatiple A by
  B        Second point to muL_SMALL_STA);
   mp_clear(&e);
   mp_clern ECC_BAD_ARG_E;
   }
Len < (1 + 2*numlen)) {
 
      *outLen = 1 +ECC key in ANSI nB != 0)) {ore byte 0x04 1en != NULL) {
      numlen = key->dp->size;
   L_SMALL_ST = 1 + 2*numlen;
      return LENGTH_ONLY_E;
   }

   if (key == NULL - mp_unsignrr == MP_OKAY)
                    err = met != MP_OKAY)
         brea<<2)]->x, &C->x);

                if (err == MP_O  }
   numlen = key->dp->size;

   if (*outLen < (1 + 2*numlen)) {
      *outLen = 1 + 2*numlen;
      return BUFFER_E;
   }

rr == MP_OKAY)
         err = mp_read_unsigned_bin16);
   if (err == MP_OKAY)

                    err = ecc_project hashlen) > orderBits)
           mp_rsh#ifdef CY(erre_add_point(C, precomp[nA + (nB<<2)], C,
                                /* if not first, a clea*AY)
 Fr == P>pubk       global
  Computes kA*A + kB*montC u!= MPShamir's Trick
  A= 0x04;
F */
 ->pubkcc_p* inley
     ompresWh[0];ed)
{
   e A b if B= 0x04;
Secon= MP_OKAsed)
{
    if (ecc_expoed == 0)
        Beturn C= 0x04;
[out] Destinat* kA->pubk(everoverlap with A or Bble }
    }
 M
    }
, &s[1]->x
= mp_unsigned_biodulsuccess
*/ 

   ANSI k;
    ear(&key->p* reduce to ALL, DYNAMIC_TYPE_Tear(&key->pB reduce to affine */
    err =ear(&key->pCd to truncate if bkey.z);
       base->x  brbase->x         if ( */
I   e= mp_to_unsis lo    /]);
        muust  too );
       fo(& ecc_makULL)
       return;

   mp_ and justify         HAVE_THREAD_LSIZE;
   downMuteters p->Gy, 16);
  ECCubkey(&ANSIfp_*)keu, modulus,y->pubkey.x/
    famic poinLockkey->pubkey.z, &keyeed 0ble (i != 0, j eed MUTEX*/
    foracce if (mp_init_mreak n
 * accept if->pubke;

  if ( == NU     mp_clA        }
 an E== MP_?reak;
        & in[0or pclear(&s);
  f (err =MP_OKAY)      
        if ((RO_E;& in[0] != 0);
  )) /* gclear(&s);
   mpLen & f USE_FAST_   }
& in    if (err == MP_OKAY                   er&bas& in[!
   }

   if (in[0] ULL))ment LRU_dbl_point(C,++_OKAY if succ1the order of base poin       if (err odulus)
#endif
{
  e
   if (in[0] != 0x04 & && iey =     mp_clB        }
                err = mp_cop= 0x03) {
      err = ASASN_PARSE2E;
   }

   if (in[n[0] == 0x02 || in[0] == 0x03) {
#ifdedef HAVE_C x++) {
       compres   if (err == M       err = NOT_CO2,    i    if (err == MP_O  if (err == MP_OKAY) {
      /*2determine the idx */

      if (compressed)
          inLen = (2nLen-1)*2 + 1;  /* used uncompressed len */

   ize >= ((inLen        2 hash and load,_bin(&keyhigher jod(&u* ked load 
            break1  if (mp_cmp(&key-= (inLen-1)*2 + len2    }
      }
    ASSLute m 

        /* iint* A, mp_int* kA,
 setup_SIZE - , &BUFFER);
  iff (err == MP_OKAY) {
 clear(&s);
   mp_rn ECC_BA
    for ecc_point* A, mp_int* kA,
 calc_se
staiz_x963) {
 if not f      m;
   in<<2)]->y, &C->y);

&t2, &prime, &a, &b, NULL) != M   if (err == he hash and load e == 0) {
    prime, a,     /* we m   }
nit_multi(&tti(&= mp_mod(&ey->idx  = x;
          key->dp = &ec_read_unsigned_bin(&key->pubkey.x, (byte*)in+1, (inLen-1)>>1);

#ifdef HAVE_COMP_KEY
   if2(err == MP_OKAY && cod data */
  1) {   /* build y */, prec ECC_B4 */
   out[0] = 0x04;

        mp_int t1, t2, prim prime, a, b;

        if (mp_init_multi(&t1,  NULL) {
      numled)ecc_sets[x].size >= ((inAY)
            err = MEMORY_E;

    ;

        /* load prime */
        if (err == MP_OKAY)
            err MSET(buf, 0, ECC_BU= mp_read_radix(&prime, (char *signed)ecc_sets[x].si&t1, &key->pu load a */
        if (err == MP_OAY)
            err2= mp_read_radix(&a, (char *)key->dp->Af, f ((unsigned)ecc_sets[x].size >= ((inY
   if (er (mp_ 16);

        /* computempressed == 1>= 2 &&   mp_clear(&u1);
   mp_clear(&u2);
    /* compute x^3 */
     qrtmf (err == MP_OKAY)
            err = mp_sqr(&keypubkey.x, &t1);

        if (er== MP_OKAY)
            err = mp_mulmod(&t1, &key->p<<2)]->y, &C-)key->dp->prime, 16);

        /*            break;
        }
 )
     *s
   t co = mp_mulmod(&t1, &key NULL && out == NULLLen & se
sta_ANSI X9.63 f    A,inLe        err =  (char *)key->dp-      */
   if (mp_init_multi Un != MP_OKAY) {
      re_OKAY;

   /* check for 4, 2,  int          a, (c);
   and justify k   for (with
 * compression option */
int ec  kt2);

  nit_)
{
   ic mQ, &m,Gt2);

  BThe key, out, outLen);
#  R   return ecc_export_x963_of    duc      if

    rey->pturn NOT_COy.x);1]->);
   ap returnboolenB] Iorden-zerc_pop&mu,-1)>>1), normal_ecc_mulco-ordrt_xe */
    if (err ecc_projecomp[(yef 2) &jacobian-t ecc_mul2aif

f (err == MPAY) {
  p_cllic ECfulC ke ey in ANSI X9eak;lenB) + tB);

    /* aGB);

    /* allocate the table */
    if (err == (x = 0; x       errH
            if (err =E;

   /* must be odd */
   if     err = mpS(mp__BAD_ARG_E
   err = mp_mu   err = GEN_MEM_ERR;
                beturey */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                     NULL, NL, NULL) != MP_OKAY) {
      return MEMORY_E;
   }
   err = MP_OKAY;

   /* check for 4, 2, or 3 */
   if (in[0] != 0x04 && ix++) {
      G in[0] != 0x03) {
      err = ASN_PARSEE;
   }

   if (in[0] == 0x02 || in[0] == 0x03) {
#ifdef  XMEMSET(      , &t2, &primgned_bin     } else {
           err = NOT_CO, 0, *);

        ifrr == MP_OKAY) {
      /*determine the idx */

      if (compressed)
          inLen = (nLen-1)*2 + 1;  /* usedf ((unsigned)ecc_sets[x].siz;

       ed_bin(&key->pubkey.x, (byte*)in+1, (inLen-1)>>1);

#ifdef HAVE_COMP_KEY
   if(err == MP_OKAY && copressed == 1) {   /* build y */
        mp_int t1, t2, prime, a, b;

        if (mp_init_multi(&t1, &t2, &prime, &a, &b, NULL) != MP_OKAY)
        
        mp_it(&pubkeRR;
  }
  X
   word MEMORY_E;

        /* load prime */
        if (err == MP_OKAY)
            err = mp_read_radix(&prime, (char *)key->dp->prime, 16;

        /*  compute x^3 + a*x + b */
        AY)
            err= mp_read_radix(&a, (char *)key->dp->Af, 16);

        /* load b */
;

        if (ret != 0)
        return ret;

    r == MP_OKAY) {
         
   wor((mp_isodd(&t2) && in[0] == 0x03) ||
               (!mp_isodd(&t2) && in[0] == 0x02)) {
                err = mp_mod(&t2, &prime, &key->pubkey.y);
            }
      char* k     return MEadix(    mod(&prime, &t2, &prime, &key->pubkey.y);
        , &mu, G     return MEMAY)
        errn err;
p_clear(&b);
        mp_clear(&prime);
        mp_clear(&t2);
        mp_clear(&t1);
   }
#endif

   if (err == MP_OKAY &if (helper funct* kA,orn GEN bignum ;
    ...st beod(&B->c }
 dt, outy.x);
    mbkey.*)kee *)key->dp-> if , errfp_ GEN   err  if (err == MP_OKAY)  key-  mp_clear(&key->k);
   }
   ecc_del_point(base);
   mp_clear(&prime)clear(&s);
  igned_bin_size(kB);
  len  = MAX(lenA, lenB is this a private key? */
  L || key == NULL || rng ==NULL)
     return ECC_BAD_ARG_E;

   /* is this a private key? */
  f (key->type != ECC_PRIVAKEY) {
      return ECC_BAD_AR MP_LT)
            - lenA) + veName ECC curve n   /* is the IDX valid ?e->y, (char *)key-precomp[nAut, word32r *)ke           essedF        compression    (void)    mp_clear(&rt  if (err       return ECC_BAD_ARG_E;

   if (ecc_is_valid_idx(key->idx) == 0) {
      return ECC_BAD_ARG_E;
   }
   numlen = key->dp->size;

   if (*out      reKAY;

   /* check for 4, 2, or 3 */mp_clear(&rtmp);
  = 1 + 2ear(&b);
        mp_clealear(&prime);
        mp_clearoutLen, reekey->pubkey.z, &key->k,
                 MP_OKAYKAY;

   /* check for 4, 2, ub,
KAY;

   /6);
CC 2, o    pre if (    ENCRYPT


enum ecCliSt = Ntive_aecCLI    e      re12)]-> (err == MPSALT_GET  mp2  err = mp_read_radixS&key->3  err = mp_read_rENT_REQ  mp4  err = mp_read_RECV_RESP = 16)err = mp_read_eed STATE = 99ad an   iread QySrv
    if (err =SRVP_OKAY)
        err = mp_r(x =radix(&key->pubkey.y, qy,; x++) {
  if (err == MP_OKAY(x =1);

  p_set(&key->pubkey; x++     m  /* read and set (x =curve */
    if (err ==
strucn ANEncCtxif (errcond(&Byte* kdfSaltP_OK/* opt* kal saltture
kdf   if (e     if (ecc_seInfo].size == 0) {
 info       err = ASN_PARSE_E;
  macts[x].size == 0) {
          mac   if (eword32signesets[xSz].size n = 1)>>
      dp = &ecc_sets[x];
     }      key->type = EC   }dp = &ecc_sets[x];    key      key->type =    keyits)
    yteL) != clientts[x[EXCHANGEP(ecc_sZ]ufB >>  keysg exchangbreak;
  RIVATEKEY;server   err = mp_read_radix(&key->k, d, 16);
    }

    if (err != encAlg} elssize which>pubry= 0)  typ }

    if (err != kdfkey.y);
        mp_key deriv_x963_Y) {
    >pubkey.z);
        mpmabkey.y);
        mp_y->dr;
}


/* key size in octets */protocolP_OKAY)
    we REQ(curve
     en);MP_OKA    err = RIVATEKEY;
  Sx].siP_MEM
#e0;

       te,->k, ( (CYASSL_BI &precompf (err != M) {
eturn from ecc_sign_hash for actual value
   of           if (eccANSIctx_get_own_    (}
      * ctx(err ==mp;

ctin(&kime);||etur->ecc_sign_     == MP_OKAY)
    key */z;

    retu_HEADER_SZ + 4->size;
_CLIENY)
    err =  */
}


#ual r + 4 == MP_OKAclear(&s);
   mp* number of mp_read_radix(&k(&t1, &key->puead_rad* number      e(char *)key->dp->A_projective_add/
#ifndef FP_ENTRIEt the curve */
P_ENTRIES 16
#endif

CC_BAD_ARG_E;
       mndef FP_L */
}


#ifdef FP_ECC

/* fixeSERVERt ECC cache */
/* num in of entr(x = 0; he cache */
#ifndef Fr FP_LU!= 0; x++) {
   P_ENTRIES 16
#endif

/* nuMP_OKAY) {ts in LUT */
#ifndef FP_LUT
    #define FP_Lively
  {
             f ECC_SHAMIR
    /* Sharmir requires a biggf (err == MPkey */ub,
ze == 0) {
  ep_refo, everero(&stmp)bef<2],or af    set_peer < 0)   i in ANSI
   ecc_ /* 
        retur,N_PARSE_E;
   /* ca
   szn sz;

    return sz * 2 +     /    2 + sz <4;  /* (4) worst caeed bit trunca= ASN_


#ivate ke  mp /*  MEMORount of timeS&bassz if (err == MP0oint* y->dp->     i      6);
    ixed  = "SecnlenMessage E);
    ";
U<<FP_LUT]; /* fipoint* LUpoint lookup */ 
   mp_int      n sz;

 RIVATtmprr = mp_read_radi/{
  _OKAY on half*/
  D_LS this cache isstimate */
}

r *)key-2 + SIG_HEADER_SZ + 4;nstan LUT + CYASSL_BIT_S      lru_count;       /* am */
}


#ifdef FP_ECC

/* fixed point ECC cache  1; CPY #errorP_OKAY) {,
#ifn,ing needed */
stay->k,
      /
/* number of entries radix(&k6);

        /def FP_ENTRIES
    #definSe
    #if (FULL && out == NULL def FP_ENTRIES
    #ly
    #endif
#endif


/** Oureed ENCve */
cc_free(&pubs a bigger LUT, Tex inits */
    static mber of biex ecc_fp_lock;
#endif /* HAVE_THREAD_LS */
r FP_LUT must be to help direct the generaively
    #endif
#eltatic const struct {
   int ham, termively
    #endi_orders[] = {
   { 0, 0, 0 }, { 1, 0, 0 }, { 1, 0, 0 }, { 2, 1,  if (ermix, no break16 },t1);
  /*THRE[2<<2]s 2
   { 2,    

/* wase poinverwritbreak;
  /
    st || k4 }, { 2, 2, 4  +, no lo,, no lon MEMOR{ 2, 1, 4 }, { 2, 2, 4  16 }, { 5,atic CyaSSL_Mutex 15, 16 }, 
   { 1, 0, 0 }CyaSSL_Mutex || k 15, 16 }ry has been u 1, 3  mp/* number of bits in 2 }, 
   { 2locking needed */
sta4, 7, 32 }, y->type  8, 32 },FP_LUT < 2)
     }, { 4, 13,, { 4, 11, 32 }, { 3, 12, 32AD_LS */
ivate ke        p;
   int  ean ufa<< 2)  key */
  y has been used  32 }(     if (ec)dicate cache (&t1, &keys been used */
  r = mp_reINFO 3, 1err == MP_O   lock;            /<<FP_LUT]; /* fited (0) or not (1) *orderlags, RNG* rnubkey.z)p_cache_t;
Buffell nse estimate */
}

fp_cache_t frnign a mes2 +  FP_Lti(&keyTHREAD_LS
    static volatile int i 2, 1, 64 }, (, 5, 64 }

/* fixed point ?, 16 }, { 4, 14, :) || (FP_LUT < 2)
, { 4, 28, 3RNG_GenerateB*)ke(rngex ecc1, 64 _fp_lock;
#endif /* H          /    mp_cl
   down { 6, 31, 32 }, 
#if FP_Ln sz;

    retuutex inits */
  x < p */ 0,igned_bi}
      ) mp_unsignedount pubkey.  mpecAES_128_CBC, 32 }, { 4, 25, 3, 26, 64 }HKDF    256, 32 }, { 4, 25
int ec 5, 29,MA     { 5, 30, 64 }, { 6EADER_SZ + (RIVA) FP_L, &t2, &pri 
   9, 64 }, { 3, 10, 64 }, T
    #define FP_LUT     8U
#end   e HAVE_THREAD_L{ 3, 36, 64 }, { 4 (FP_LUst be between 2 and 12 inclusive}, 
   { 3}int* g; .y.dwkey)R FP_SIZEre    so1);
r doesn't hav key)down/ GEN_    resBIT_SI<<FP_LUT]; /{ 6,  64 }, { 3, 20,  > 6
   { 1, 0, }, { 3, 3, 64 }, { 2, 4, 64 },   int        lru_count;       /* am }, { 4, 19, p */ 



#ifdef FPn MEMORkey in ANSI5, 30, 32 },  64 }, { 6, 59, 64,
   {oint* g; .y.dp/    eif (eet, 20, 32s_read_radcc_kC 64 }, , 8,        re4 }, { 6newT_MAT FP_LUT > 6
   { 1, 0,    err = 5, 6* qy,
            retur 3,         rulus, &mp   { 3, 24, 64 } }, 
= MP_OKAY) {
ECC 4, 7, 3 }, { 4,64 }, { 3, 33, 64 }, { 3, 34, 64 }, { 4, 35 6, 12 64 }, { 5, 51p */ 7, 63,;

    r 6, urn M1, 0, 0 }, 4 }, { 6if (k{ 4,, 32 }, { 4,  return ECC_B struct {
   ectvoid eif (e     ny64 }ources,  lenr 23, key &pre8, 64 }, { 4,if (k        return sz;

    retu, 22, 64 }, { 5, 23, 64 }, 
   { 3, 24, 64 }, { inits */proje 64 }, 
128 }, { 4, 11, 128 { 5, 45, y->dp->ordeANSI if keyL_BITs 64 }, { 3, 20, 64 *>pubKey{ 5,28 },ivSp, &s); /* s = (e + xrurn MP_OKAY o*128 }Lmp_cc_sets* digest{ 5,8 }, { 4b*)keS         /* copy { 3, 18, 12switch/
}


#pubkey.he cache */
#ifndThe  }, { 5, 27, :&t1, &key->pubkey* { 4, 37 = KEY {
   5, (&t1, &key->pubkey*, {      reIV28 }, 64, 50, 128 }, { 5, 542, 128  mp, { BLOCK {
  (&t1, &key->pubkeyr(&p);
   mp_clear( 20, 32}, 
   { 3, 48, 12    lru_count;           /* if both zero, 128 }, { 5,
int ec8 }, { 5, 46, 128 }, {    { 2, 32,}, 
   { 3, 48, 128, 41, 12 = 2, 32,_DIGEST6, 55, 128 }, 
   { 4, 56, 128 }, { 5, 57, 128 }, { 5, 58, 128 }, { 6, 59, 128 }, { 5, 60, 128 }, rime, &t2,THREAD_LS
    static volatile int i*3, 40,   mp8 }, { 4, + 51, 12+ }, { 3, 6nt        lock;      (kA)cc_clear(&t, outshare 7
 c 6, rukey.roughp_cl, 730, 1ho &p,non, 20, 32 mult break   /*sst besgSzits + CYbhar* cre
*/
->typ    pubkey., i.e.,(&key->pupadded{ 3,    lock;t public EC{ 4, 50, 64 clear(&formakeym ecivKeorde, 92, 128ub { 6, */
         sgLL, DYNAMIC_TYPE_Tc_sets[28 },,if (eccout8 }, { 4, ou 128         return sz;

  8 }, { 3, 128 } 60, 1c_sets[x];4, 52, 128, { 5, 101, 128 }, 5, 78, 128, { 4, 7, 128 }, .dp lC22,     precomp[x] = ecc_new_poinif (ecc6, 61, 1{ 4, S, 128
   {  107, 128 }, 28 }if (precompnature size}, { 5, 108, 12[    MAX{
  x(&key-&premax, 87, of signature size28 }, {{ 4, BUF, 128 },turn from 13, 128 }, {        fo, 101, 128 }, { 5, 10{ 4, 4, 112, 12per thread,09, 128 }, {Len{ 5, 120, 128 }, {  { 4, 37{ 5, 120, 128 }, { , { { 5, 120, 128 }, {       /  }

, 116, 128 28 },      /if do bigd, 16);
    }

    if (e, 128 },  { 4, 8 }, { 6, 109, 128 encIv8 }, { 6, 109, 128 ma, 256 , { 3, 178 }, { 4, 64 }, { 3}, { 64, 64 }, { 3d, 1n sz * 2 + _SIZn sz * 2 +, 38, 128 }, { 5, 39, 128 },, 98, def HAVE_THREAD_LS
    static volatile int initMute }, { 4, 19 { 3,);

{ 1, 0,    if (err = }, { 4, 19, &, { 5, 1TYPE }, { 3, 20, 128, 18, 256;rr = mpe);

   re { 5, 15, 128 }}, { 4, 35, 12p */ & { 4, 37, &, { 4 &3, 40, 12&, 41, 128, 38, 128 }, { 5, 39, 128 }, &42, 128 }, { 3, 17, 128 }, THREAD_LS
    st 128 imate */
}


#ifdef FP_ECC

/* fixe (FP_LUT < 4)
    128 }, { 6, 121, 128 }, { 6, 121, *(ecc 4, 35, 64 }, }, { 2, 1, !nclusive
       42, 64 }, { 5,, 0 }, { 1, 0, 0 }, { 1, 4, 25, 64 }, d 12 inclusively
    #en     e're done03) m poinpr(&klowRO_E;
*)key->dp-UT, TAO */
    #if (FP_LUT > 12) ||d point ECC cache */
/* number of, { 4 LUT */
stat { 5, 39, 256 }, 
   { 3, 40, 256 }, { 4, 41, 256 },UT     8U
#end      mp3, 25only dy)
{    n break;
   4, 21, 256 }, i,j](256 }, > 128 128 }, )8 }, { 8,128 }, { 5, ve_add_point(precomp[1<< 5, 58, 256 }, (28 },%42, 128 5, 29, 256 }, { 5, 30,eed PADDING}, { 4, 4AD_L*256 },<
   { 2 +, 128 }, ) 3, 65, 256 }, { 3(precomp[5, 128 }, { 5, 106, 128 }, { 6,{ 5, 108, 12 3, 34, 128 }, { 3128 }, 
   shlen) > orderBits)
           mp_rshbAD_L6 }, { 4, 73, 6, 55, 64 }, 
   { 4, 5!= 0) */
 nsigne8 }, 256 }, { 4, 74, 256 128 },  75, 256 }, { 4, 76, 256 }, { 5, 77, 256 }, { 4,tion ecc_key struc, 128 { 5, 108, 12shlen) > orderBits)
           mp_rshb(&radix(&mG->y, (char *))key->dp->Gy, , 15, 128 }{ 5, 1_1, 12856 }, { , }, { 6, , 256 }, 
   {& { 7, 11128 }, { 3, , 256 }, { 3, 18, 1, 128 }, { 5,64 }, {clear(&s);
   m}, 
   { 64 }, { 5 }, 
   { 3, 48, 1 73, 2{ 5,(2, 32,, 95, 256 }, 
   { 7, 11 }, { 6
   { 2, { 4, 26, 256 }, { 5, 27, 2 3, 10, 32 }, , { 5, 105   }, 108, 256 },  }, { 4, 26, 256 }, { 5, 27, 2, { ,4, 256 }d(&t1, &key->pubke_point* C, mp_i 57, 128 }, { 5, 58, 128 },  73, 2eed bit truncatio err = mp_copy(&precomp[nA3, 6, 16 }, {{ 4, 97, 256 }, { 4, 98 { 4,  34, 25 +}, { 3, 60, 128  { 3,, 64  256 }+128 }, { 7, 1234, 256 },56 }, { 7, 123, 256  +, 124,  { 4, 98, 256 }, { 5, 45, 128 }, { 5, 46, 18 }, { 6, 47, 128 }, 
   { 3, 48, 1       /* compute x^3Aes aes(&t1, &key->pubkey 256 }, {AesSetKey(&a
   }, { 7,9, 128 }, { 4}, { Ivnt(C, C, modulus, &mp);
            else
              31, 256 }, {ES);

    IONd(&t1, &key->pubkey 256 }, { 5, 29, 256 }, {

   return err;
}


/* export public , 256 }, { 4Cb
   }, { 256 },7, 12 7,  128 }d(&t1, &key->pubke<<2)]->y, &C->y);, 113, 256 }, { 5, 114, 256 }, { 6, 115, 256 }, { 5, 116, 256 }, { 6, 117, 256 }, { 6, 118, 256 }, { 7, 119, 256 }, 
   { 5, 120128 }, { 6, 62, 128 }, { 7, 63, 128}, 
   { 2, 64, 128 }, { 3, 65, 128       /* compute x^3Hy->dhmac 256 }, { 4, 145, 256 }, { 56 }, 134, 2 { 5, 128 }, ECD 5, 13128 }, { 4, 67, 12{ 5, 141, 256 }, { 5, 142, 256 }, { 6, 143, 256 }, 
   { 3, 144, 256 }, { 4, 145, 256 }, { 56 }Update65, 256 147, 256 4, 148, 256 }, { 5,56 }, { 5, 169, 256 }, { 5, 170, 256 }, { 6, 171, 256 }, { 5, 172, 256 }, { 6, 173, 256 },  }, { 4, 13,56 }, { 6, 181, 256 }, { 7, 175, 256 }, 
   { 4, 176, 256 }, { 5, 177, 256 }, { 5, 178, 256 }, { 6, 179, 256 },Final 256 }, { 6+, { 4, 148, 256 }, { 5, 149, 256 }, { 5, 150, 256 }, { 6, 151, 256 }, 
   { 4, 152, 256 }, { 5, 153, 256 }, { 5, 154, 256 }, { 6, 155, 256 }, { 5, 156, 256 },60, 128 56 }, {=128 }, 56 }, { 4,, { 5, 71, 256 }, 
   { 3, 72, 25 6, 87, 256 }, 
   { 4, 88, 256 }, { 5, 89, 256 }, { 5, _projec56 },e_add_point(C, precomp[nA + (nB<<2)], C,}, { 5, 30, 256 128 },   { = MP0, 128 }, { 4, 81, 128 }, { 4, 82, 128 }, { 5, 83, 128 }, { 4, 84, 128 }, { 5, 85, 18 }, { 5, 90, 128 }, { 6, 91, 1, 209,  5, 92, 128 }, { 6, 93, 128 }, { 6, 94, 128 }, { 7, 95, 128 }, 
   { 3, 96, 128 }, { 4, 97, 128 }, { 4, 98, 128 }, { 5, 99, 128 }, { 4, 100, 128 }, { 5, 101, 128 }, { 5, 102, 128 }, { 6, 103, 128 }, 
   { 4, 104, 128 }, { 5, 105, 128 }, { 5, 106, 128 }, { 6, 107, 128 }, { 5, 108, 128 }, { 6, 109, 128 }, { 6, 110, 128 }, { 7, 111, 128 }, 
   { 4, 112, 128 }, { 5, 113, 128 }, { 5, 114, 128 }, { 6, 115, 128 }, { 5, 116, 128 }, { 6, 117, 128 }, { 6, 118, 128 }, { 7, 119, 128 }, 
   { 5, 120, 128 }, { 6, 121, 128 }, { 6, 122, 128 }, { 7, 123, 128 }, { 6, 124, 128 }, { 7, 125, 128 }, { 7, 126, 1/

   256 } key, f FP_LUT > 8
   { 1, 0, 0 }, { 2, 1, 256 }, { 2, 2, 256 }, { 3, 3, 256 }, { 2, 4, 256 }, { 3, 5, 256 }, { 3, 6, 256 }, { 4, 7, 256 }, 
   { 2, 8, 256 }, { 3, 9, 256 }, { 3, 10, 256 }, { 4, 11, 256 }, { 3, 12, 256 }, { 4, 13, 256 }, { 4, 14, 256 }, { 5, 15, 256 }, 
   { 2, 16, 256 }, { 3, 17, 256 }, { 3, 18, 256 }, { 4, 19, 256 }, { 3, 20, 256 }, { 4, 21, 256 }, { 4, 22, 256 }, { 5, 23, 256 }, 
   { 3, 24, 256 }, { 4, 25, 256 }, { 4, 26, 256 }, { 5, 27, 256 }, { 4, 28, 256 }, { 5, 29, 256 }, { 5, 30, 256  { 7, 63, 256 }, }


#ifdef FP_ECC

/* fixed point ECC cache , { 3, 34, 256 }, { 4, 35, 256 }, { 3, 36, 256 }, { 4, 37, 4, 50, 256 }, {     mp 256 }, { 4, 52, 256 }, { 5, 53, 256 }, { 5, 54, 256 }, { 6, 5256 }, { 5, 43, 256 }, { 4, 44, 256 }, { 5, 45, 256 }, { 5, 46, 256 }, { 6, 47, 256 }, 
   { 3, 4 (FP_LUT < 4)
        #error FP_L, { 4, 38{ 5, 51, 256 }, { 4, 52, 256 }, { 5, 53, 256 }, { 5, 54, 256d 12 inclusive
         { 4, 56, 256 }, { 5, 57, 256 }, { 5, 58, 256 }, { 6, 59, 256 }, { 5, 60, 256 }, { 6, 61, 256 }, { 6, 62, 256 }, { 7, 63, 256 }, 
    { 2- }, { 4,  % 42, 128  }, { 3, 65, 256 }, { 3, 66, 256 }, { 4, 67, 256 }, { 3, 68, 2-6 }, { 4, 69, 256 }, { 4, 70, 256 }, { 5, 71, 256 }, 
   { 3, 72, 256 }, { 4, 73, 256 }, { 4, 74, 256 }, { 5, 75, 256 }, { 4, 76, 256 }, { 5, 77, 256 }, { 5, 78, 256 }, { 6, 79, 256 }, 
   { 3, 80, 256 }, { 4, 81, 256 }, { 4, 82, 256 }, { 5, 83, 256 }, { 4, 84, 256 }, { 5, 85, 256 }, { 5, 86, 256 }, { 6, 87, 256 }, 
   { 4, 88, 256 }, { 5, 89, 256 }, { 5, 90, 256 }, { 6, 91, 256 }, { 5, 92, 256 }, { 6, 93, 256 }, { 6, 94, 256 }, { 7, 95, 256 }, 
   { 3, 96, 256 }, { 4, 97, 256 }, { 4, 98, 256 }, { 5, 99, 256 }, { 4, 100, 256 }, { 5, 101, 256 }, { 5, 102, 256 }, { 6, 103, 256 }, 
   { 4, 104, 256 }, { 5, 105, 256 }, { 5, 106, 256 }, { 6, 107, 256 }, { 5, 108, 256 }, { 6, 109, 256 }, { 6, 110, 256 }, { 7, 111, 256 }, 
   { 4, 112, 256 }, { 5, 113, 256 }, { 5, 114, 256 }, { 6, 115, 256 }, { 5, 116, 256 }, { 6, 117, 256 }, { 6, 118, 256 }, { 7, 119, 256 }, 
   { 5, 120, 256 }, { 6, 121, 256 }, { 6, 122, 256 }, { 7, 123, 256 }, { 6, 124, 256 }, { 7, 125, 256 }, { 7, 126, 256 }, { 8, 127, 2158, 256 }, { 7, 159, 256 }, 
   { 3, 160, 256 }, { 4, 161, 256 }, { 4, 162, 2RIVATverify[128 }, { 4, 67, 12 per th }, { 4, 162, 256 }, { 5, 163, 256 }, { 4, 164, 256 }, { 5, 165, 256 }, { 5, 166, 256 }, { 6, 167, 256 }, 
   { 4, 168, 256 }, { 5, 169, 256 }, { 5, 170, 256 }, { 6, 171, 256 }, { 5, 172, 256 }, { 6, 173, 256 }, 256 }, { 4{ 5, 60, 556 }, { 7, 175, 256 }, 
   { 4, 176, 256 }, { 5, 177, 256 }, { 5, 178, 256 }, { 6, 179, 256 }, { 5, 180, 256 }, { 6, 181, 256 }, { 6, 182, 256 }, { 7, 183, 256 }, 
   { 5, 184, 256 }, { 6, 185, 256 }, { 6, 186, 256 }, { 7, 187, 256 }, { 6, 188,}, { 3   { 3, 144, 512 }, { 4, 145, 512 }, { 4, 146, 512 }, { 5, 147, 512 }, { 4, 148, 512 , preemer);}, { 3}, {  +128 },  { 3, 65, ,6 }, { 4, 6 }, { 6, 143, 256 }, 
   { 3, 73, 2 proper 256 }, { 5, 149, 256 }, { 5, 150, 256 }, { 6, 151, 256 }, 
   { 4, 152, 256 }, { 5, 153, 256 }, { 5, 154, 256 }, { 6, 155, 256 }, { 5, 156, 256 }, { 6, 157, 256 }, { 6, 56 }, 
   { 2, 128, 256 }, { 3, 129, 256 }, { 3, 130, 256 }, { 4, 131, 256 }, { 3, 132, 256 }, { 4, 133, 256 }, { 4, 134, 256 }, { 5, 135, 256 }, 
   { 3, 136, 256 }, { 4, 137, 256 }, { 4, 138, 256 }, { 5, 139, 256 }, { 4, 14DE 256 }, { 5, 141, 256 }, { 5, 142, 256 }, { 6, 143, 256 }, 
   { 3, 144, 256 }, { 4, 145, 256 }, { 4, 146D{ 5, 21 { 5, 147, 256 }, { 4 512 }, 
   { 3, 144, 512 }7, 190, 256 }, { 8, 191, 256 }, 
   { 3, 192, 256 }, { 4, 193, 256 }, { 4, 194, 256 }, { 5, 195, 256 }, { 4, 196, 256 }, { 5, 197, 256 }, { 5, 198, 256 }, { 6 { 3, 65,  }, 
   { 4, 200, 256 }, { 5, 201, 256 }, { 5, 202, 256 }, { 6, 203, 256 }, { 5, 204, 256 }, { 6, 205, 256 }, { 6, 206, 256 }, { 7, 207, 256 }, 
   { 4, 208, 256KAY;

   /* che 16);

     2, opubkey.x, qx,COMP_KEY}, 
       m{
    _clear c4, 8a | n) (or Legend    f near(prime)r = HAC pp. 73 key.i(&r, 2.149= MP_ion op__clearexport ecad to truncfor (x* c(err =
        a1, p
     { 4, 100k,  0 }_rea32, 2E;

   /*residM
#e
ubSz, ecpey* 0AY)
    errVAL}, { 5<<2]->x);
_d(pTYPE_TMP_BUGetween 4 a 7, 235, 512 2 },16 },mp[2<ep 1. 6, 2ary co_read_rad0}, { 6, 236, isP_OKA(alti(& }

   if* }, recomp[;
   }

   /* ge, 239, 512 }, 
2  { 5, 240,1_read_rad1}, { 6, 236, 512 } (a,2 },#endif

   retur243, 
    fo{ 6, 244, 512 }, { 7, 245, 20, 32 56 }, 4, D_ARG_512 }, 
3.  }, { 3a    1 * 2**k{ 2, def HAV 16        for (;; (& 231  mp_int        u2;
   5, 30, 232, 216 }, 255, 512 }, 
   { (&p1&e);
   mp_clear(&m);rr = ecc_pa1 }, { 5, 60, 6, 512 }, { 4, 51ividIT_SIZlarger pow you wy->d { 9,r* qrr =nt_lsb 262, 512 512 }, 
div_2d6, 512 if  231 55, { 6, { 4, 9 }, {load b */
     512 }, 
4  { 5,lear(even7
   s=8, 247, 4, 259k (bitb 256 }, { 4, 912 }
    fo      if (mp_is }, */
 , 512 },, 512= 1/7 _SIZ 8)worst=ix(&or 5123/5 { 5, 278!= 0x04 &512 },  = p->dp    & 7 if ((unsigne80, 512 }= 1, { 2, 512 }, {78 }, { 4, 44, component o mp_to_unsi83, 512 }, 36, 283, 512 }, 5 5, 284, 512 },  4, 168, 53, 6, 16 }, { 4, }, 
5  { 5,     3 { 5, 4) *and* 254, { 5, 291, 5char 288, 256 }, {  59, 51 { 5, 281, 3 { 4,3)&bas((a1.12 }, { 6, 295, 274, 512 }, { -32, 256;
}


 512 }, { 5, 270, 512 }, { 6, 27 5,  4, 2156 }, { 4, 412 }, { 5,  }, 
   { }, { 248, 512 }, { 7, 24249, 512 }, { 5512 }, { 4, 276, n= NU  }
  254,  { 4, 280,(&B->y, & , { }, { 60,    
         { 5, 270, 512 { 5, 90, 257, 512 23, 512260,, 308, 5mu, , { 6, 309, 512 }, { 6, 310, 512 , 304, * _OKAY)
5, 298, 5if fi, 512 },rr = ecc 260, }, { 6, { 7, 3162, 5_IN;
}


/, 512128 , { 5, sqrtmod_, 512export ecn 229, 512 } 512d to truncre

/* if { 4r
   l 512 },,6, 316, 512 });

    1     Q, S, Z, M, T     tw4, 32E;

   /*i{ 6, 234yte 0xhandlhar* csim    8 },256 }, , 236, 512 },nTYPE_#endif

   returmp_P_OK, 97 }, { 5, 60, 64, 512 }, { 7 6, 236, 512 },  4, 3221, 512 }, { M_ERR;
         , { rom ecim errd(&B->o ECC_SHA/* TAO removeQ, & 255, 512 }, 
228, 51n, { 4, 32& { 4, 32&e);
   mp_clea }, { 5, 30, 232, 2FAST_ 512 }, ;
   }
}, { 5, 337, 512*/ 339quadr>dp->!= M83, 512 }, { { 5, 2, or  255, 512 }, 
   {  XFREE(t   {C, &Q, &S, &Z, &M&e);
   mp_cle512 }, { 5, 263,  { 7, 349, 512 }, { 7, 350, 5Tr ==y->dwo05, 256 { 5, 356,  69, 256 }, 512 }, { 6, 358, 2 }, { 4, 261, 512 }, { 4, 2t1);2 }, { 4, 2C, 360, 512 },Q, 360, 512 },S, 360, 512 },/* HAVE_rr = ecc_pM, 512 }, { 5, 263, 512 }, 
  SPECIAL CASE:277, { 5, 3291,4, 29 4,         mpdi inlly:, { 7, n^ 512 }+1)/46, 348, 51 { 5, Handbood(&A Applied C09, ography_multi(&r, 3.36 { 5,{ 9,307, 512 }, 5, 512 }, 43, 2 512 309, 512 }, { 6, 3if (e 295, 52 }, { 37, 512 f US, 512 },    { 5, 56 }, { 4, 912 }, { 6, 310, 512 7, 512 }, { 4, 512 },{ 7, 80, 512 }, { 8, 381, 512 }, { 8, 382, 512 }, { 9, 383, 512 }, 
   { 3, 384, 512 }, { 4, 385, 51exp 320, 51512 }512 },  { 6, 512 } 512 },
    2 }, { 6NOW: TonelliShankr(&k}, { 6, 2, or76, 512 }, { 7, 377, 5 512 }256 },    if (eactor}, { { 4,      2
       imee->x 16;  bigQT > 7p_clea, 128 },  4, 400, 512 }, { 5, 401, 512 as:{ 6, 398 = Q*2^(&t1);
  , 512 }, ngth 2 }, { 6Q, 512 }, 
   { 3, 384, 512 }, { 4, 385, 51sub_d(8, 3   { }, { 6,/* Q }, { 5, - 8, 247,, 309, 512 }, { 6, 310, 512 , 512 }, 512 5, 408,S }, dp = &ecc   } 
512 }, { 7, 377, 5 }, {, 2712 }sage digest
 382, 512 }, {, 35 }, { 6, 408, 512Q / 2reak;
        }, { 8, 381, 512 }, { 78, 512 }, { 8, 351,    {}, { 6,  6, 412, 51S +, 409, 51216 }, { 4,err == Zk);
    [0];
e4, 512 }, symbol (Z|, 512 6, 345512 }, { 6, , 512 }, { 6, 406, 512 }, { 7, 4 fixet(512 2, { 6, 412Zy->p }, { 7, 413, 512 }, { 7, 414, 512 }, 
   { 4, 4228, 51512 2 }, { 6, 342, 51}, { 6, 309, 512 }, { 6, 3&bas12 }, { 6, 345, }, { 4,         
        6, 419, 512 }, { 5, 420, 512 }, { 6, 421Z 512 }/* HAVE_THRE{ 8, 43Z 7, 423, 512 }, 
   { 5, 387, 512 }, { 4, 388, 512 }, { 5, 389512 }Q512 }, { 7{ 3, 33,{ 8, C43, 5^ Q6, 348, 512 },80, 512 }, { 8, 381, 512 }, { 8, 382, 5 6, 4212 }, 
 83, 512 }, 
   { 3, 384, 512 }, { 4, 385, 512 }, { 4, 386, 512 },6 }, {, 51(Q 7, unsi1, 512 }, { 5, 387, 512 }, { 4, 388, 512 }, { 5, 389, 512 }, { 5, 3& mp_rshb/* R 5, 3^ (57, 512 }, ) 449, 512 }, { 5, 450, 512 }, { 6, 451, 512 }, { 5, 4{ 5, 389, 51 512 }, 
  T, { 6, 412T12 }, {, 449, 512 }, { 5, 450, 512 }, { 6, 451, 512 }, { 5, 4ngth o1, 5, 512 },/* M}, { , { 5, 450, 512 }, { 6, 451, 512 }, { 5, 4}, { 7, 42 },  512 { 7, 413, 512 }, { 7, 414, 51 395, 512 }, , 512 }, 
   { 6, 472 355 456, 512 }i* qy,
       
   { 5, 432, 512 }, { 6, 433,330, 512 }, { 6512 }248, 512 }, &t1, &key->pur(&p);
   mp_cl 446, 512 }, { 9,  9, 38 }, , 512 }, 456, 512 } }, { 6, 419, 512 }, { 5, 420,  i++t, public key in ANS512 }, { 7, 377, 512 },, { 3, 18, 12 { 6, 472R 390, 51487, 512 }, 
    if (err == M, { 6, 391, 51err == MP_OKAAD_L{ 9, 479, 512 }, 
 490, 512 }, { 8, 491, 512 }, { 7 }, { 7, 407, 51M, i, 512 }, { 7, 490, 512 }, { 8, 491, 512 }, { 7 }, { 7, 407, 51, 485 { 7, 504, 512 }, { 8, 505, 512 }, { 8, 506, 512 }, { 9 6, 488, 5 }, , 461, 512 },12 }, { 7, 49, { 6, 42, { M - i 6,  
   { 4, 22 }, { 9, 509, 512 }, { 9, 510, 512 }, { 10, 511,  { 8 
#if FP_LUT > 10
   { 1, 0, 0 },C, {  { 2, 1, 1024 } }, 
   { 5, 464, 5{ 8, 501, 512 }, { 8, 502, 512 }, { 9, 503, ;
  int 461, 512 }, { 4, 448,8, 512 },(t54, t1 { 3, 9, 1024 }, { 3, 10, 1024 }, { 4, 11, 1024 }, { 3, 12, 10 break;
, 512461, 512 }, { 7, 46, 462, 512 (R5, 15, 1024 }, 
   { 2, 16, 1024 }, { 3, 17, 1024 }, { 3, 18, 1024 }, { 4,  355C, 512 }, { 6, 468,468, 512 },(T * C { 3, 9, 1024 }, { 3, 10, 1024 }, { 4, 11, 1024 }, { { 7, 4}, 
  , { 4, 14, 10273, i2 }, { 6, s a bigger2 }, { 6, 316, 512 }, { 7, { 5,  }, { 4, 35, { 3, 3, 361, 512 },4 }, { 4, 37,}, { 6}, { 7, 363, 512, { 6, 364, 512 rr = ecc_p 6, 46rr = ecc_pecomp rr = ecc_prwo512 }, { 8, 319, 512 }     port, { licAY)
 

  in ANSI X9.63.z);
at 512 ressRO_E;
6, 91, 12024 }_x963_ 6, 47, 10 5, 92, 12k, 13{ 4, 97, 128 }, { 4, 9 { 4cess *c_sets[numl1, 128  { 4, 1 73, 2gned_bin_size85, 256 2, 8, 256 }, { 3, 9, 256 1, 102456 }, { 6, 79, 25ead_rad 82, ADtrun80, 256 .x, &cc_is_valid_idx 6, ->idK
   X, { 3, 18, , { 5, 58, 1024 }, { 63, 33, 1024 }, 34, 2{ 5,->alizaE_TMP_BUF56 }4 },     + }, 
  5, 512 }, 
 1024 }, },  66, 102ount_bits(&p);

       /* trunrecomp[2<<2],yte 0xRIVAT, { 5,out       }, {odd(6 },->pubkey.y { 40x03 :, { , 36, 2 */
adT > 7
<<2], /* argc 1; x <  2560000006, 1024 63,  73, 2 < 4; y++) {
        { 4, 73, 10        /* s = e +  xr11, 256+ { 3(}, 
   -                precomp4 }, 
   { 3,)8 }, { 7, 1024 }, { 3, 68, 1024    { 4, 208, 256 },d     - b { 5, c 
   , 
   { ub/* export ec, 229, 512 bd to trunc }, Y)
     (err = { 4, 1012 }, { 6, { 4,56 }, , 259, 512 }, { 3, 26t}, { 3, 257, 512 }, { 3, 258, 512 }, { 4, 259, 512 }, sub{ 6, b4 }, 512 }, { 4, 261, 512 }, { 4,95, 1 512 }, { 5, 263, 512 , 307, 512 }, { &1, 2, d 512 }, { 7, 318, 512 } { 8, 319, 512 }KAY;

   /* che}, { 7, ey->pu219, 512 }, { 6, 24 }