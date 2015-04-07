/* test.c
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

#include <cyassl/ctaocrypt/settings.h>

#ifdef XMALLOC_USER
    #include <stdlib.h>  /* we're using malloc / free direct here */
#endif

#ifndef NO_CRYPT_TEST

#ifdef CYASSL_TEST_CERT
    #include <cyassl/ctaocrypt/asn.h>
#else
    #include <cyassl/ctaocrypt/asn_public.h>
#endif
#include <cyassl/ctaocrypt/md2.h>
#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/md4.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>
#include <cyassl/ctaocrypt/sha512.h>
#include <cyassl/ctaocrypt/arc4.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/coding.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/camellia.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/dh.h>
#include <cyassl/ctaocrypt/dsa.h>
#include <cyassl/ctaocrypt/hc128.h>
#include <cyassl/ctaocrypt/rabbit.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/ripemd.h>
#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>
#endif
#ifdef HAVE_BLAKE2
    #include <cyassl/ctaocrypt/blake2.h>
#endif
#ifdef HAVE_LIBZ
    #include <cyassl/ctaocrypt/compress.h>
#endif
#ifdef HAVE_PKCS7
    #include <cyassl/ctaocrypt/pkcs7.h>
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#ifdef OPENSSL_EXTRA
    #include <cyassl/openssl/evp.h>
    #include <cyassl/openssl/rand.h>
    #include <cyassl/openssl/hmac.h>
    #include <cyassl/openssl/des.h>
#endif


#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048)
    /* include test cert and key buffers for use with NO_FILESYSTEM */
    #if defined(CYASSL_MDK_ARM)
        #include "cert_data.h"
                        /* use certs_test.c for initial data, so other
                                               commands can share the data. */
    #else
        #include <cyassl/certs_test.h>
    #endif
#endif

#if defined(CYASSL_MDK_ARM)
        #include <stdio.h>
        #include <stdlib.h>
    extern FILE * CyaSSL_fopen(const char *fname, const char *mode) ;
    #define fopen CyaSSL_fopen
#endif

#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif
#ifdef HAVE_CAVIUM
    #include "cavium_sysdep.h"
    #include "cavium_common.h"
    #include "cavium_ioctl.h"
#endif

#ifdef FREESCALE_MQX
    #include <mqx.h>
    #include <fio.h>
    #include <stdlib.h>
#else
    #include <stdio.h>
#endif


#ifdef THREADX
    /* since just testing, use THREADX log printf instead */
    int dc_log_printf(char*, ...);
        #undef printf
        #define printf dc_log_printf
#endif

#include "ctaocrypt/test/test.h"


typedef struct testVector {
    const char*  input;
    const char*  output;
    size_t inLen;
    size_t outLen;
} testVector;

int  md2_test(void);
int  md5_test(void);
int  md4_test(void);
int  sha_test(void);
int  sha256_test(void);
int  sha512_test(void);
int  sha384_test(void);
int  hmac_md5_test(void);
int  hmac_sha_test(void);
int  hmac_sha256_test(void);
int  hmac_sha384_test(void);
int  hmac_sha512_test(void);
int  hmac_blake2b_test(void);
int  hkdf_test(void);
int  arc4_test(void);
int  hc128_test(void);
int  rabbit_test(void);
int  des_test(void);
int  des3_test(void);
int  aes_test(void);
int  aesgcm_test(void);
int  gmac_test(void);
int  aesccm_test(void);
int  camellia_test(void);
int  rsa_test(void);
int  dh_test(void);
int  dsa_test(void);
int  random_test(void);
int  pwdbased_test(void);
int  ripemd_test(void);
int  openssl_test(void);   /* test mini api */
int pbkdf1_test(void);
int pkcs12_test(void);
int pbkdf2_test(void);
#ifdef HAVE_ECC
    int  ecc_test(void);
    #ifdef HAVE_ECC_ENCRYPT
        int  ecc_encrypt_test(void);
    #endif
#endif
#ifdef HAVE_BLAKE2
    int  blake2b_test(void);
#endif
#ifdef HAVE_LIBZ
    int compress_test(void);
#endif
#ifdef HAVE_PKCS7
    int pkcs7enveloped_test(void);
    int pkcs7signed_test(void);
#endif



static void err_sys(const char* msg, int es)
{
    printf("%s error = %d\n", msg, es);
    #if !defined(THREADX) && !defined(CYASSL_MDK_ARM)
  	if (msg)
        exit(es);
    #endif
    return;
}

/* func_args from test.h, so don't have to pull in other junk */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;



void ctaocrypt_test(void* args)
{
    int ret = 0;

    ((func_args*)args)->return_code = -1; /* error state */

#if !defined(NO_BIG_INT)
    if (CheckCtcSettings() != 1)
        err_sys("Build vs runtime math mismatch\n", -1234);

#ifdef USE_FAST_MATH
    if (CheckFastMathSettings() != 1)
        err_sys("Build vs runtime fastmath FP_MAX_BITS mismatch\n", -1235);
#endif /* USE_FAST_MATH */
#endif /* !NO_BIG_INT */


#ifndef NO_MD5
    if ( (ret = md5_test()) != 0)
        err_sys("MD5      test failed!\n", ret);
    else
        printf( "MD5      test passed!\n");
#endif

#ifdef CYASSL_MD2
    if ( (ret = md2_test()) != 0)
        err_sys("MD2      test failed!\n", ret);
    else
        printf( "MD2      test passed!\n");
#endif

#ifndef NO_MD4
    if ( (ret = md4_test()) != 0)
        err_sys("MD4      test failed!\n", ret);
    else
        printf( "MD4      test passed!\n");
#endif

#ifndef NO_SHA
    if ( (ret = sha_test()) != 0)
        err_sys("SHA      test failed!\n", ret);
    else
        printf( "SHA      test passed!\n");
#endif

#ifndef NO_SHA256
    if ( (ret = sha256_test()) != 0)
        err_sys("SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif

#ifdef CYASSL_SHA384
    if ( (ret = sha384_test()) != 0)
        err_sys("SHA-384  test failed!\n", ret);
    else
        printf( "SHA-384  test passed!\n");
#endif

#ifdef CYASSL_SHA512
    if ( (ret = sha512_test()) != 0)
        err_sys("SHA-512  test failed!\n", ret);
    else
        printf( "SHA-512  test passed!\n");
#endif

#ifdef CYASSL_RIPEMD
    if ( (ret = ripemd_test()) != 0)
        err_sys("RIPEMD   test failed!\n", ret);
    else
        printf( "RIPEMD   test passed!\n");
#endif

#ifdef HAVE_BLAKE2
    if ( (ret = blake2b_test()) != 0)
        err_sys("BLAKE2b  test failed!\n", ret);
    else
        printf( "BLAKE2b  test passed!\n");
#endif

#ifndef NO_HMAC
    #ifndef NO_MD5
        if ( (ret = hmac_md5_test()) != 0)
            err_sys("HMAC-MD5 test failed!\n", ret);
        else
            printf( "HMAC-MD5 test passed!\n");
    #endif

    #ifndef NO_SHA
    if ( (ret = hmac_sha_test()) != 0)
        err_sys("HMAC-SHA test failed!\n", ret);
    else
        printf( "HMAC-SHA test passed!\n");
    #endif

    #ifndef NO_SHA256
        if ( (ret = hmac_sha256_test()) != 0)
            err_sys("HMAC-SHA256 test failed!\n", ret);
        else
            printf( "HMAC-SHA256 test passed!\n");
    #endif

    #ifdef CYASSL_SHA384
        if ( (ret = hmac_sha384_test()) != 0)
            err_sys("HMAC-SHA384 test failed!\n", ret);
        else
            printf( "HMAC-SHA384 test passed!\n");
    #endif

    #ifdef CYASSL_SHA512
        if ( (ret = hmac_sha512_test()) != 0)
            err_sys("HMAC-SHA512 test failed!\n", ret);
        else
            printf( "HMAC-SHA512 test passed!\n");
    #endif

    #ifdef HAVE_BLAKE2
        if ( (ret = hmac_blake2b_test()) != 0)
            err_sys("HMAC-BLAKE2 test failed!\n", ret);
        else
            printf( "HMAC-BLAKE2 test passed!\n");
    #endif

    #ifdef HAVE_HKDF
        if ( (ret = hkdf_test()) != 0)
            err_sys("HMAC-KDF    test failed!\n", ret);
        else
            printf( "HMAC-KDF    test passed!\n");
    #endif

#endif

#ifdef HAVE_AESGCM
    if ( (ret = gmac_test()) != 0)
        err_sys("GMAC     test passed!\n", ret);
    else
        printf( "GMAC     test passed!\n");
#endif

#ifndef NO_RC4
    if ( (ret = arc4_test()) != 0)
        err_sys("ARC4     test failed!\n", ret);
    else
        printf( "ARC4     test passed!\n");
#endif

#ifndef NO_HC128
    if ( (ret = hc128_test()) != 0)
        err_sys("HC-128   test failed!\n", ret);
    else
        printf( "HC-128   test passed!\n");
#endif

#ifndef NO_RABBIT
    if ( (ret = rabbit_test()) != 0)
        err_sys("Rabbit   test failed!\n", ret);
    else
        printf( "Rabbit   test passed!\n");
#endif

#ifndef NO_DES3
    if ( (ret = des_test()) != 0)
        err_sys("DES      test failed!\n", ret);
    else
        printf( "DES      test passed!\n");
#endif

#ifndef NO_DES3
    if ( (ret = des3_test()) != 0)
        err_sys("DES3     test failed!\n", ret);
    else
        printf( "DES3     test passed!\n");
#endif

#ifndef NO_AES
    if ( (ret = aes_test()) != 0)
        err_sys("AES      test failed!\n", ret);
    else
        printf( "AES      test passed!\n");

#ifdef HAVE_AESGCM
    if ( (ret = aesgcm_test()) != 0)
        err_sys("AES-GCM  test failed!\n", ret);
    else
        printf( "AES-GCM  test passed!\n");
#endif

#ifdef HAVE_AESCCM
    if ( (ret = aesccm_test()) != 0)
        err_sys("AES-CCM  test failed!\n", ret);
    else
        printf( "AES-CCM  test passed!\n");
#endif
#endif

#ifdef HAVE_CAMELLIA
    if ( (ret = camellia_test()) != 0)
        err_sys("CAMELLIA test failed!\n", ret);
    else
        printf( "CAMELLIA test passed!\n");
#endif

    if ( (ret = random_test()) != 0)
        err_sys("RANDOM   test failed!\n", ret);
    else
        printf( "RANDOM   test passed!\n");

#ifndef NO_RSA
    if ( (ret = rsa_test()) != 0)
        err_sys("RSA      test failed!\n", ret);
    else
        printf( "RSA      test passed!\n");
#endif

#ifndef NO_DH
    if ( (ret = dh_test()) != 0)
        err_sys("DH       test failed!\n", ret);
    else
        printf( "DH       test passed!\n");
#endif

#ifndef NO_DSA
    if ( (ret = dsa_test()) != 0)
        err_sys("DSA      test failed!\n", ret);
    else
        printf( "DSA      test passed!\n");
#endif

#ifndef NO_PWDBASED
    if ( (ret = pwdbased_test()) != 0)
        err_sys("PWDBASED test failed!\n", ret);
    else
        printf( "PWDBASED test passed!\n");
#endif

#ifdef OPENSSL_EXTRA
    if ( (ret = openssl_test()) != 0)
        err_sys("OPENSSL  test failed!\n", ret);
    else
        printf( "OPENSSL  test passed!\n");
#endif

#ifdef HAVE_ECC
    if ( (ret = ecc_test()) != 0)
        err_sys("ECC      test failed!\n", ret);
    else
        printf( "ECC      test passed!\n");
    #ifdef HAVE_ECC_ENCRYPT
        if ( (ret = ecc_encrypt_test()) != 0)
            err_sys("ECC Enc  test failed!\n", ret);
        else
            printf( "ECC Enc  test passed!\n");
    #endif
#endif

#ifdef HAVE_LIBZ
    if ( (ret = compress_test()) != 0)
        err_sys("COMPRESS test failed!\n", ret);
    else
        printf( "COMPRESS test passed!\n");
#endif

#ifdef HAVE_PKCS7
    if ( (ret = pkcs7enveloped_test()) != 0)
        err_sys("PKCS7enveloped test failed!\n", ret);
    else
        printf( "PKCS7enveloped test passed!\n");

    if ( (ret = pkcs7signed_test()) != 0)
        err_sys("PKCS7signed    test failed!\n", ret);
    else
        printf( "PKCS7signed    test passed!\n");
#endif

    ((func_args*)args)->return_code = ret;
}


#ifndef NO_MAIN_DRIVER

#ifdef HAVE_CAVIUM

static int OpenNitroxDevice(int dma_mode,int dev_id)
{
   Csp1CoreAssignment core_assign;
   Uint32             device;

   if (CspInitialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
      return -1;
   if (Csp1GetDevType(&device))
      return -1;
   if (device != NPX_DEVICE) {
      if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
                (Uint32 *)&core_assign)!= 0)
         return -1;
   }
   CspShutdown(CAVIUM_DEV_ID);

   return CspInitialize(dma_mode, dev_id);
}

#endif /* HAVE_CAVIUM */

    /* so overall tests can pull in test function */

    int main(int argc, char** argv)
    {

        func_args args;


#ifdef HAVE_CAVIUM
        int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
        if (ret != 0)
            err_sys("Cavium OpenNitroxDevice failed", -1236);
#endif /* HAVE_CAVIUM */

        args.argc = argc;
        args.argv = argv;

        ctaocrypt_test(&args);

#ifdef HAVE_CAVIUM
        CspShutdown(CAVIUM_DEV_ID);
#endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */


#ifdef CYASSL_MD2
int md2_test()
{
    Md2  md2;
    byte hash[MD2_DIGEST_SIZE];

    testVector a, b, c, d, e, f, g;
    testVector test_md2[7];
    int times = sizeof(test_md2) / sizeof(testVector), i;

    a.input  = "";
    a.output = "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69"
               "\x27\x73";
    a.inLen  = strlen(a.input);
    a.outLen = MD2_DIGEST_SIZE;

    b.input  = "a";
    b.output = "\x32\xec\x01\xec\x4a\x6d\xac\x72\xc0\xab\x96\xfb\x34\xc0"
               "\xb5\xd1";
    b.inLen  = strlen(b.input);
    b.outLen = MD2_DIGEST_SIZE;

    c.input  = "abc";
    c.output = "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b\x30\x28\x3a\x69\xe6\xde"
               "\xd6\xbb";
    c.inLen  = strlen(c.input);
    c.outLen = MD2_DIGEST_SIZE;

    d.input  = "message digest";
    d.output = "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b\x21\x9f\xf3\x30\x31\xfe"
               "\x06\xb0";
    d.inLen  = strlen(d.input);
    d.outLen = MD2_DIGEST_SIZE;

    e.input  = "abcdefghijklmnopqrstuvwxyz";
    e.output = "\x4e\x8d\xdf\xf3\x65\x02\x92\xab\x5a\x41\x08\xc3\xaa\x47"
               "\x94\x0b";
    e.inLen  = strlen(e.input);
    e.outLen = MD2_DIGEST_SIZE;

    f.input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345"
               "6789";
    f.output = "\xda\x33\xde\xf2\xa4\x2d\xf1\x39\x75\x35\x28\x46\xc3\x03"
               "\x38\xcd";
    f.inLen  = strlen(f.input);
    f.outLen = MD2_DIGEST_SIZE;

    g.input  = "1234567890123456789012345678901234567890123456789012345678"
               "9012345678901234567890";
    g.output = "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9\x80\x6c\x3c\x66\xf3"
               "\xef\xd8";
    g.inLen  = strlen(g.input);
    g.outLen = MD2_DIGEST_SIZE;

    test_md2[0] = a;
    test_md2[1] = b;
    test_md2[2] = c;
    test_md2[3] = d;
    test_md2[4] = e;
    test_md2[5] = f;
    test_md2[6] = g;

    InitMd2(&md2);

    for (i = 0; i < times; ++i) {
        Md2Update(&md2, (byte*)test_md2[i].input, (word32)test_md2[i].inLen);
        Md2Final(&md2, hash);

        if (memcmp(hash, test_md2[i].output, MD2_DIGEST_SIZE) != 0)
            return -155 - i;
    }

    return 0;
}
#endif

#ifndef NO_MD5
int md5_test(void)
{
    Md5  md5;
    byte hash[MD5_DIGEST_SIZE];

    testVector a, b, c, d, e;
    testVector test_md5[5];
    int times = sizeof(test_md5) / sizeof(testVector), i;

    a.input  = "abc";
    a.output = "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f"
               "\x72";
    a.inLen  = strlen(a.input);
    a.outLen = MD5_DIGEST_SIZE;

    b.input  = "message digest";
    b.output = "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61"
               "\xd0";
    b.inLen  = strlen(b.input);
    b.outLen = MD5_DIGEST_SIZE;

    c.input  = "abcdefghijklmnopqrstuvwxyz";
    c.output = "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1"
               "\x3b";
    c.inLen  = strlen(c.input);
    c.outLen = MD5_DIGEST_SIZE;

    d.input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345"
               "6789";
    d.output = "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d"
               "\x9f";
    d.inLen  = strlen(d.input);
    d.outLen = MD5_DIGEST_SIZE;

    e.input  = "1234567890123456789012345678901234567890123456789012345678"
               "9012345678901234567890";
    e.output = "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6"
               "\x7a";
    e.inLen  = strlen(e.input);
    e.outLen = MD5_DIGEST_SIZE;

    test_md5[0] = a;
    test_md5[1] = b;
    test_md5[2] = c;
    test_md5[3] = d;
    test_md5[4] = e;

    InitMd5(&md5);

    for (i = 0; i < times; ++i) {
        Md5Update(&md5, (byte*)test_md5[i].input, (word32)test_md5[i].inLen);
        Md5Final(&md5, hash);

        if (memcmp(hash, test_md5[i].output, MD5_DIGEST_SIZE) != 0)
            return -5 - i;
    }

    return 0;
}
#endif /* NO_MD5 */


#ifndef NO_MD4

int md4_test(void)
{
    Md4  md4;
    byte hash[MD4_DIGEST_SIZE];

    testVector a, b, c, d, e, f, g;
    testVector test_md4[7];
    int times = sizeof(test_md4) / sizeof(testVector), i;

    a.input  = "";
    a.output = "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89"
               "\xc0";
    a.inLen  = strlen(a.input);
    a.outLen = MD4_DIGEST_SIZE;

    b.input  = "a";
    b.output = "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb"
               "\x24";
    b.inLen  = strlen(b.input);
    b.outLen = MD4_DIGEST_SIZE;

    c.input  = "abc";
    c.output = "\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72"
               "\x9d";
    c.inLen  = strlen(c.input);
    c.outLen = MD4_DIGEST_SIZE;

    d.input  = "message digest";
    d.output = "\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01"
               "\x4b";
    d.inLen  = strlen(d.input);
    d.outLen = MD4_DIGEST_SIZE;

    e.input  = "abcdefghijklmnopqrstuvwxyz";
    e.output = "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d"
               "\xa9";
    e.inLen  = strlen(e.input);
    e.outLen = MD4_DIGEST_SIZE;

    f.input  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345"
               "6789";
    f.output = "\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0"
               "\xe4";
    f.inLen  = strlen(f.input);
    f.outLen = MD4_DIGEST_SIZE;

    g.input  = "1234567890123456789012345678901234567890123456789012345678"
               "9012345678901234567890";
    g.output = "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05"
               "\x36";
    g.inLen  = strlen(g.input);
    g.outLen = MD4_DIGEST_SIZE;

    test_md4[0] = a;
    test_md4[1] = b;
    test_md4[2] = c;
    test_md4[3] = d;
    test_md4[4] = e;
    test_md4[5] = f;
    test_md4[6] = g;

    InitMd4(&md4);

    for (i = 0; i < times; ++i) {
        Md4Update(&md4, (byte*)test_md4[i].input, (word32)test_md4[i].inLen);
        Md4Final(&md4, hash);

        if (memcmp(hash, test_md4[i].output, MD4_DIGEST_SIZE) != 0)
            return -205 - i;
    }

    return 0;
}

#endif /* NO_MD4 */

#ifndef NO_SHA

int sha_test(void)
{
    Sha  sha;
    byte hash[SHA_DIGEST_SIZE];

    testVector a, b, c, d;
    testVector test_sha[4];
    int ret;
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2"
               "\x6C\x9C\xD0\xD8\x9D";
    a.inLen  = strlen(a.input);
    a.outLen = SHA_DIGEST_SIZE;

    b.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    b.output = "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29"
               "\xE5\xE5\x46\x70\xF1";
    b.inLen  = strlen(b.input);
    b.outLen = SHA_DIGEST_SIZE;

    c.input  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaa";
    c.output = "\x00\x98\xBA\x82\x4B\x5C\x16\x42\x7B\xD7\xA1\x12\x2A\x5A\x44"
               "\x2A\x25\xEC\x64\x4D";
    c.inLen  = strlen(c.input);
    c.outLen = SHA_DIGEST_SIZE;

    d.input  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "aaaaaaaaaa";
    d.output = "\xAD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7"
               "\x53\x99\x5E\x26\xA0";
    d.inLen  = strlen(d.input);
    d.outLen = SHA_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;
    test_sha[3] = d;

    ret = InitSha(&sha);
    if (ret != 0)
        return -4001;

    for (i = 0; i < times; ++i) {
        ShaUpdate(&sha, (byte*)test_sha[i].input, (word32)test_sha[i].inLen);
        ShaFinal(&sha, hash);

        if (memcmp(hash, test_sha[i].output, SHA_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}

#endif /* NO_SHA */

#ifdef CYASSL_RIPEMD
int ripemd_test(void)
{
    RipeMd  ripemd;
    byte hash[RIPEMD_DIGEST_SIZE];

    testVector a, b, c, d;
    testVector test_ripemd[4];
    int times = sizeof(test_ripemd) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6"
               "\xb0\x87\xf1\x5a\x0b\xfc";
    a.inLen  = strlen(a.input);
    a.outLen = RIPEMD_DIGEST_SIZE;

    b.input  = "message digest";
    b.output = "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8"
               "\x5f\xfa\x21\x59\x5f\x36";
    b.inLen  = strlen(b.input);
    b.outLen = RIPEMD_DIGEST_SIZE;

    c.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    c.output = "\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0\x6c\x27\xdc"
               "\xf4\x9a\xda\x62\xeb\x2b";
    c.inLen  = strlen(c.input);
    c.outLen = RIPEMD_DIGEST_SIZE;

    d.input  = "12345678901234567890123456789012345678901234567890123456"
               "789012345678901234567890";
    d.output = "\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb\xd3\x32\x3c\xab"
               "\x82\xbf\x63\x32\x6b\xfb";
    d.inLen  = strlen(d.input);
    d.outLen = RIPEMD_DIGEST_SIZE;

    test_ripemd[0] = a;
    test_ripemd[1] = b;
    test_ripemd[2] = c;
    test_ripemd[3] = d;

    InitRipeMd(&ripemd);

    for (i = 0; i < times; ++i) {
        RipeMdUpdate(&ripemd, (byte*)test_ripemd[i].input,
                     (word32)test_ripemd[i].inLen);
        RipeMdFinal(&ripemd, hash);

        if (memcmp(hash, test_ripemd[i].output, RIPEMD_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}
#endif /* CYASSL_RIPEMD */


#ifdef HAVE_BLAKE2


#define BLAKE2_TESTS 3

static const byte blake2b_vec[BLAKE2_TESTS][BLAKE2B_OUTBYTES] =
{
  {
    0x78, 0x6A, 0x02, 0xF7, 0x42, 0x01, 0x59, 0x03,
    0xC6, 0xC6, 0xFD, 0x85, 0x25, 0x52, 0xD2, 0x72,
    0x91, 0x2F, 0x47, 0x40, 0xE1, 0x58, 0x47, 0x61,
    0x8A, 0x86, 0xE2, 0x17, 0xF7, 0x1F, 0x54, 0x19,
    0xD2, 0x5E, 0x10, 0x31, 0xAF, 0xEE, 0x58, 0x53,
    0x13, 0x89, 0x64, 0x44, 0x93, 0x4E, 0xB0, 0x4B,
    0x90, 0x3A, 0x68, 0x5B, 0x14, 0x48, 0xB7, 0x55,
    0xD5, 0x6F, 0x70, 0x1A, 0xFE, 0x9B, 0xE2, 0xCE
  },
  {
    0x2F, 0xA3, 0xF6, 0x86, 0xDF, 0x87, 0x69, 0x95,
    0x16, 0x7E, 0x7C, 0x2E, 0x5D, 0x74, 0xC4, 0xC7,
    0xB6, 0xE4, 0x8F, 0x80, 0x68, 0xFE, 0x0E, 0x44,
    0x20, 0x83, 0x44, 0xD4, 0x80, 0xF7, 0x90, 0x4C,
    0x36, 0x96, 0x3E, 0x44, 0x11, 0x5F, 0xE3, 0xEB,
    0x2A, 0x3A, 0xC8, 0x69, 0x4C, 0x28, 0xBC, 0xB4,
    0xF5, 0xA0, 0xF3, 0x27, 0x6F, 0x2E, 0x79, 0x48,
    0x7D, 0x82, 0x19, 0x05, 0x7A, 0x50, 0x6E, 0x4B
  },
  {
    0x1C, 0x08, 0x79, 0x8D, 0xC6, 0x41, 0xAB, 0xA9,
    0xDE, 0xE4, 0x35, 0xE2, 0x25, 0x19, 0xA4, 0x72,
    0x9A, 0x09, 0xB2, 0xBF, 0xE0, 0xFF, 0x00, 0xEF,
    0x2D, 0xCD, 0x8E, 0xD6, 0xF8, 0xA0, 0x7D, 0x15,
    0xEA, 0xF4, 0xAE, 0xE5, 0x2B, 0xBF, 0x18, 0xAB,
    0x56, 0x08, 0xA6, 0x19, 0x0F, 0x70, 0xB9, 0x04,
    0x86, 0xC8, 0xA7, 0xD4, 0x87, 0x37, 0x10, 0xB1,
    0x11, 0x5D, 0x3D, 0xEB, 0xBB, 0x43, 0x27, 0xB5
  }
};



int blake2b_test(void)
{
    Blake2b b2b;
    byte    digest[64];
    byte    input[64];
    int     i, ret;

    for (i = 0; i < (int)sizeof(input); i++)
        input[i] = (byte)i;

    for (i = 0; i < BLAKE2_TESTS; i++) {
        ret = InitBlake2b(&b2b, 64);
        if (ret != 0)
            return -4002;

        ret = Blake2bUpdate(&b2b, input, i);
        if (ret != 0)
            return -4003;

        ret = Blake2bFinal(&b2b, digest, 64);
        if (ret != 0)
            return -4004;

        if (memcmp(digest, blake2b_vec[i], 64) != 0) {
            return -300 - i;
        }
    }

    return 0;
}
#endif /* HAVE_BLAKE2 */


#ifndef NO_SHA256
int sha256_test(void)
{
    Sha256 sha;
    byte   hash[SHA256_DIGEST_SIZE];

    testVector a, b;
    testVector test_sha[2];
    int ret;
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
               "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
               "\x15\xAD";
    a.inLen  = strlen(a.input);
    a.outLen = SHA256_DIGEST_SIZE;

    b.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    b.output = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
               "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
               "\x06\xC1";
    b.inLen  = strlen(b.input);
    b.outLen = SHA256_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;

    ret = InitSha256(&sha);
    if (ret != 0)
        return -4005;

    for (i = 0; i < times; ++i) {
        ret = Sha256Update(&sha, (byte*)test_sha[i].input,(word32)test_sha[i].inLen);
        if (ret != 0)
            return -4006;
        ret = Sha256Final(&sha, hash);
        if (ret != 0)
            return -4007;

        if (memcmp(hash, test_sha[i].output, SHA256_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}
#endif


#ifdef CYASSL_SHA512
int sha512_test(void)
{
    Sha512 sha;
    byte   hash[SHA512_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector test_sha[2];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
               "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55"
               "\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3"
               "\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f"
               "\xa5\x4c\xa4\x9f";
    a.inLen  = strlen(a.input);
    a.outLen = SHA512_DIGEST_SIZE;

    b.input  = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi"
               "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    b.output = "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14"
               "\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88"
               "\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4"
               "\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b"
               "\x87\x4b\xe9\x09";
    b.inLen  = strlen(b.input);
    b.outLen = SHA512_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;

    ret = InitSha512(&sha);
    if (ret != 0)
        return -4009;

    for (i = 0; i < times; ++i) {
        ret = Sha512Update(&sha, (byte*)test_sha[i].input,(word32)test_sha[i].inLen);
        if (ret != 0)
            return -4010;

        ret = Sha512Final(&sha, hash);
        if (ret != 0)
            return -4011;

        if (memcmp(hash, test_sha[i].output, SHA512_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}
#endif


#ifdef CYASSL_SHA384
int sha384_test(void)
{
    Sha384 sha;
    byte   hash[SHA384_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector test_sha[2];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50"
               "\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff"
               "\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34"
               "\xc8\x25\xa7";
    a.inLen  = strlen(a.input);
    a.outLen = SHA384_DIGEST_SIZE;

    b.input  = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi"
               "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    b.output = "\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b"
               "\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0"
               "\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91"
               "\x74\x60\x39";
    b.inLen  = strlen(b.input);
    b.outLen = SHA384_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;

    ret = InitSha384(&sha);
    if (ret != 0)
        return -4012;

    for (i = 0; i < times; ++i) {
        ret = Sha384Update(&sha, (byte*)test_sha[i].input,(word32)test_sha[i].inLen);
        if (ret != 0)
            return -4013;

        ret = Sha384Final(&sha, hash);
        if (ret != 0)
            return -4014;

        if (memcmp(hash, test_sha[i].output, SHA384_DIGEST_SIZE) != 0)
            return -10 - i;
    }

    return 0;
}
#endif /* CYASSL_SHA384 */


#if !defined(NO_HMAC) && !defined(NO_MD5)
int hmac_md5_test(void)
{
    Hmac hmac;
    byte hash[MD5_DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc"
               "\x9d";
    a.inLen  = strlen(a.input);
    a.outLen = MD5_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b.output = "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7"
               "\x38";
    b.inLen  = strlen(b.input);
    b.outLen = MD5_DIGEST_SIZE;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3"
               "\xf6";
    c.inLen  = strlen(c.input);
    c.outLen = MD5_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS) || defined(HAVE_CAVIUM)
        if (i == 1)
            continue; /* cavium can't handle short keys, fips not allowed */
#endif
#ifdef HAVE_CAVIUM
        if (HmacInitCavium(&hmac, CAVIUM_DEV_ID) != 0)
            return -20009;
#endif
        ret = HmacSetKey(&hmac, MD5, (byte*)keys[i], (word32)strlen(keys[i]));
        if (ret != 0)
            return -4015;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4016;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4017;

        if (memcmp(hash, test_hmac[i].output, MD5_DIGEST_SIZE) != 0)
            return -20 - i;
#ifdef HAVE_CAVIUM
        HmacFreeCavium(&hmac);
#endif
    }

    return 0;
}
#endif /* NO_HMAC && NO_MD5 */

#if !defined(NO_HMAC) && !defined(NO_SHA)
int hmac_sha_test(void)
{
    Hmac hmac;
    byte hash[SHA_DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c"
               "\x8e\xf1\x46\xbe\x00";
    a.inLen  = strlen(a.input);
    a.outLen = SHA_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b.output = "\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf"
               "\x9c\x25\x9a\x7c\x79";
    b.inLen  = strlen(b.input);
    b.outLen = SHA_DIGEST_SIZE;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b"
               "\x4f\x63\xf1\x75\xd3";
    c.inLen  = strlen(c.input);
    c.outLen = SHA_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS) || defined(HAVE_CAVIUM)
        if (i == 1)
            continue; /* cavium can't handle short keys, fips not allowed */
#endif
#ifdef HAVE_CAVIUM
        if (HmacInitCavium(&hmac, CAVIUM_DEV_ID) != 0)
            return -20010;
#endif
        ret = HmacSetKey(&hmac, SHA, (byte*)keys[i], (word32)strlen(keys[i]));
        if (ret != 0)
            return -4018;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4019;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4020;

        if (memcmp(hash, test_hmac[i].output, SHA_DIGEST_SIZE) != 0)
            return -20 - i;
#ifdef HAVE_CAVIUM
        HmacFreeCavium(&hmac);
#endif
    }

    return 0;
}
#endif


#if !defined(NO_HMAC) && !defined(NO_SHA256)
int hmac_sha256_test(void)
{
    Hmac hmac;
    byte hash[SHA256_DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1"
               "\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32"
               "\xcf\xf7";
    a.inLen  = strlen(a.input);
    a.outLen = SHA256_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b.output = "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75"
               "\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec"
               "\x38\x43";
    b.inLen  = strlen(b.input);
    b.outLen = SHA256_DIGEST_SIZE;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81"
               "\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5"
               "\x65\xfe";
    c.inLen  = strlen(c.input);
    c.outLen = SHA256_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS) || defined(HAVE_CAVIUM)
        if (i == 1)
            continue; /* cavium can't handle short keys, fips not allowed */
#endif
#ifdef HAVE_CAVIUM
        if (HmacInitCavium(&hmac, CAVIUM_DEV_ID) != 0)
            return -20011;
#endif
        ret = HmacSetKey(&hmac, SHA256, (byte*)keys[i],(word32)strlen(keys[i]));
        if (ret != 0)
            return -4021;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4022;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4023;

        if (memcmp(hash, test_hmac[i].output, SHA256_DIGEST_SIZE) != 0)
            return -20 - i;
#ifdef HAVE_CAVIUM
        HmacFreeCavium(&hmac);
#endif
    }

    return 0;
}
#endif


#if !defined(NO_HMAC) && defined(HAVE_BLAKE2)
int hmac_blake2b_test(void)
{
    Hmac hmac;
    byte hash[BLAKE2B_256];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\x72\x93\x0d\xdd\xf5\xf7\xe1\x78\x38\x07\x44\x18\x0b\x3f\x51"
               "\x37\x25\xb5\x82\xc2\x08\x83\x2f\x1c\x99\xfd\x03\xa0\x16\x75"
               "\xac\xfd";
    a.inLen  = strlen(a.input);
    a.outLen = BLAKE2B_256;

    b.input  = "what do ya want for nothing?";
    b.output = "\x3d\x20\x50\x71\x05\xc0\x8c\x0c\x38\x44\x1e\xf7\xf9\xd1\x67"
               "\x21\xff\x64\xf5\x94\x00\xcf\xf9\x75\x41\xda\x88\x61\x9d\x7c"
               "\xda\x2b";
    b.inLen  = strlen(b.input);
    b.outLen = BLAKE2B_256;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\xda\xfe\x2a\x24\xfc\xe7\xea\x36\x34\xbe\x41\x92\xc7\x11\xa7"
               "\x00\xae\x53\x9c\x11\x9c\x80\x74\x55\x22\x25\x4a\xb9\x55\xd3"
               "\x0f\x87";
    c.inLen  = strlen(c.input);
    c.outLen = BLAKE2B_256;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS) || defined(HAVE_CAVIUM)
        if (i == 1)
            continue; /* cavium can't handle short keys, fips not allowed */
#endif
#ifdef HAVE_CAVIUM
        if (HmacInitCavium(&hmac, CAVIUM_DEV_ID) != 0)
            return -20011;
#endif
        ret = HmacSetKey(&hmac, BLAKE2B_ID, (byte*)keys[i],
                         (word32)strlen(keys[i]));
        if (ret != 0)
            return -4024;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4025;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4026;

        if (memcmp(hash, test_hmac[i].output, BLAKE2B_256) != 0)
            return -20 - i;
#ifdef HAVE_CAVIUM
        HmacFreeCavium(&hmac);
#endif
    }

    return 0;
}
#endif


#if !defined(NO_HMAC) && defined(CYASSL_SHA384)
int hmac_sha384_test(void)
{
    Hmac hmac;
    byte hash[SHA384_DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90"
               "\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb"
               "\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2"
               "\xfa\x9c\xb6";
    a.inLen  = strlen(a.input);
    a.outLen = SHA384_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b.output = "\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b"
               "\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22"
               "\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa"
               "\xb2\x16\x49";
    b.inLen  = strlen(b.input);
    b.outLen = SHA384_DIGEST_SIZE;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8"
               "\x6f\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66"
               "\x14\x4b\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01"
               "\xa3\x4f\x27";
    c.inLen  = strlen(c.input);
    c.outLen = SHA384_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS)
        if (i == 1)
            continue; /* fips not allowed */
#endif
        ret = HmacSetKey(&hmac, SHA384, (byte*)keys[i],(word32)strlen(keys[i]));
        if (ret != 0)
            return -4027;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4028;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4029;

        if (memcmp(hash, test_hmac[i].output, SHA384_DIGEST_SIZE) != 0)
            return -20 - i;
    }

    return 0;
}
#endif


#if !defined(NO_HMAC) && defined(CYASSL_SHA512)
int hmac_sha512_test(void)
{
    Hmac hmac;
    byte hash[SHA512_DIGEST_SIZE];

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c"
               "\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1"
               "\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae"
               "\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20"
               "\x3a\x12\x68\x54";
    a.inLen  = strlen(a.input);
    a.outLen = SHA512_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b.output = "\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0"
               "\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25"
               "\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8"
               "\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a"
               "\x38\xbc\xe7\x37";
    b.inLen  = strlen(b.input);
    b.outLen = SHA512_DIGEST_SIZE;

    c.input  = "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
               "\xDD\xDD\xDD\xDD\xDD\xDD";
    c.output = "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b"
               "\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27"
               "\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e"
               "\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59"
               "\xe1\x32\x92\xfb";
    c.inLen  = strlen(c.input);
    c.outLen = SHA512_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test_hmac[2] = c;

    for (i = 0; i < times; ++i) {
#if defined(HAVE_FIPS)
        if (i == 1)
            continue; /* fips not allowed */
#endif
        ret = HmacSetKey(&hmac, SHA512, (byte*)keys[i],(word32)strlen(keys[i]));
        if (ret != 0)
            return -4030;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].input,
                   (word32)test_hmac[i].inLen);
        if (ret != 0)
            return -4031;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
            return -4032;

        if (memcmp(hash, test_hmac[i].output, SHA512_DIGEST_SIZE) != 0)
            return -20 - i;
    }

    return 0;
}
#endif


#ifndef NO_RC4
int arc4_test(void)
{
    byte cipher[16];
    byte plain[16];

    const char* keys[] =
    {
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xef\x01\x23\x45"
    };

    testVector a, b, c, d;
    testVector test_arc4[4];

    int times = sizeof(test_arc4) / sizeof(testVector), i;

    a.input  = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    a.output = "\x75\xb7\x87\x80\x99\xe0\xc5\x96";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    b.output = "\x74\x94\xc2\xe7\x10\x4b\x08\x79";
    b.inLen  = 8;
    b.outLen = 8;

    c.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    c.output = "\xde\x18\x89\x41\xa3\x37\x5d\x3a";
    c.inLen  = 8;
    c.outLen = 8;

    d.input  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    d.output = "\xd6\xa1\x41\xa7\xec\x3c\x38\xdf\xbd\x61";
    d.inLen  = 10;
    d.outLen = 10;

    test_arc4[0] = a;
    test_arc4[1] = b;
    test_arc4[2] = c;
    test_arc4[3] = d;

    for (i = 0; i < times; ++i) {
        Arc4 enc;
        Arc4 dec;
        int  keylen = 8;  /* strlen with key 0x00 not good */
        if (i == 3)
            keylen = 4;

#ifdef HAVE_CAVIUM
        if (Arc4InitCavium(&enc, CAVIUM_DEV_ID) != 0)
            return -20001;
        if (Arc4InitCavium(&dec, CAVIUM_DEV_ID) != 0)
            return -20002;
#endif

        Arc4SetKey(&enc, (byte*)keys[i], keylen);
        Arc4SetKey(&dec, (byte*)keys[i], keylen);

        Arc4Process(&enc, cipher, (byte*)test_arc4[i].input,
                    (word32)test_arc4[i].outLen);
        Arc4Process(&dec, plain,  cipher, (word32)test_arc4[i].outLen);

        if (memcmp(plain, test_arc4[i].input, test_arc4[i].outLen))
            return -20 - i;

        if (memcmp(cipher, test_arc4[i].output, test_arc4[i].outLen))
            return -20 - 5 - i;

#ifdef HAVE_CAVIUM
        Arc4FreeCavium(&enc);
        Arc4FreeCavium(&dec);
#endif
    }

    return 0;
}
#endif


int hc128_test(void)
{
#ifdef HAVE_HC128
    byte cipher[16];
    byte plain[16];

    const char* keys[] =
    {
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD",
        "\x0F\x62\xB5\x08\x5B\xAE\x01\x54\xA7\xFA\x4D\xA0\xF3\x46\x99\xEC"
    };

    const char* ivs[] =
    {
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x0D\x74\xDB\x42\xA9\x10\x77\xDE\x45\xAC\x13\x7A\xE1\x48\xAF\x16",
        "\x28\x8F\xF6\x5D\xC4\x2B\x92\xF9\x60\xC7\x2E\x95\xFC\x63\xCA\x31"
    };


    testVector a, b, c, d;
    testVector test_hc128[4];

    int times = sizeof(test_hc128) / sizeof(testVector), i;

    a.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    a.output = "\x37\x86\x02\xB9\x8F\x32\xA7\x48";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    b.output = "\x33\x7F\x86\x11\xC6\xED\x61\x5F";
    b.inLen  = 8;
    b.outLen = 8;

    c.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    c.output = "\x2E\x1E\xD1\x2A\x85\x51\xC0\x5A";
    c.inLen  = 8;
    c.outLen = 8;

    d.input  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    d.output = "\x1C\xD8\xAE\xDD\xFE\x52\xE2\x17\xE8\x35\xD0\xB7\xE8\x4E\x29";
    d.inLen  = 15;
    d.outLen = 15;

    test_hc128[0] = a;
    test_hc128[1] = b;
    test_hc128[2] = c;
    test_hc128[3] = d;

    for (i = 0; i < times; ++i) {
        HC128 enc;
        HC128 dec;

        /* align keys/ivs in plain/cipher buffers */
        memcpy(plain,  keys[i], 16);
        memcpy(cipher, ivs[i],  16);

        Hc128_SetKey(&enc, plain, cipher);
        Hc128_SetKey(&dec, plain, cipher);

        /* align input */
        memcpy(plain, test_hc128[i].input, test_hc128[i].outLen);
        Hc128_Process(&enc, cipher, plain,  (word32)test_hc128[i].outLen);
        Hc128_Process(&dec, plain,  cipher, (word32)test_hc128[i].outLen);

        if (memcmp(plain, test_hc128[i].input, test_hc128[i].outLen))
            return -120 - i;

        if (memcmp(cipher, test_hc128[i].output, test_hc128[i].outLen))
            return -120 - 5 - i;
    }

#endif /* HAVE_HC128 */
    return 0;
}


#ifndef NO_RABBIT
int rabbit_test(void)
{
    byte cipher[16];
    byte plain[16];

    const char* keys[] =
    {
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xAC\xC3\x51\xDC\xF1\x62\xFC\x3B\xFE\x36\x3D\x2E\x29\x13\x28\x91"
    };

    const char* ivs[] =
    {
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x59\x7E\x26\xC1\x75\xF5\x73\xC3",
        0
    };

    testVector a, b, c;
    testVector test_rabbit[3];

    int times = sizeof(test_rabbit) / sizeof(testVector), i;

    a.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    a.output = "\xED\xB7\x05\x67\x37\x5D\xCD\x7C";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    b.output = "\x6D\x7D\x01\x22\x92\xCC\xDC\xE0";
    b.inLen  = 8;
    b.outLen = 8;

    c.input  = "\x00\x00\x00\x00\x00\x00\x00\x00";
    c.output = "\x04\xCE\xCA\x7A\x1A\x86\x6E\x77";
    c.inLen  = 8;
    c.outLen = 8;

    test_rabbit[0] = a;
    test_rabbit[1] = b;
    test_rabbit[2] = c;

    for (i = 0; i < times; ++i) {
        Rabbit enc;
        Rabbit dec;
        byte*  iv;

        /* align keys/ivs in plain/cipher buffers */
        memcpy(plain,  keys[i], 16);
        if (ivs[i]) {
            memcpy(cipher, ivs[i],   8);
            iv = cipher;
        } else
            iv = NULL;
        RabbitSetKey(&enc, plain, iv);
        RabbitSetKey(&dec, plain, iv);

        /* align input */
        memcpy(plain, test_rabbit[i].input, test_rabbit[i].outLen);
        RabbitProcess(&enc, cipher, plain,  (word32)test_rabbit[i].outLen);
        RabbitProcess(&dec, plain,  cipher, (word32)test_rabbit[i].outLen);

        if (memcmp(plain, test_rabbit[i].input, test_rabbit[i].outLen))
            return -130 - i;

        if (memcmp(cipher, test_rabbit[i].output, test_rabbit[i].outLen))
            return -130 - 5 - i;
    }

    return 0;
}
#endif /* NO_RABBIT */


#ifndef NO_DES3
int des_test(void)
{
    const byte vector[] = { /* "now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    byte plain[24];
    byte cipher[24];

    Des enc;
    Des dec;

    const byte key[] =
    {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };

    const byte iv[] =
    {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
    };

    const byte verify[] =
    {
        0x8b,0x7c,0x52,0xb0,0x01,0x2b,0x6c,0xb8,
        0x4f,0x0f,0xeb,0xf3,0xfb,0x5f,0x86,0x73,
        0x15,0x85,0xb3,0x22,0x4b,0x86,0x2b,0x4b
    };

    int ret;

    ret = Des_SetKey(&enc, key, iv, DES_ENCRYPTION);
    if (ret != 0)
        return -31;

    Des_CbcEncrypt(&enc, cipher, vector, sizeof(vector));
    ret = Des_SetKey(&dec, key, iv, DES_DECRYPTION);
    if (ret != 0)
        return -32;
    Des_CbcDecrypt(&dec, plain, cipher, sizeof(cipher));

    if (memcmp(plain, vector, sizeof(plain)))
        return -33;

    if (memcmp(cipher, verify, sizeof(cipher)))
        return -34;

    return 0;
}
#endif /* NO_DES3 */


#ifndef NO_DES3
int des3_test(void)
{
    const byte vector[] = { /* "Now is the time for all " w/o trailing 0 */
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    byte plain[24];
    byte cipher[24];

    Des3 enc;
    Des3 dec;

    const byte key3[] =
    {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
        0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
    };
    const byte iv3[] =
    {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81

    };

    const byte verify3[] =
    {
        0x43,0xa0,0x29,0x7e,0xd1,0x84,0xf8,0x0e,
        0x89,0x64,0x84,0x32,0x12,0xd5,0x08,0x98,
        0x18,0x94,0x15,0x74,0x87,0x12,0x7d,0xb0
    };

    int ret;


#ifdef HAVE_CAVIUM
    if (Des3_InitCavium(&enc, CAVIUM_DEV_ID) != 0)
        return -20005;
    if (Des3_InitCavium(&dec, CAVIUM_DEV_ID) != 0)
        return -20006;
#endif
    ret = Des3_SetKey(&enc, key3, iv3, DES_ENCRYPTION);
    if (ret != 0)
        return -31;
    ret = Des3_SetKey(&dec, key3, iv3, DES_DECRYPTION);
    if (ret != 0)
        return -32;
    ret = Des3_CbcEncrypt(&enc, cipher, vector, sizeof(vector));
    if (ret != 0)
        return -33;
    ret = Des3_CbcDecrypt(&dec, plain, cipher, sizeof(cipher));
    if (ret != 0)
        return -34;

    if (memcmp(plain, vector, sizeof(plain)))
        return -35;

    if (memcmp(cipher, verify3, sizeof(cipher)))
        return -36;

#ifdef HAVE_CAVIUM
    Des3_FreeCavium(&enc);
    Des3_FreeCavium(&dec);
#endif
    return 0;
}
#endif /* NO_DES */


#ifndef NO_AES
int aes_test(void)
{
    Aes enc;
    Aes dec;

    const byte msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    const byte verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };

    byte key[] = "0123456789abcdef   ";  /* align */
    byte iv[]  = "1234567890abcdef   ";  /* align */

    byte cipher[AES_BLOCK_SIZE * 4];
    byte plain [AES_BLOCK_SIZE * 4];
    int  ret;

#ifdef HAVE_CAVIUM
        if (AesInitCavium(&enc, CAVIUM_DEV_ID) != 0)
            return -20003;
        if (AesInitCavium(&dec, CAVIUM_DEV_ID) != 0)
            return -20004;
#endif
    ret = AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1001;
    ret = AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1002;

    ret = AesCbcEncrypt(&enc, cipher, msg,   AES_BLOCK_SIZE);
    if (ret != 0)
        return -1005;
    ret = AesCbcDecrypt(&dec, plain, cipher, AES_BLOCK_SIZE);
    if (ret != 0)
        return -1006;

    if (memcmp(plain, msg, AES_BLOCK_SIZE))
        return -60;

    if (memcmp(cipher, verify, AES_BLOCK_SIZE))
        return -61;

#ifdef HAVE_CAVIUM
        AesFreeCavium(&enc);
        AesFreeCavium(&dec);
#endif
#ifdef CYASSL_AES_COUNTER
    {
        const byte ctrKey[] =
        {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };

        const byte ctrIv[] =
        {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
            0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
        };


        const byte ctrPlain[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };

        const byte ctrCipher[] =
        {
            0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
            0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
            0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
            0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
            0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
            0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
            0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
            0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
        };

        const byte oddCipher[] =
        {
            0xb9,0xd7,0xcb,0x08,0xb0,0xe1,0x7b,0xa0,
            0xc2
        };

        AesSetKeyDirect(&enc, ctrKey, AES_BLOCK_SIZE, ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        AesSetKeyDirect(&dec, ctrKey, AES_BLOCK_SIZE, ctrIv, AES_ENCRYPTION);

        AesCtrEncrypt(&enc, cipher, ctrPlain, AES_BLOCK_SIZE*4);
        AesCtrEncrypt(&dec, plain, cipher, AES_BLOCK_SIZE*4);

        if (memcmp(plain, ctrPlain, AES_BLOCK_SIZE*4))
            return -66;

        if (memcmp(cipher, ctrCipher, AES_BLOCK_SIZE*4))
            return -67;

        /* let's try with just 9 bytes, non block size test */
        AesSetKeyDirect(&enc, ctrKey, AES_BLOCK_SIZE, ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        AesSetKeyDirect(&dec, ctrKey, AES_BLOCK_SIZE, ctrIv, AES_ENCRYPTION);

        AesCtrEncrypt(&enc, cipher, ctrPlain, 9);
        AesCtrEncrypt(&dec, plain, cipher, 9);

        if (memcmp(plain, ctrPlain, 9))
            return -68;

        if (memcmp(cipher, ctrCipher, 9))
            return -69;

        /* and an additional 9 bytes to reuse tmp left buffer */
        AesCtrEncrypt(&enc, cipher, ctrPlain, 9);
        AesCtrEncrypt(&dec, plain, cipher, 9);

        if (memcmp(plain, ctrPlain, 9))
            return -70;

        if (memcmp(cipher, oddCipher, 9))
            return -71;
    }
#endif /* CYASSL_AES_COUNTER */

#if defined(CYASSL_AESNI) && defined(CYASSL_AES_DIRECT)
    {
        const byte niPlain[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };

        const byte niCipher[] =
        {
            0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
            0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
        };

        const byte niKey[] =
        {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };

        XMEMSET(cipher, 0, AES_BLOCK_SIZE);
        ret = AesSetKey(&enc, niKey, sizeof(niKey), cipher, AES_ENCRYPTION);
        if (ret != 0)
            return -1003;
        AesEncryptDirect(&enc, cipher, niPlain);
        if (XMEMCMP(cipher, niCipher, AES_BLOCK_SIZE) != 0)
            return -20006;

        XMEMSET(plain, 0, AES_BLOCK_SIZE);
        ret = AesSetKey(&dec, niKey, sizeof(niKey), plain, AES_DECRYPTION);
        if (ret != 0)
            return -1004;
        AesDecryptDirect(&dec, plain, niCipher);
        if (XMEMCMP(plain, niPlain, AES_BLOCK_SIZE) != 0)
            return -20007;
    }
#endif /* CYASSL_AESNI && CYASSL_AES_DIRECT */

    return 0;
}

#ifdef HAVE_AESGCM
int aesgcm_test(void)
{
    Aes enc;

    /*
     * This is Test Case 16 from the document Galois/
     * Counter Mode of Operation (GCM) by McGrew and
     * Viega.
     */
    const byte k[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    const byte iv[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    const byte p[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };

    const byte a[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    const byte c[] =
    {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };

    const byte t[] =
    {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };

    byte t2[sizeof(t)];
    byte p2[sizeof(c)];
    byte c2[sizeof(p)];

    int result;

    memset(t2, 0, sizeof(t2));
    memset(c2, 0, sizeof(c2));
    memset(p2, 0, sizeof(p2));

    AesGcmSetKey(&enc, k, sizeof(k));
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    AesGcmEncrypt(&enc, c2, p, sizeof(c2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (memcmp(c, c2, sizeof(c2)))
        return -68;
    if (memcmp(t, t2, sizeof(t2)))
        return -69;

    result = AesGcmDecrypt(&enc, p2, c2, sizeof(p2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result != 0)
        return -70;
    if (memcmp(p, p2, sizeof(p2)))
        return -71;

    return 0;
}

int gmac_test(void)
{
    Gmac gmac;

    const byte k1[] =
    {
        0x89, 0xc9, 0x49, 0xe9, 0xc8, 0x04, 0xaf, 0x01,
        0x4d, 0x56, 0x04, 0xb3, 0x94, 0x59, 0xf2, 0xc8
    };
    const byte iv1[] =
    {
        0xd1, 0xb1, 0x04, 0xc8, 0x15, 0xbf, 0x1e, 0x94,
        0xe2, 0x8c, 0x8f, 0x16
    };
    const byte a1[] =
    {
       0x82, 0xad, 0xcd, 0x63, 0x8d, 0x3f, 0xa9, 0xd9,
       0xf3, 0xe8, 0x41, 0x00, 0xd6, 0x1e, 0x07, 0x77
    };
    const byte t1[] =
    {
        0x88, 0xdb, 0x9d, 0x62, 0x17, 0x2e, 0xd0, 0x43,
        0xaa, 0x10, 0xf1, 0x6d, 0x22, 0x7d, 0xc4, 0x1b
    };

    const byte k2[] =
    {
        0x40, 0xf7, 0xec, 0xb2, 0x52, 0x6d, 0xaa, 0xd4,
        0x74, 0x25, 0x1d, 0xf4, 0x88, 0x9e, 0xf6, 0x5b
    };
    const byte iv2[] =
    {
        0xee, 0x9c, 0x6e, 0x06, 0x15, 0x45, 0x45, 0x03,
        0x1a, 0x60, 0x24, 0xa7
    };
    const byte a2[] =
    {
        0x94, 0x81, 0x2c, 0x87, 0x07, 0x4e, 0x15, 0x18,
        0x34, 0xb8, 0x35, 0xaf, 0x1c, 0xa5, 0x7e, 0x56
    };
    const byte t2[] =
    {
        0xc6, 0x81, 0x79, 0x8e, 0x3d, 0xda, 0xb0, 0x9f,
        0x8d, 0x83, 0xb0, 0xbb, 0x14, 0xb6, 0x91
    };

    const byte k3[] =
    {
        0xb8, 0xe4, 0x9a, 0x5e, 0x37, 0xf9, 0x98, 0x2b,
        0xb9, 0x6d, 0xd0, 0xc9, 0xb6, 0xab, 0x26, 0xac
    };
    const byte iv3[] =
    {
        0xe4, 0x4a, 0x42, 0x18, 0x8c, 0xae, 0x94, 0x92,
        0x6a, 0x9c, 0x26, 0xb0
    };
    const byte a3[] =
    {
        0x9d, 0xb9, 0x61, 0x68, 0xa6, 0x76, 0x7a, 0x31,
        0xf8, 0x29, 0xe4, 0x72, 0x61, 0x68, 0x3f, 0x8a
    };
    const byte t3[] =
    {
        0x23, 0xe2, 0x9f, 0x66, 0xe4, 0xc6, 0x52, 0x48
    };

    byte tag[16];

    memset(tag, 0, sizeof(tag));
    GmacSetKey(&gmac, k1, sizeof(k1));
    GmacUpdate(&gmac, iv1, sizeof(iv1), a1, sizeof(a1), tag, sizeof(t1));
    if (memcmp(t1, tag, sizeof(t1)) != 0)
        return -126;

    memset(tag, 0, sizeof(tag));
    GmacSetKey(&gmac, k2, sizeof(k2));
    GmacUpdate(&gmac, iv2, sizeof(iv2), a2, sizeof(a2), tag, sizeof(t2));
    if (memcmp(t2, tag, sizeof(t2)) != 0)
        return -127;

    memset(tag, 0, sizeof(tag));
    GmacSetKey(&gmac, k3, sizeof(k3));
    GmacUpdate(&gmac, iv3, sizeof(iv3), a3, sizeof(a3), tag, sizeof(t3));
    if (memcmp(t3, tag, sizeof(t3)) != 0)
        return -128;

    return 0;
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
int aesccm_test(void)
{
    Aes enc;

    /* key */
    const byte k[] =
    {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
    };

    /* nonce */
    const byte iv[] =
    {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5
    };

    /* plaintext */
    const byte p[] =
    {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
    };

    const byte a[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    const byte c[] =
    {
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
        0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
        0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
    };

    const byte t[] =
    {
        0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
    };

    byte t2[sizeof(t)];
    byte p2[sizeof(p)];
    byte c2[sizeof(c)];

    int result;

    memset(t2, 0, sizeof(t2));
    memset(c2, 0, sizeof(c2));
    memset(p2, 0, sizeof(p2));

    AesCcmSetKey(&enc, k, sizeof(k));
    /* AES-CCM encrypt and decrypt both use AES encrypt internally */
    AesCcmEncrypt(&enc, c2, p, sizeof(c2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (memcmp(c, c2, sizeof(c2)))
        return -107;
    if (memcmp(t, t2, sizeof(t2)))
        return -108;

    result = AesCcmDecrypt(&enc, p2, c2, sizeof(p2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result != 0)
        return -109;
    if (memcmp(p, p2, sizeof(p2)))
        return -110;

    /* Test the authentication failure */
    t2[0]++; /* Corrupt the authentication tag. */
    result = AesCcmDecrypt(&enc, p2, c, sizeof(p2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result == 0)
        return -111;

    /* Clear c2 to compare against p2. p2 should be set to zero in case of
     * authentication fail. */
    memset(c2, 0, sizeof(c2));
    if (memcmp(p2, c2, sizeof(p2)))
        return -112;

    return 0;
}
#endif /* HAVE_AESCCM */


#endif /* NO_AES */


#ifdef HAVE_CAMELLIA

enum {
    CAM_ECB_ENC, CAM_ECB_DEC, CAM_CBC_ENC, CAM_CBC_DEC
};

typedef struct {
    int type;
    const byte* plaintext;
    const byte* iv;
    const byte* ciphertext;
    const byte* key;
    word32 keySz;
    int errorCode;
} test_vector_t;

int camellia_test(void)
{
    /* Camellia ECB Test Plaintext */
    static const byte pte[] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /* Camellia ECB Test Initialization Vector */
    static const byte ive[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    /* Test 1: Camellia ECB 128-bit key */
    static const byte k1[] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const byte c1[] =
    {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43
    };

    /* Test 2: Camellia ECB 192-bit key */
    static const byte k2[] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    static const byte c2[] =
    {
        0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8,
        0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9
    };

    /* Test 3: Camellia ECB 256-bit key */
    static const byte k3[] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const byte c3[] =
    {
        0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c,
        0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09
    };

    /* Camellia CBC Test Plaintext */
    static const byte ptc[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };

    /* Camellia CBC Test Initialization Vector */
    static const byte ivc[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    /* Test 4: Camellia-CBC 128-bit key */
    static const byte k4[] =
    {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    static const byte c4[] =
    {
        0x16, 0x07, 0xCF, 0x49, 0x4B, 0x36, 0xBB, 0xF0,
        0x0D, 0xAE, 0xB0, 0xB5, 0x03, 0xC8, 0x31, 0xAB
    };

    /* Test 5: Camellia-CBC 192-bit key */
    static const byte k5[] =
    {
        0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
        0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
        0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
    };
    static const byte c5[] =
    {
        0x2A, 0x48, 0x30, 0xAB, 0x5A, 0xC4, 0xA1, 0xA2,
        0x40, 0x59, 0x55, 0xFD, 0x21, 0x95, 0xCF, 0x93
    };

    /* Test 6: CBC 256-bit key */
    static const byte k6[] =
    {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
        0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
    };
    static const byte c6[] =
    {
        0xE6, 0xCF, 0xA3, 0x5F, 0xC0, 0x2B, 0x13, 0x4A,
        0x4D, 0x2C, 0x0B, 0x67, 0x37, 0xAC, 0x3E, 0xDA
    };

    byte out[CAMELLIA_BLOCK_SIZE];
    Camellia cam;
    int i, testsSz;
    const test_vector_t testVectors[] =
    {
        {CAM_ECB_ENC, pte, ive, c1, k1, sizeof(k1), -114},
        {CAM_ECB_ENC, pte, ive, c2, k2, sizeof(k2), -115},
        {CAM_ECB_ENC, pte, ive, c3, k3, sizeof(k3), -116},
        {CAM_ECB_DEC, pte, ive, c1, k1, sizeof(k1), -117},
        {CAM_ECB_DEC, pte, ive, c2, k2, sizeof(k2), -118},
        {CAM_ECB_DEC, pte, ive, c3, k3, sizeof(k3), -119},
        {CAM_CBC_ENC, ptc, ivc, c4, k4, sizeof(k4), -120},
        {CAM_CBC_ENC, ptc, ivc, c5, k5, sizeof(k5), -121},
        {CAM_CBC_ENC, ptc, ivc, c6, k6, sizeof(k6), -122},
        {CAM_CBC_DEC, ptc, ivc, c4, k4, sizeof(k4), -123},
        {CAM_CBC_DEC, ptc, ivc, c5, k5, sizeof(k5), -124},
        {CAM_CBC_DEC, ptc, ivc, c6, k6, sizeof(k6), -125}
    };

    testsSz = sizeof(testVectors)/sizeof(test_vector_t);
    for (i = 0; i < testsSz; i++) {
        if (CamelliaSetKey(&cam, testVectors[i].key, testVectors[i].keySz,
                                                        testVectors[i].iv) != 0)
            return testVectors[i].errorCode;

        switch (testVectors[i].type) {
            case CAM_ECB_ENC:
                CamelliaEncryptDirect(&cam, out, testVectors[i].plaintext);
                if (memcmp(out, testVectors[i].ciphertext, CAMELLIA_BLOCK_SIZE))
                    return testVectors[i].errorCode;
                break;
            case CAM_ECB_DEC:
                CamelliaDecryptDirect(&cam, out, testVectors[i].ciphertext);
                if (memcmp(out, testVectors[i].plaintext, CAMELLIA_BLOCK_SIZE))
                    return testVectors[i].errorCode;
                break;
            case CAM_CBC_ENC:
                CamelliaCbcEncrypt(&cam, out, testVectors[i].plaintext,
                                                           CAMELLIA_BLOCK_SIZE);
                if (memcmp(out, testVectors[i].ciphertext, CAMELLIA_BLOCK_SIZE))
                    return testVectors[i].errorCode;
                break;
            case CAM_CBC_DEC:
                CamelliaCbcDecrypt(&cam, out, testVectors[i].ciphertext,
                                                           CAMELLIA_BLOCK_SIZE);
                if (memcmp(out, testVectors[i].plaintext, CAMELLIA_BLOCK_SIZE))
                    return testVectors[i].errorCode;
                break;
            default:
                break;
        }
    }

    /* Setting the IV and checking it was actually set. */
    CamelliaSetIV(&cam, ivc);
    if (XMEMCMP(cam.reg, ivc, CAMELLIA_BLOCK_SIZE))
        return -1;

    /* Setting the IV to NULL should be same as all zeros IV */
    if (CamelliaSetIV(&cam, NULL) != 0 ||
                                    XMEMCMP(cam.reg, ive, CAMELLIA_BLOCK_SIZE))
        return -1;

    /* First parameter should never be null */
    if (CamelliaSetIV(NULL, NULL) == 0)
        return -1;

    /* First parameter should never be null, check it fails */
    if (CamelliaSetKey(NULL, k1, sizeof(k1), NULL) == 0)
        return -1;

    /* Key should have a size of 16, 24, or 32 */
    if (CamelliaSetKey(&cam, k1, 0, NULL) == 0)
        return -1;

    return 0;
}
#endif /* HAVE_CAMELLIA */


#if defined(HAVE_HASHDRBG) || defined(NO_RC4)

int random_test(void)
{
    const byte test1Entropy[] =
    {
        0xa6, 0x5a, 0xd0, 0xf3, 0x45, 0xdb, 0x4e, 0x0e, 0xff, 0xe8, 0x75, 0xc3,
        0xa2, 0xe7, 0x1f, 0x42, 0xc7, 0x12, 0x9d, 0x62, 0x0f, 0xf5, 0xc1, 0x19,
        0xa9, 0xef, 0x55, 0xf0, 0x51, 0x85, 0xe0, 0xfb, 0x85, 0x81, 0xf9, 0x31,
        0x75, 0x17, 0x27, 0x6e, 0x06, 0xe9, 0x60, 0x7d, 0xdb, 0xcb, 0xcc, 0x2e
    };
    const byte test1Output[] =
    {
        0xd3, 0xe1, 0x60, 0xc3, 0x5b, 0x99, 0xf3, 0x40, 0xb2, 0x62, 0x82, 0x64,
        0xd1, 0x75, 0x10, 0x60, 0xe0, 0x04, 0x5d, 0xa3, 0x83, 0xff, 0x57, 0xa5,
        0x7d, 0x73, 0xa6, 0x73, 0xd2, 0xb8, 0xd8, 0x0d, 0xaa, 0xf6, 0xa6, 0xc3,
        0x5a, 0x91, 0xbb, 0x45, 0x79, 0xd7, 0x3f, 0xd0, 0xc8, 0xfe, 0xd1, 0x11,
        0xb0, 0x39, 0x13, 0x06, 0x82, 0x8a, 0xdf, 0xed, 0x52, 0x8f, 0x01, 0x81,
        0x21, 0xb3, 0xfe, 0xbd, 0xc3, 0x43, 0xe7, 0x97, 0xb8, 0x7d, 0xbb, 0x63,
        0xdb, 0x13, 0x33, 0xde, 0xd9, 0xd1, 0xec, 0xe1, 0x77, 0xcf, 0xa6, 0xb7,
        0x1f, 0xe8, 0xab, 0x1d, 0xa4, 0x66, 0x24, 0xed, 0x64, 0x15, 0xe5, 0x1c,
        0xcd, 0xe2, 0xc7, 0xca, 0x86, 0xe2, 0x83, 0x99, 0x0e, 0xea, 0xeb, 0x91,
        0x12, 0x04, 0x15, 0x52, 0x8b, 0x22, 0x95, 0x91, 0x02, 0x81, 0xb0, 0x2d,
        0xd4, 0x31, 0xf4, 0xc9, 0xf7, 0x04, 0x27, 0xdf
    };
    const byte test2EntropyA[] =
    {
        0x63, 0x36, 0x33, 0x77, 0xe4, 0x1e, 0x86, 0x46, 0x8d, 0xeb, 0x0a, 0xb4,
        0xa8, 0xed, 0x68, 0x3f, 0x6a, 0x13, 0x4e, 0x47, 0xe0, 0x14, 0xc7, 0x00,
        0x45, 0x4e, 0x81, 0xe9, 0x53, 0x58, 0xa5, 0x69, 0x80, 0x8a, 0xa3, 0x8f,
        0x2a, 0x72, 0xa6, 0x23, 0x59, 0x91, 0x5a, 0x9f, 0x8a, 0x04, 0xca, 0x68
    };
    const byte test2EntropyB[] =
    {
        0xe6, 0x2b, 0x8a, 0x8e, 0xe8, 0xf1, 0x41, 0xb6, 0x98, 0x05, 0x66, 0xe3,
        0xbf, 0xe3, 0xc0, 0x49, 0x03, 0xda, 0xd4, 0xac, 0x2c, 0xdf, 0x9f, 0x22,
        0x80, 0x01, 0x0a, 0x67, 0x39, 0xbc, 0x83, 0xd3
    };
    const byte test2Output[] =
    {
        0x04, 0xee, 0xc6, 0x3b, 0xb2, 0x31, 0xdf, 0x2c, 0x63, 0x0a, 0x1a, 0xfb,
        0xe7, 0x24, 0x94, 0x9d, 0x00, 0x5a, 0x58, 0x78, 0x51, 0xe1, 0xaa, 0x79,
        0x5e, 0x47, 0x73, 0x47, 0xc8, 0xb0, 0x56, 0x62, 0x1c, 0x18, 0xbd, 0xdc,
        0xdd, 0x8d, 0x99, 0xfc, 0x5f, 0xc2, 0xb9, 0x20, 0x53, 0xd8, 0xcf, 0xac,
        0xfb, 0x0b, 0xb8, 0x83, 0x12, 0x05, 0xfa, 0xd1, 0xdd, 0xd6, 0xc0, 0x71,
        0x31, 0x8a, 0x60, 0x18, 0xf0, 0x3b, 0x73, 0xf5, 0xed, 0xe4, 0xd4, 0xd0,
        0x71, 0xf9, 0xde, 0x03, 0xfd, 0x7a, 0xea, 0x10, 0x5d, 0x92, 0x99, 0xb8,
        0xaf, 0x99, 0xaa, 0x07, 0x5b, 0xdb, 0x4d, 0xb9, 0xaa, 0x28, 0xc1, 0x8d,
        0x17, 0x4b, 0x56, 0xee, 0x2a, 0x01, 0x4d, 0x09, 0x88, 0x96, 0xff, 0x22,
        0x82, 0xc9, 0x55, 0xa8, 0x19, 0x69, 0xe0, 0x69, 0xfa, 0x8c, 0xe0, 0x07,
        0xa1, 0x80, 0x18, 0x3a, 0x07, 0xdf, 0xae, 0x17
    };
    int ret;

    ret = RNG_HealthTest(0, test1Entropy, sizeof(test1Entropy), NULL, 0,
                            test1Output, sizeof(test1Output));
    if (ret != 0) return -39;

    ret = RNG_HealthTest(1, test2EntropyA, sizeof(test2EntropyA),
                            test2EntropyB, sizeof(test2EntropyB),
                            test2Output, sizeof(test2Output));
    if (ret != 0) return -40;

    return 0;
}

#else /* HAVE_HASHDRBG || NO_RC4 */

int random_test(void)
{
    RNG  rng;
    byte block[32];
    int ret;

#ifdef HAVE_CAVIUM
    ret = InitRngCavium(&rng, CAVIUM_DEV_ID);
    if (ret != 0) return -2007;
#endif
    ret = InitRng(&rng);
    if (ret != 0) return -39;

    ret = RNG_GenerateBlock(&rng, block, sizeof(block));
    if (ret != 0) return -40;

    return 0;
}

#endif /* HAVE_HASHDRBG || NO_RC4 */


#ifdef HAVE_NTRU

byte GetEntropy(ENTROPY_CMD cmd, byte* out);

byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    static RNG rng;

    if (cmd == INIT)
        return (InitRng(&rng) == 0) ? 1 : 0;

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endif /* HAVE_NTRU */

#ifndef NO_RSA

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #ifdef FREESCALE_MQX
        static const char* clientKey  = "a:\\certs\\client-key.der";
        static const char* clientCert = "a:\\certs\\client-cert.der";
        #ifdef CYASSL_CERT_GEN
            static const char* caKeyFile  = "a:\\certs\\ca-key.der";
            static const char* caCertFile = "a:\\certs\\ca-cert.pem";
            #ifdef HAVE_ECC
                static const char* eccCaKeyFile  = "a:\\certs\\ecc-key.der";
                static const char* eccCaCertFile = "a:\\certs\\server-ecc.pem";
            #endif
        #endif
    #elif defined(CYASSL_MKD_SHELL)
        static char* clientKey = "certs/client-key.der";
        static char* clientCert = "certs/client-cert.der";
        void set_clientKey(char *key) {  clientKey = key ; }
        void set_clientCert(char *cert) {  clientCert = cert ; }
        #ifdef CYASSL_CERT_GEN
            static char* caKeyFile  = "certs/ca-key.der";
            static char* caCertFile = "certs/ca-cert.pem";
            void set_caKeyFile (char * key)  { caKeyFile   = key ; }
            void set_caCertFile(char * cert) { caCertFile = cert ; }
            #ifdef HAVE_ECC
                static const char* eccCaKeyFile  = "certs/ecc-key.der";
                static const char* eccCaCertFile = "certs/server-ecc.pem";
                void set_eccCaKeyFile (char * key)  { eccCaKeyFile  = key ; }
                void set_eccCaCertFile(char * cert) { eccCaCertFile = cert ; }
            #endif
        #endif
    #else
        static const char* clientKey  = "./certs/client-key.der";
        static const char* clientCert = "./certs/client-cert.der";
        #ifdef CYASSL_CERT_GEN
            static const char* caKeyFile  = "./certs/ca-key.der";
            static const char* caCertFile = "./certs/ca-cert.pem";
            #ifdef HAVE_ECC
                static const char* eccCaKeyFile  = "./certs/ecc-key.der";
                static const char* eccCaCertFile = "./certs/server-ecc.pem";
            #endif
        #endif
    #endif
#endif



#define FOURK_BUF 4096

int rsa_test(void)
{
    byte*   tmp;
    size_t bytes;
    RsaKey key;
    RNG    rng;
    word32 idx = 0;
    int    ret;
    byte   in[] = "Everyone gets Friday off.";
    word32 inLen = (word32)strlen((char*)in);
    byte   out[256];
    byte   plain[256];
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    FILE*  file, * file2;
#endif
#ifdef CYASSL_TEST_CERT
    DecodedCert cert;
#endif

    tmp = (byte*)malloc(FOURK_BUF);
    if (tmp == NULL)
        return -40;

#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, client_key_der_1024, sizeof_client_key_der_1024);
    bytes = sizeof_client_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, client_key_der_2048, sizeof_client_key_der_2048);
    bytes = sizeof_client_key_der_2048;
#else
    file = fopen(clientKey, "rb");

    if (!file)
        err_sys("can't open ./certs/client-key.der, "
                "Please run from CyaSSL home dir", -40);

    bytes = fread(tmp, 1, FOURK_BUF, file);
    fclose(file);
#endif /* USE_CERT_BUFFERS */

#ifdef HAVE_CAVIUM
    RsaInitCavium(&key, CAVIUM_DEV_ID);
#endif
    ret = InitRsaKey(&key, 0);
    if (ret != 0) return -39;
    ret = RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
    if (ret != 0) return -41;

    ret = InitRng(&rng);
    if (ret != 0) return -42;

    ret = RsaPublicEncrypt(in, inLen, out, sizeof(out), &key, &rng);
    if (ret < 0) return -43;

    ret = RsaPrivateDecrypt(out, ret, plain, sizeof(plain), &key);
    if (ret < 0) return -44;

    if (memcmp(plain, in, inLen)) return -45;

    ret = RsaSSL_Sign(in, inLen, out, sizeof(out), &key, &rng);
    if (ret < 0) return -46;

    memset(plain, 0, sizeof(plain));
    ret = RsaSSL_Verify(out, ret, plain, sizeof(plain), &key);
    if (ret < 0) return -47;

    if (memcmp(plain, in, ret)) return -48;

#if defined(CYASSL_MDK_ARM)
    #define sizeof(s) strlen((char *)(s))
#endif

#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, client_cert_der_1024, sizeof_client_cert_der_1024);
    bytes = sizeof_client_cert_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, client_cert_der_2048, sizeof_client_cert_der_2048);
    bytes = sizeof_client_cert_der_2048;
#else
    file2 = fopen(clientCert, "rb");
    if (!file2)
        return -49;

    bytes = fread(tmp, 1, FOURK_BUF, file2);
    fclose(file2);
#endif

#ifdef sizeof
		#undef sizeof
#endif

#ifdef CYASSL_TEST_CERT
    InitDecodedCert(&cert, tmp, (word32)bytes, 0);

    ret = ParseCert(&cert, CERT_TYPE, NO_VERIFY, 0);
    if (ret != 0) return -491;

    FreeDecodedCert(&cert);
#else
    (void)bytes;
#endif


#ifdef CYASSL_KEY_GEN
    {
        byte*  der;
        byte*  pem;
        int    derSz = 0;
        int    pemSz = 0;
        RsaKey derIn;
        RsaKey genKey;
        FILE*  keyFile;
        FILE*  pemFile;

        ret = InitRsaKey(&genKey, 0);
        if (ret != 0)
            return -300;
        ret = MakeRsaKey(&genKey, 1024, 65537, &rng);
        if (ret != 0)
            return -301;

        der = (byte*)malloc(FOURK_BUF);
        if (der == NULL) {
            FreeRsaKey(&genKey);
            return -307;
        }
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(der);
            FreeRsaKey(&genKey);
            return -308;
        }

        derSz = RsaKeyToDer(&genKey, der, FOURK_BUF);
        if (derSz < 0) {
            free(der);
            free(pem);
            return -302;
        }

        keyFile = fopen("./key.der", "wb");
        if (!keyFile) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -303;
        }
        ret = (int)fwrite(der, 1, derSz, keyFile);
        fclose(keyFile);
        if (ret != derSz) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -313;
        }

        pemSz = DerToPem(der, derSz, pem, FOURK_BUF, PRIVATEKEY_TYPE);
        if (pemSz < 0) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -304;
        }

        pemFile = fopen("./key.pem", "wb");
        if (!pemFile) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -305;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        fclose(pemFile);
        if (ret != pemSz) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -314;
        }

        ret = InitRsaKey(&derIn, 0);
        if (ret != 0) {
            free(der);
            free(pem);
            FreeRsaKey(&genKey);
            return -3060;
        }
        idx = 0;
        ret = RsaPrivateKeyDecode(der, &idx, &derIn, derSz);
        if (ret != 0) {
            free(der);
            free(pem);
            FreeRsaKey(&derIn);
            FreeRsaKey(&genKey);
            return -306;
        }

        FreeRsaKey(&derIn);
        FreeRsaKey(&genKey);
        free(pem);
        free(der);
    }
#endif /* CYASSL_KEY_GEN */


#ifdef CYASSL_CERT_GEN
    /* self signed */
    {
        Cert        myCert;
        byte*       derCert;
        byte*       pem;
        FILE*       derFile;
        FILE*       pemFile;
        int         certSz;
        int         pemSz;
#ifdef CYASSL_TEST_CERT
        DecodedCert decode;
#endif

        derCert = (byte*)malloc(FOURK_BUF);
        if (derCert == NULL)
            return -309;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(derCert);
            return -310;
        }

        InitCert(&myCert);

        strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
        strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
        strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
        strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);
        myCert.isCA    = 1;
        myCert.sigType = CTC_SHA256wRSA;

        certSz = MakeSelfCert(&myCert, derCert, FOURK_BUF, &key, &rng);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            return -401;
        }

#ifdef CYASSL_TEST_CERT
        InitDecodedCert(&decode, derCert, certSz, 0);
        ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -402;
        }
        FreeDecodedCert(&decode);
#endif
        derFile = fopen("./cert.der", "wb");
        if (!derFile) {
            free(derCert);
            free(pem);
            return -403;
        }
        ret = (int)fwrite(derCert, 1, certSz, derFile);
        fclose(derFile);
        if (ret != certSz) {
            free(derCert);
            free(pem);
            return -414;
        }

        pemSz = DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
        if (pemSz < 0) {
            free(derCert);
            free(pem);
            return -404;
        }

        pemFile = fopen("./cert.pem", "wb");
        if (!pemFile) {
            free(derCert);
            free(pem);
            return -405;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        fclose(pemFile);
        if (ret != pemSz) {
            free(derCert);
            free(pem);
            return -406;
        }
        free(pem);
        free(derCert);
    }
    /* CA style */
    {
        RsaKey      caKey;
        Cert        myCert;
        byte*       derCert;
        byte*       pem;
        FILE*       derFile;
        FILE*       pemFile;
        int         certSz;
        int         pemSz;
        size_t      bytes3;
        word32      idx3 = 0;
        FILE*       file3 ;
#ifdef CYASSL_TEST_CERT
        DecodedCert decode;
#endif

        derCert = (byte*)malloc(FOURK_BUF);
        if (derCert == NULL)
            return -311;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(derCert);
            return -312;
        }

        file3 = fopen(caKeyFile, "rb");

        if (!file3) {
            free(derCert);
            free(pem);
            return -412;
        }

        bytes3 = fread(tmp, 1, FOURK_BUF, file3);
        fclose(file3);

        ret = InitRsaKey(&caKey, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -411;
        }
        ret = RsaPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes3);
        if (ret != 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -413;
        }

        InitCert(&myCert);

        strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
        strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
        strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
        strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);

        ret = SetIssuer(&myCert, caCertFile);
        if (ret < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -405;
        }

        certSz = MakeCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -407;
        }

        certSz = SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF,
                          &caKey, NULL, &rng);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -408;
        }


#ifdef CYASSL_TEST_CERT
        InitDecodedCert(&decode, derCert, certSz, 0);
        ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -409;
        }
        FreeDecodedCert(&decode);
#endif

        derFile = fopen("./othercert.der", "wb");
        if (!derFile) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -410;
        }
        ret = (int)fwrite(derCert, 1, certSz, derFile);
        fclose(derFile);
        if (ret != certSz) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -416;
        }

        pemSz = DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
        if (pemSz < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -411;
        }

        pemFile = fopen("./othercert.pem", "wb");
        if (!pemFile) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -412;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        if (ret != pemSz) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -415;
        }
        fclose(pemFile);
        free(pem);
        free(derCert);
        FreeRsaKey(&caKey);
    }
#ifdef HAVE_ECC
    /* ECC CA style */
    {
        ecc_key     caKey;
        Cert        myCert;
        byte*       derCert;
        byte*       pem;
        FILE*       derFile;
        FILE*       pemFile;
        int         certSz;
        int         pemSz;
        size_t      bytes3;
        word32      idx3 = 0;
        FILE*       file3;
#ifdef CYASSL_TEST_CERT
        DecodedCert decode;
#endif

        derCert = (byte*)malloc(FOURK_BUF);
        if (derCert == NULL)
            return -5311;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(derCert);
            return -5312;
        }

        file3 = fopen(eccCaKeyFile, "rb");

        if (!file3) {
            free(derCert);
            free(pem);
            return -5412;
        }

        bytes3 = fread(tmp, 1, FOURK_BUF, file3);
        fclose(file3);

        ecc_init(&caKey);
        ret = EccPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes3);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -5413;
        }

        InitCert(&myCert);
        myCert.sigType = CTC_SHA256wECDSA;

        strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
        strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(myCert.subject.org, "wolfSSL", CTC_NAME_SIZE);
        strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(myCert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
        strncpy(myCert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);

        ret = SetIssuer(&myCert, eccCaCertFile);
        if (ret < 0) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5405;
        }

        certSz = MakeCert(&myCert, derCert, FOURK_BUF, NULL, &caKey, &rng);
        if (certSz < 0) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5407;
        }

        certSz = SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF,
                          NULL, &caKey, &rng);
        if (certSz < 0) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5408;
        }

#ifdef CYASSL_TEST_CERT
        InitDecodedCert(&decode, derCert, certSz, 0);
        ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
        if (ret != 0) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5409;
        }
        FreeDecodedCert(&decode);
#endif

        derFile = fopen("./certecc.der", "wb");
        if (!derFile) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5410;
        }
        ret = (int)fwrite(derCert, 1, certSz, derFile);
        fclose(derFile);
        if (ret != certSz) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5414;
        }

        pemSz = DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
        if (pemSz < 0) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5411;
        }

        pemFile = fopen("./certecc.pem", "wb");
        if (!pemFile) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5412;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        if (ret != pemSz) {
            free(pem);
            free(derCert);
            ecc_free(&caKey);
            return -5415;
        }
        fclose(pemFile);
        free(pem);
        free(derCert);
        ecc_free(&caKey);
    }
#endif /* HAVE_ECC */
#ifdef HAVE_NTRU
    {
        RsaKey      caKey;
        Cert        myCert;
        byte*       derCert;
        byte*       pem;
        FILE*       derFile;
        FILE*       pemFile;
        FILE*       caFile;
        FILE*       ntruPrivFile;
        int         certSz;
        int         pemSz;
        word32      idx3;
#ifdef CYASSL_TEST_CERT
        DecodedCert decode;
#endif
        derCert = (byte*)malloc(FOURK_BUF);
        if (derCert == NULL)
            return -311;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(derCert);
            return -312;
        }

        byte   public_key[557];          /* sized for EES401EP2 */
        word16 public_key_len;           /* no. of octets in public key */
        byte   private_key[607];         /* sized for EES401EP2 */
        word16 private_key_len;          /* no. of octets in private key */
        DRBG_HANDLE drbg;
        static uint8_t const pers_str[] = {
                'C', 'y', 'a', 'S', 'S', 'L', ' ', 't', 'e', 's', 't'
        };
        word32 rc = ntru_crypto_drbg_instantiate(112, pers_str,
                          sizeof(pers_str), GetEntropy, &drbg);
        if (rc != DRBG_OK) {
            free(derCert);
            free(pem);
            return -448;
        }

        rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2,
                                             &public_key_len, NULL,
                                             &private_key_len, NULL);
        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -449;
        }

        rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2,
                                             &public_key_len, public_key,
                                             &private_key_len, private_key);
        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -450;
        }

        rc = ntru_crypto_drbg_uninstantiate(drbg);

        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -451;
        }

        caFile = fopen(caKeyFile, "rb");

        if (!caFile) {
            free(derCert);
            free(pem);
            return -452;
        }

        bytes = fread(tmp, 1, FOURK_BUF, caFile);
        fclose(caFile);

        ret = InitRsaKey(&caKey, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -453;
        }
        ret = RsaPrivateKeyDecode(tmp, &idx3, &caKey, (word32)bytes);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -454;
        }

        InitCert(&myCert);

        strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
        strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
        strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
        strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);

        ret = SetIssuer(&myCert, caCertFile);
        if (ret < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -455;
        }

        certSz = MakeNtruCert(&myCert, derCert, FOURK_BUF, public_key,
                              public_key_len, &rng);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            FreeRsaKey(&caKey);
            return -456;
        }

        certSz = SignCert(myCert.bodySz, myCert.sigType, derCert, FOURK_BUF,
                          &caKey, NULL, &rng);
        FreeRsaKey(&caKey);
        if (certSz < 0) {
            free(derCert);
            free(pem);
            return -457;
        }


#ifdef CYASSL_TEST_CERT
        InitDecodedCert(&decode, derCert, certSz, 0);
        ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -458;
        }
        FreeDecodedCert(&decode);
#endif
        derFile = fopen("./ntru-cert.der", "wb");
        if (!derFile) {
            free(derCert);
            free(pem);
            return -459;
        }
        ret = (int)fwrite(derCert, 1, certSz, derFile);
        fclose(derFile);
        if (ret != certSz) {
            free(derCert);
            free(pem);
            return -473;
        }

        pemSz = DerToPem(derCert, certSz, pem, FOURK_BUF, CERT_TYPE);
        if (pemSz < 0) {
            free(derCert);
            free(pem);
            return -460;
        }

        pemFile = fopen("./ntru-cert.pem", "wb");
        if (!pemFile) {
            free(derCert);
            free(pem);
            return -461;
        }
        ret = (int)fwrite(pem, 1, pemSz, pemFile);
        fclose(pemFile);
        if (ret != pemSz) {
            free(derCert);
            free(pem);
            return -474;
        }

        ntruPrivFile = fopen("./ntru-key.raw", "wb");
        if (!ntruPrivFile) {
            free(derCert);
            free(pem);
            return -462;
        }
        ret = (int)fwrite(private_key, 1, private_key_len, ntruPrivFile);
        fclose(ntruPrivFile);
        if (ret != private_key_len) {
            free(pem);
            free(derCert);
            return -475;
        }
        free(pem);
        free(derCert);
    }
#endif /* HAVE_NTRU */
#ifdef CYASSL_CERT_REQ
    {
        Cert        req;
        byte*       der;
        byte*       pem;
        int         derSz;
        int         pemSz;
        FILE*       reqFile;

        der = (byte*)malloc(FOURK_BUF);
        if (der == NULL)
            return -463;
        pem = (byte*)malloc(FOURK_BUF);
        if (pem == NULL) {
            free(der);
            return -464;
        }

        InitCert(&req);

        req.version = 0;
        req.isCA    = 1;
        strncpy(req.challengePw, "yassl123", CTC_NAME_SIZE);
        strncpy(req.subject.country, "US", CTC_NAME_SIZE);
        strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
        strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
        strncpy(req.subject.org, "yaSSL", CTC_NAME_SIZE);
        strncpy(req.subject.unit, "Development", CTC_NAME_SIZE);
        strncpy(req.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
        strncpy(req.subject.email, "info@yassl.com", CTC_NAME_SIZE);
        req.sigType = CTC_SHA256wRSA;

        derSz = MakeCertReq(&req, der, FOURK_BUF, &key, NULL);
        if (derSz < 0) {
            free(pem);
            free(der);
            return -465;
        }

        derSz = SignCert(req.bodySz, req.sigType, der, FOURK_BUF,
                          &key, NULL, &rng);
        if (derSz < 0) {
            free(pem);
            free(der);
            return -466;
        }

        pemSz = DerToPem(der, derSz, pem, FOURK_BUF, CERTREQ_TYPE);
        if (pemSz < 0) {
            free(pem);
            free(der);
            return -467;
        }

        reqFile = fopen("./certreq.der", "wb");
        if (!reqFile) {
            free(pem);
            free(der);
            return -468;
        }

        ret = (int)fwrite(der, 1, derSz, reqFile);
        fclose(reqFile);
        if (ret != derSz) {
            free(pem);
            free(der);
            return -471;
        }

        reqFile = fopen("./certreq.pem", "wb");
 t (C) 2if (!reqFile) {ht (C) 20
 * free(pemight (C) 20 * This fder is part of Cyareturn -469ght (C) 20}ht (C) 20ret = (int)fwrit file, 1, pemSz, 14 wolfSght (C) 20fclose(he terms of the GN06-2te i!= underSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free softwa70; you can reof the GNUis file is part ofSSL.
 *
 * CyaS}
#endif /* CYASSL_CERT_REQ */ibuted in the hope thatGEN wilht (CFreeRsaKey(&key);
#ifdef HAVE_CAVIUMht (CRsaRRANCaviumthout eveuted ht (Cater tmp);ANY WAee soft0;
}
TY or FI
ven nthe NO_DH
 * G !defined(USEe thatBUFFERS_1024) &&ic License for more details2048)ht (Cen the FREESCALE_MQXht (C) 20static const char* dhKey = "a:\tests\\dhcopy.der"ght (C#else License
 * along with this program; * tests/ite to the Free Sofor FISee the
int dh_test(void)
L Inc.1, UCULAR ght (Cword32 bytes   #include <idx = 0, priver tpubssl/ccyass2l/ctaoc2, agreeer tifdef X2ght (Cconf   tmp[.
 *]R
    #includpt/s[256b.h>  /* we're ubng malloc / free diriv2ng malloc / free direndef NO_CRYPT_TEST
ifdefdef CYASSL_TEST_CERT
  ndef NO_CRYPDrogra keyasn.h>
#else
   ER
    RNGFIG_Hng;e
 * Gthe  for more details.
 *ht (CXMEMCPYR A ,USA
key_ders.
 *, sizeof_#include <cyasss of thconfi =/ctaocrypt/md5.h>
#inclITY lif u should have received a copy of thcrypt/md2.h>
#include <ccopyl/ctaocrypt/md5.h>
#copy de <cyassl/ctaocrypt/md4.h>
#inccopy <cyaware
 *FILE*  file = fopen(progr, "ryrighHAVE_C6-20/cta of ths free softw50lude <cassl/cta(clude )SS Fadd2.h>
1l/ctaocrR A P,l/cta2.h>
#iU Generocrypt/buted in t for more detailUT ANY WAInit
#elsthout eve <cyassl/ctaocryp2t/camelte it 
#elsDecodOR A , &idx, hout,<cyasst/camelas publishe0ocrypt/coding.h>
#i1lude <cyinclud<cyassl/ctaocrypt/hmac.h>
#include <cya2ssl/ctaocrypt/dh.h>
#include <cyassl/ctaocryp2ARTICULAR  =cyassRng(&rngocrypt/dh.h>
#include <cyassl/ctaocryp3aocrypt/pwdba DhGenerateKeyPairthout, inclrypt/s, &<cyassl/ctaenditaoc <cyassl/ct+aocrclude <cyassl/ctaocr2ypt/ecc.h>
#ake2pt/settings.f
#ifs.h>
ocrypt/dh.h>
#include <cyassl/ctaocryp4HAVE_ECC
    #inAfdeftaocrypifdef, &ifdef XMAh>
#en<cyassl/ctatings.h>
E2
    #include PKCS7
    

#ifdefake2LLOC_USE
#endif
#pt/settings.l/ctaococrypt/dh.h>
#include <cyassl/ctaocryp5lude <cyassmemcmp(nclude rning toifdef X)ocrypt/coding.h>
#i6lude <cRRANl/ctaocrypt/camelnssl/evp.h>
  #ifdTICULAR PURPOSE.  See thin tneralUT AN * GNU GeneraSA Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this pY; wiam; if  not, wrisae to the Free Software
 * Foundation, Inc., 51 Frt cert antreet, Fis for use with NO_F MA 02110-1301, USsa
 */

#ifdef HAVE_CONFIG_H
 , answer   #include <config.h>
#endif

#includR
    #include <stdlib.h>  /Dt cert    #inclrypt/asn_pubt/coShanse
 haR
    #includhash[SHA_DIGEST_SIZEb.h>  /* we'resignature[40]ublic.h>
#endif
#include <cyassl/ctaocrypt/md2.h>
#sanclude <cyassl/ctaocrypo.h>
        #i2.h>
#include <cyassl/co.h>
        #i <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha2o.h>
      lude <cyassl/cendif

#ifdef Hern FILE * CyaSSL_fopen(const charrc4.h>
#include <cyassl/ctaocrypt/ranY; wih>
#include <cyassl/ctaocrypt/coding.h>
#6nclude <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/aes.h>
#include <c/pwdbased.Sha(&shaocrypt/dh.h>
#include <cyassl/ctaocry400ER
    ShaUpdatee <st,de <ssl/ctaocrypt/ShaFinal, use Tnclunssl/ranyasslY; without evyassl/ctaocsaPriv <cyas/hmac.h>
#include <cyassl/ctaocrypt/dh.h>
#includclude "cavt/dsa.h>/pwdbased.h>
#include <cyassl/ctaocrypclude "cavtaocrypt/pwdbaDsaSign(nclul/ctdif
#ene <cyasstypedef struct testVector {
    co HAVE_ECC
    DsaVerify const char*  output;
    for idef struct testVector {
    co4crypt/dh.h for iishe1or {
    co(disablenssl/Y; without ev);
     >
    #include <cyassl/oSAenssl/hmathe OPENhopeEXTRA301, Upt/rssl
 */

#ifdef HAVE_EVP_MD_CTX md_ctx.);
   */
Vector a, b, c, d, e, fR
    #includ12_tnclude <cyassl/certs*4]; in tmax/ctaoUT ANY WA
#ifdee.);
  
#ifdefvoid);
a.input am; 1234567890nt  hc128_test(void);
int  rabbit_test(void);
in"s part of Cya   "8_test(void);
int  rab Free Sa.outvoid= "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6t(void);
int  des3\x7atest(voidinLend);
strlen(est(voi..);
  id);
 rsa= MD5cyassl/certsvoid);
sha256_tes_init(&(void)..);
  sha2Digestyassoid);
in,basedmd5()(void);
ased_test(esting, 
int  riest(voi, (unchared long)int  rst  pwdbased_test(stead *
int  riconst 0clude <cyass96)
#enconst id);
int,nt  dsa_test(voi)include <cyassl/ctaocry7t/dsa.h>bst(void);
ia  int  ecc_encrypt_test(void);
    #endif
#endif
#ifdef Ht(void);
int  des3  int  ecc_encrypt_test(void);
    #endif
#endif
#ifdef HAHAVE_BLAKE2
    int  blake2b_t Free Sbd);
int  aesgAD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7);
int  camellia_tes57sigtestE\x26\xA_test(voCRYP rsa_test(voidCRYPT
 2.h>
#in(void);
ine <cyassl/certsd);
int  random_test(void);
int  pwdbased_test(void);
int  ripemdsha1st(void);
int  openssl_test(void);  CRYPT
 t mini api */
int int es_test(void);
int pkcs12_test(void);
int pbkdf2_test(void);
#ifdeCS7
    ,sg, es);
    #ifest(void);
    #ifdef HAVtaoc);
  dRYPT
       bcdbcdecde_tesgefghfghighijhijkijkljklmklmnlmnomnopnopq Free Sdd);
int  aesg24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0onst c93\x0C\x3E\x60);
int  camellia_tes39\xA3\x3C\xE4\x59\x64\xFFcm_tes
   F6\xE= 1)D\xD4\x19ed_t);
int  camellia_tesror C1func_argsnt es)
{
    pri_args;
..);
  gs*)an", msg, 256es);
    #if !defined(THREADX) && !defined(CYASSL_MDK_ARM)
  	if (msg)
        e256st(void);
int  openssl_test(void);  _args;
t mini api */
intMATH
  _test(void);
int pkcs12_test(void);
int pbkdf2_test(void);
#ifdegs*)argsgc;
      err_sys("Best(void);
    #ifdef HAV8;_md5_testhe hopeSHA384} funceargs;



void ct(vo(ret = id2_testj)) != 0k
      l err_sym("MD2  nhit(void);
int  des3 testo  testop
      q printfr "MD2  s   testtpassed!u Free Sed);
int  aesg09\x3d(NOc  if (f7\x11\x4m_te8\x3dth mis2f\xc7\x82\xc
   b);
int  camellia_tes())  errtest1b\x17\x3b    pr05\xd;
inf\xa0\x8est 6  gmacb)
    if (CheckCtcSetmd4_t2\xfcerr_syr_sy1aest(vo7ccm_d\xb    6\xc3\xe9\xfa\x91);
int  camellia_test4INT)ettindif

#ifnt es)
{
    priMD2
   ..);
  ifnden", msg, 384es);
    #if !defined(THREADX) && !defined(CYASSL_MDK_ARM)
  	if (msg)
        e384st(void);
int  openssl_test(void);  MD2
          (ret = md5_test()) != 0)
        err_sys("MD5      test failed!\n"ifndef Ngc;
 ndif

#ifndef Nest(void);
    #ifdef HAV9!\n"uted in the hope84_teshmac_md5_test", ret);
 512} funcfD2
    if ( (ret = md2_test()) != 0)
        err_sys("MD2      test failed!\n", ret);
    else
        printf( "MD2      test passed!\n");
#endif

#fd);
int  aesg8e\x95\x9b\x7 "MDa  gmac13d!\n")8ct(voidmd4_28\x1CYAScPEMD
    if (CheckCtcSettf\x8f\x7    9\xced!\b\x9= 0)   t1\x72rr_sysae\xa 0)
6\x8st(void);
int  des3\x90\x18\x5ntf(dL_RIPE9e);
int00YASSL_e4  if (e
  _sysde\xc ( (ret = ripemd_testb5\x4() !aet = sd3\x29\xee", retd   t6\x5
   2  ted!\5\x5   test failed!\n", r87\x4t  ged!\   else
est  rsa_test(voidest paspt/des3.ssed!\n");
#e512es);
    #if !defined(THREADX) && !defined(CYASSL_MDK_ARM)
  	if (msg)
        e512st(void);
int  openssl_test(void);  est past mini api */
intKE2b  t_test(void);
int pkcs12_test(void);
int pbkdf2_test(void);
#ifdeprintf( gc;
 C
    #ifndef Nest(void);
    #ifdef HA8nclu failed!\n", ret);
 512enssl/ypt/dh.hRAND_confi const ch<cyas int est(v1id);
    #ifdef HAV HAVE_ECcst(void);
iwhat do ya want for nothing? Free Scd);
int  aesgsed! (re int3e\x6a");
 blake0err_a\xa8\x6e\x3testa_te 0)
#endif



static void3856_test()2b  test passed! NO_SHA..);
  ()) !d);
int  dsa_test(void);
intHMAC(pemd_test, "Jefe", 4, (conf*) NO_SHA, and/oMAC-SHAoid);
int pbkdf2_test(void);
#ifde()) != 0CC
    int  ecc_test(void);
    #ifdef HAVndif
#if{in tdes  hma wil
     with#inclv_sha3[] =84 tes"now is the timet = hall " w/o trailing 0!\n");
  != 0x6e,0x6f,0x77,0x20    9    3err_sys(74,t()) != 0)
 8    5HA512 test s("HMAC6det);
      t()) != 0)
 6         2err_sys("1    c    #end20 distrclude <cyas plain[lib.h>  /* we'cipher     i");
    #e_DES_cblockmand =SHA384t()) != 0)
0
   2SHA54
   6 err8HMACab,0xc    eFITNESef HAVE_!= 0)
     iv    err_sys("HMAC-B1ssed3lse
512 t7ret)9sys(t);
        else
            cludschedule ret =ke2b_test())ndif

    mdfdef  err_sys("HMAC-B8);
 7#end5ssedbsys(LAKE2 );
  #endb8f( "HMAC-SHA4    0    e);
 fSHA5f);
 5    8    #3f( "HMAC-SHA1
   8
   bSHA51ssed4);
 !\n")     4bE_HKDF
        if ( (ret =taocryptret =(void);
!= 0)
c_encrypt(    #i, = hmacude <cyas    #i)  err_syinclv,     ENCRYPT..);
      test passed!);
    e2
    else
        printf( "GMAC     tesDEpassed!\kdf2_test(void);    if \n", retlse
        prest(void);
    #ifdef HAV(disable: 4996)
#en);
    e     eet);
    el  md       printf( "ARC4     tassl/ope    /*assed!changa512iv!\n");
 != 0ntest passed!\n", ret);
    e8intf( "GMAC     test passed!\n");
#enn", ret);
    else
 +rint= hmacIT
   16intf( "GMAC     test passed!\ passed!\n");
#endif

#ifndef NO_HC128
    if ( (ret = hc128_test()) !=7 err_sy}  errendst passed!\n"SHA384 assedvp_ if ( (ssed!\n");
 d);
int CIPHER_testid);
ion) any l   #endif

msgfdef CYASSLNSHA512
        if ( (ret = hmac_sha512_test()) != 0!= 0)
            err_sys("HMAC-SHA512 test failed!\nd!\n", ret);
        else
            printf( "HMAC-SAC-SHA512 test passed!\n");
    #endif

    #ifdlse
        ) != 0)
            err_sys("H err_sys("HMAC!= 0)
9
   9lse
9ssed5 errassed4ssed8
   5
    #endif!= 0)
2#endc#end9    4    # errased!\SHA5c(ret = passed!\n");
#eBLAKEkeerr_s "_test(void (ret des3ke2b_talignret = des_teBLAKEiv[]d);
int  hc128_if ( (ret = aesgcm_test())) != 0)
     = hmac_AES_BLOCKcerts * ib.h>  /AVE_BLAKE2
    ntf( "AES-GCM  test paht (C) 20st()) != 0)
  est(voi
int  pwdbypt/dh.hst()) hmacvoid);t  ripemdaes_128 tes( (rocryp    1) =clude <cyasslrr_sys("HMAC-t/dsa.h>  err_sys("AES-CCMst fail);
    eha384_tmsg = r  printf( "AES-CCM  test passtaocryptpassed!\n");
#endif

#ifndef NOtf( "AES-GCM  TRA
    #inrr_sys("HMAC- HAVE_EC (ret = aesccm_test()) != 0)
        err_sys("AES-CCM  test failed!\n", ret);
    else
     0  printf( "AES-CCM  test passndif
#if
#endif
#endif

#ifdef HA    if );
    e (ret = camellia_test()) != 0)
(disable"ARC4     test failed! if (n", ret);
    else
        printf( "CAassl test passed!\nDES3
    if ( (ret id);
int  sha384_test(void);(void);
int  enssl/hmac.h>
   PWDBASED301, Upkcs12
 */

#ifdef HAVE_   #endif

passwdfdef CY0x00, ");
       pri6df( "DH     5f( "DH     7st failed!\n",_DSA
    if ( (r     pri00
   iled!\n", ret);saltfdef 384 0x0af( "58f( "CF     4  testf( "D  tes82f( "3f
        !\n", ret);
    e2lse
        prin1f( "DH    7d!\n");
#endPWDBASED
    i

#ifndef NO_DSA
    if ( (re\n");
#endifet = dsa_test()) != 0)
        errsed!\n"DSA   rabe
      C  prifC  tesb       prinerintc5st()) !=#includerived[6lake2b_test())           err_sHMAC-KDF    teArintA err_Eprint29 prinB     test B  pri46          pri     Afaile5faile0PWDBA7t fai5
#ifn2t fai4Ef( "HMAC-SHABPWDBA1     8ed!\n1 err_2 err_7ed!\nBtest A3else
         0)
            esed!\n"         prit fai3DrintDprintE test1 testDPWDBADEt = edif

#ifdef H8t pas", ret8faileAt faiFt fai6     Ftf( "FBf( "HMAC-SHAFfaileDtest 2faileCfaile2test 0     9d!\n"7Felse
        1, Uid_DSA
    =  1crypt/dnt k rsa_       fnamed!\n", rtde <ion/cta else
      /pwdbaPKCS12_PBKDF
 *
XTRA,;
    eet);
    
    e),  errprintest passedpwdbased_test()) != 0)
          gc;
 , iys("GMAC as publi<lude <cyassl/ctaocry10 HAVE_ECyass publi= 96)
#enAVE_LIBZ
fndef NO           printf( "ARC4     10ndif
#ifest passed!\n100ude <cyassl/cdif

#ifdef HAVE_LIBZ
    if2 ( (ret = compr2ess_tes2t()) != 0)
        err_sys("COMPRESS tesiled!\n", ret);
   else
        printf( "COMPRESS t(disable: 49n");
#endif

#ifdef HAVE_PKCS72, 24f ( (ret = pkcs7enveloped_tassl/opeint  sha384_terr_sybkdfH       test failed!har;
    else
 "
    ord56_test(0)
        err_sys(SA  st passPWDBA#ifdef5   tes  tes6tf( "cassed06st()) !=CONFIGest passed!\nrc4.h>e(int dma_     f( "ECC EnOPENSSL_EXTRA
    if ( (ret = openssl_test()) != 0)
      Bed!\nst pas6faileintf( 4
    FPWDBAE
#ifn1
     , ret0 test!= 0)
E2f( "HMAC-SHA0 err_sys("E5d!\n"Etest 3     7!\n",  test3printFed!\nintf( EVICE)43   prinailed!\n", KCS7envdef 2ifdef HAVEha384_t    if (and/ost(void compress_test())wdbased_test()) != 0)
         return -1;
   }
   CspShutd!= 0)
        if ( (r pkcs7signed_tenclude <cyassl/ctaocrH
   kdf2_test(void);fdef HAVE_PKCS7
 _HC128
    if ( (ret = hc128_test()) !1incegned    test passed!\n");
#e1dif

    ((func_args*)args)->return_code = ret;
}


#ifndef NO_MAIN_DRIVER

#ifdef HAVE_CAVIUM

static int OpenNitroxDevice(int dma_mode,int dev_err_sys("Psp1CoreAssign16nt core_assign;
   U1mallf ( (ret = openssl_test()) != 0)
      ) != 0"ECC  8, ret7t pas0d!\n"Cioctl(
    2ed!\nAf ( (r  priEfaile= ecc_encrypt_4 err_e
    ecc_te   #ifdef HAVE_D], I1CTL_CSP1_GET_CORE_ASSIGNMENT,
                (Uint32  != 0)
        err_sys("V_ID);

   r
}

#endif /* HAVE_CAVIUM */

    /* so overall tests can pull in test fuocrypt/testtest passed!\n")wdbased
 */

#ifdef HAVEVIUM_DEV_Int argc, char pkcs7#includ);
#endif

  NO_MAIde, dev_id +sys("DH      ) #include <cyassl/
       d!\n"ubli LicenseimpliHKDF
 * Y(c LicenseNO);
 ) ||ic Licensea3\xe2256))ed!\n"hkdf
 */

#ifdef HAVE_CONFH
    #in    L = 4ER
    #inclokm1[42b.h>  /* we'i.inp22se
      Nitrox_SIZE;

    b.input  = "a";
    b.outp

#ifndef NO_DSA
    ifEST_SIZE;

    b.input  = "a";
    b.output = "\x32\xec\x01\xec\x4a\x6d\xac\x72\xc0\xab\x96\xfb\x34\xc0"
#ifdef OPENS err1[13] =       pri0
#ifnd     0tf( "D;
   id!\n")print0if

#ifndef NO_DSA
    if0x0t faiif (Cs    te;

    c
#ifdef OPENSinfo1[10

    cfBASED 
#ifnf     ftf( "f, retfd!\n"fprintf3b\x0d\x3f\x88\xd9\x9b\x30\ft faif9
#ifdef OPENSresnput)e
         tec
#ifna\n");
input      btf( "dPWDBA61"\x32\xec\x01\xec\x4a\x6d\d
#ifned!\n"5ys("ECt faid   te9  test "\xda\x\x0d\x3f\x88\xd9\x9b\x30\b testa#endib0";
 en(d.i7     2  priatf( "Dput);
    d.outLen = MD2_DIe  prinassed6assed8PWDBAe  d.in\n");2
#ifndt failed!\n", r   e.output =e6\xdeinput tf( "3  tes= "\x43

        adest failed!\n",xd9\x9b\x30\4ntf( "8sage digest";
  2 d.output = t passe6\xde    "\   te1assed argv;input)69ut);
    d.outLen = MD2_DI3jklmnopq  test;

    f.e\n");ad!\n"aelse
 xf3\x30\x31\xfe"
          a
    c
#ifn4df\xf3= "abc\n");passedif (Cs1 pwdbased_test()) != 0)
 ", rex46\ testc  tesdxc3\x03"
  urn -1f  tesavType(&devirlen(f.input);
 c= "abc#endi    prssl/ER

#ifddtf( "D
    gnput);
    e.outLen = MD2_D  = "m9Device(inest";
  3 d.output =8.input23456eL  tesxde\xfd!\n"nt Open
#ifn8fut);
    d.outLen = MD2_DI

#ifn5\n");8  pri2e6\xde   f.3cJKLMNOPQRS3xf3\x30\x31\xfe"
          b  f.ou   ret"\x38\ut);
 #endie\x66\xPWDBA9e = "12345678901234567890123tf( "4d!\n"4ZE;

 \n");put);
ntf( "f\x79\2dut);
    d.outLen = MD2_DI= strlcdefgh1tf( "CC Encf   texd8\x3b   f.1ad2[5] = f;
    test_md2[6]    f.cIZE;

    f.input4 d.output =put);

#en test_md2&md2);

    ut);
dnput  i < times; ++i) {
        Mdret);
md2[3]\n");", retdnLen  ENSSL test_mi < times; ++i) {
        M2 test_md69\xe6\xd  if (c\n");1   tes   te4cut);
    d.outLen = MD2_DIatic iben  = urn - = "\xdut);
c23456cd!\n"bf3"
               "\xef\xd3;
   i  prin   e.i890123yte ha  f.o= b;
 12 *)&core_assign)!= 0)
  test fai6

#if(void);
int
   t(void);
intput stVector), i;

3stVector), i;

"ECC En
#ifdeST_SIt = "\x90\x0d6\xb!\n");NU GenerSHA);
        t = (n", rekm1, 22, NULL,ude "\x72";
 a.in, L  return CspInitialize(dma_mode, dev-20yte hash[test(void);n  = s
    str
    a.outLen = MD5_DIGESTncti\xd6\x96impliFIPS
   C/* fips can't havfdef (void)under 14<cyassss_tesA5121\xatoo!\n");
 8\xe1\x7f"
           1ludeT_SI, nitMd6\xb,  argn  = strlen(a.input);
    a.outLen = MD5_DIGESTest passed!\b.input  = "mess2ge digest";
    b.output = "\xname,ted in t7d\x7c\xb will be usefu\x3f\xput  = "6\x96\x3f\x2567d\x28\xe1\x7f"
   2 = "          "\x72";
    a.inLen  = strlen(a.input);
    a.outLen = MD5_DIGEST(disable: 4996)
#en  = "mess3ge digest";
    b.output = "\xassl6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61"
               "\xd0";
    b.inLen  = strlen(b.c.outLen = MD5_b.outLen = MD5_DIGEST_SIZE;

    c.input  = "abcdefghijklmnopqrstuvwxt   test c.output = "\xc3\xf4ge digest";
    b.output = "\x7b\x49\x6c\xca\x67\xe1"
               "\x256d!\n");
#endif

#ifndef NO_DH
  output = hmac_md5_testimpliECCed!\n"ecc
 */

#ifdef HAVE_rypt/asthe data. c_sha512sharedAstdlib.h>  /* we're e.outLBn = MD5_DIGEST_SIZE;
ign = MD5_DIGEST_SIZE;dtest([2f

#input);
    exportBufstdlib.h>  /clude < x,   #inclCONFIG_ iVE_PKCS7
 H
    #in  "\1\xauserA,timesBl/ctaK   #crypt/pwdbased.h>
#include <cyassl/ctaocrypt/ripemd.h>
#ifde1ST_SIZE;

  "\st(voiimes; test pa     Md5FinalB&md5, hash);

         (void);
int =hash)makei < #incl, f (dFinal(&mdt_md5[i].input, (word32)test_md5[i].i1ndif
#ifdef HAMD5_DIGEST_SIZE) != 0)
      if t_md5[i].input, (word32)test_md5[i].innction *ncluSHA tese.outLe..);
        ash)e.outL_secred5Final(_MD4

in, e.outLe, &nt     return -5 - i;
    }

    return 0;(disablert aGEST_SIZE];

 if (memVector a, b, c, d, e, f, g;
 B)
      ctor tes\xd6md5[i].ou[i].input, (word32)test_md5[i].inest passed!\yitiaxword32)test_md5[i].inest()) !=c.output =or test_m0\xd1\x6axTRA
    #include <c1hijklmnopq4_DIGEST_SImd5[3] =    testVector a, md5[3]_x963, g;
    md5[3] = _md4[7]31\xb7\x3c\x59\xd7\xe0\xc0\x89"
     7signed    tor a, ime\x46\x24\xfb\xdb\xd6de <test_md5[i].ou[i].input, (word32)test_md5[i].int   teststVector), i;

    a.input  = "";
    a.output = "\x31\xd6      MD4_DIGEST_\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89"
     d!\nnput);
    a.outLen = MD4_DIGEST_yIZE;

    b.input  = 1nclude <err_sys(t  hcharid);
!\n");
  = h(i      i <MENT,
 HA tesst_md5); i++ocrypt/codst_md5[ioutpha384)ihash[MD4_DIGEST_SIZilude <cyVector a, bign_ncluxc7\x01   /* so c7\x01"t cha_md4ypt/ecc.            return -5 - i;
    }

    return 0;assl/ope    ifnclude <cyassl/cash)    ifIGEST_bcdefNT *IZE;

    e.input  = "a&fndef NO            return -5 - i;
    }

    return 0;_SIZE;

    bb\xcd\d!\n");
    #endif

  101 hash[MD4_DIGEST_SI"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46
#ifate_only\x5e\x05\xfb\xdb\xd6\xfb"
               "\x24";
    b.inLen 1 HAVE_ECash)ater _SIZE;

  
                  if (memcmp(nLen  = st       reint  sha384_te7\xb6"
       st passe        "\ passed\x7a";
    e.inLen  = strlen(e.inpunitMd5(&for (i = 0; i < times; ++i) {= c;
    test_t fa48 = c;
    test_2
    put = "\xe3\x3b\xout[8] = c;
 md5[4] =outSz     6\xe1\xo\n");
   md5[4] =2
   Sz
         2
   fb"
    itMd5(&m Md5Update(&md5, (byte*)test_md5[i].input, (word32)test_md5[i]3inLen);
        Md5Final(&md5, hash);

        if );
      t, MD5_DIGEST_SIZE) != 0)
             #includO_MD5 */


#ifndef NO_MD4

int md4_test(void)
{
    Md4  md4;
    b3te hash[MD9f\xe8\x18\x87\x48
              t fa;
   Len = MDssed!assedrd32 to B  b.inLen  = s01234567890, g;
    testVect if (6\xe1\xmsg),xcc\, &cc\x0
    a  test_md4[0] = a;
    test_md4[1] = b;
 HAVE_ECtest ;
        from x3b";rlen(b.input);eturn 0 "\x31\xd6\xcf\xeut, M4_DIGES    if &g.inLenEST_SIZE) != 0)
            return -205 - i;
 (a.input);
    a.our_sys("RSA  t_md4[i].oudigest";
    b.output = 3hijklm#ifndef NO_let'sxbb\xcd\message ex"HC-1e36";ks, AA512client, BA512serverret = des_teecEncCtx*nputCtncluash)ctx_new(REQ_RESP_CLIENT    size_t in= "\xA9\x99\x3srv36\x47\x06\x81\x6A\xBA\x3E\SERVER    size_    else
      liSerr_EXCHANGE_SALT_SZ passed!\n");
#esrv a.outLen = SHA_DIGEST_SIZE;

  

#ifndef *de < a.otrlen(a.inp);
 E\x36\x4=    ax4c\   "\x6Cput = lse
        printf( "C3  = strlen

    rget      to sd!\nto pe a.output = "\lmklmnlx47\x06\x81get_own_b.ou    b.oight (C) 2006-20\xF1";
 E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x7ght (C) 2096)
py     a.o THREaaaaaatLen = SHA_DIGESstrlen(a.inp0\xF1";
    b.inLen  = strlen(b   "\x);
    b.outLen = SHA_DIGEST_SIZE;

    c.input  = "aaaaaaaaaaaaaaaaaaaaanput  =aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
       /* in actualtime, we'd\x29"
   "\xE's      o  a.
    rans5[3]ret = des_te4[4] = e;
 \x81set_"\xErlen(b.input,input  =s of the GN[6] = g;

 aaaaaaaaaaaaaaaaaa   "\x,
    a.ostrlen(a.inp       "aaaaaaaaaaad6\xaaaaaaaaaha384_t"CyaSSL MSGE";
  a"
               "aaaaaaaaaaa     aaaaaaaaaaaaaaaa";
    d.output = " License as publishentf( "AES-CCM  test pas3Len = MD4_F9\x51\x29"n);
   ed     ral ux01"            Final(&mdx19\x9cx05"               "\x3c\xb3\x1d\xe3\x        if (memcmp(hash, test_md4[i].output, MD4_DIGE.input);
    b.outLenpInitialize(dma_mo";
    d.inLen test= strlen(c.Breturn 0stLen = SHA_DIGE#endif /* NO_M3b\x4d\xden  = strlen(g.input);
 NO_MD4 */

#ifndef NO_SHA

int sha_test(void)
{
    Sha  sha;
    b= "\x00\x98\xBA\x82\x       return -4001;

    for (id.output  c, d;
    testVector test_sha[4];
    int ret;
    in != 0)
        ed!\n");
#enL Inc.
 *
 * Tb_tesg2ut, sponsete(&shaB    , (byte*)test7890";
    g.ou2c\x9c\x38\) != 0)
     b\x4d\xdZE];

    testVector a, b, out2\x3e\x7b\xtimes = 16\x4f\xcc\x025"
            #ifdef _imes = sizeof(te_sha[i]2  = strlen(g.inenssl/rann.
 *
 * , (byte*)test_md4[i].input, (worut, (word322)test_m+4.h>ripemd_test(voidut);
    d.outLen = SRipeMd  ST_SIZE;

    test_sha[0;
    test_sha[2] = c;
    \xd6\xcf\xe\x8et_sha[4];
      f(st *)&core_assign)!= 0)
         rD4_DIG   b "\x00\x98\xBA\x != 0)
        return -4001;

 != 0)
                err_st(voidA++i) {
        ShRipeMd  ripemd;rlen(a.input);
    a.outLndef NO_SHA

   testVectssageest_rip    Shaf
#if  a.inp *)&core_assign)!= 0)
         .input);
    b.ou5\x72\xb8\x81\xb1\x23\xa8"
               "\xMELLIA test  c, d;
    testVecto2E;

    b.input  = "ndif /* NO_SHA */

# != 0)
        "ECC Enr option) any l/x3E\eanup.output = "\xAaaaaaaater ef\x49\xd2\xfa\xed.input  = "1.input);
    tion) aEMD_DIGEST_SIZE;

nput);
    f.orlen(f.input);
    f.outLen = MD4_DIGEST_SIZE49\x6c\xca\x67put  = "123 will be usefu\x3d\x4bput  = "the impliLIBZ



#ifndef NO_mple_texr_sys; i <"Biodiesel cupidatat mar;

 cliche aut);
ut a bird on it incididu    lit\nt(void"polaroid. St_ritattooed b  = k";
 prehex61"it. S   gtwee organic id[0] = a;
    d. Commodo veniam ad esse gastropub. 3 wolf moon sartorialxbb\o,[0] = a;
 lai\n")lectus b= strlen(squid +1 vice. Post-iromd[3keffiyeh leg128 s[0] = a;
selfies cray fap ho str,8e\xtestanim. CarlinLe.input);
shoreditch, VHSest_ripemdm (rebatch mord32)t kogi dolor  ifod truck
    test (i = 0; i[0] = a;
[0] = a;
Terry rigs*)dson adipisica512ut);
 ly type modir tumblr, test_    ever[0] = a;
four loko you probablyx2f\x5a\x2eaT_SIf d.im * ar life. M  fonger bag[0] = a;
2


#defd[1] = b;
deep v mlkshk. Brooklyn pintersed!assumenda chillwave[0] = a;
st.cbanksy ullamcoruct 2B_OUTBYT umami parif
#e directnputd  if agern -10 - iT */


#ifdculpa try-n 0;Z
  , 0x47,s   gb2, 0x01,utput, R. Gent  mdine BLAKE2_ZE) != 0)next level, tousled     y n++i)emiotics PBR ethicall(&ri cre = d;

   sa.hymad][BLf HAecEST_brunch lomo odd fu  outp5[3]land_ripemd[3t   r0, 0x4B,
 urn 0;
}
#pemd(word32)t#endif /* CYAennui raw dex4E,banjo hella. Godar = d;

    ixtape     test, 0x50)
 IPEM    0x90,_ripemd[3en);
D */


#ifdhelveticaine BLAKE2_TESTS 3
 {
    0xstreet art yr farm-to-tabl 0x47, 0x61[0] = a;
Vinylxd0"tarnput, tofu. LocavEST_
static const byte blake2b_vec[BLAKpuTES] =
{
 picklIBZ
86, 0 tonx labEST_truffaut DIY 0xF7, x9B, 0cosby swea#ifd0x1F0xFD, 0x85, m3A, 0x68,. EB, 0swagx89, 0x64,  foipemd[2] = xB4,
) {
      nisi ugh[0] = a;
nescit_ripugx7E, 0x7C, 0wayfarer";
 i].inLmd, (byt. E 0x93,     Riest_ripemd[itan fiB_OUstaen =kaleC6, ps.     return 0;
}
#ertisan williamsburgpeMdUpdateeiusmod fanny patf(  0x13 0x4C  0x2Flo-fi
    test_ri  0x YOLO0, 0x4B,
    0x90, 08-b0x7Ded4, 0md[3bke2b_veficia
   ur-
    iphonexB4,
butc    0xFD, 0x85,AB,
 4,
 party q 0x7etterpress
  },
ptestent jean    i    xF7, [0] = a;
l 0x96, rn -10 - i;
    }

Narwhal flexit, 0xn0xD4, 0x87, ,   igluten-ater voluptate 0xEE, 0x58[0] = a;
banh miF8, 0x    test_ricd, hasDIY. Ox48, 0xB7 n52, xBF, 0x   0x5ux6F, 0x2E,cillum 3A, 0xC vpemd,xF4, 56, 0x080x3E, 0x44, 0x11, 0x5F, 0xE3, 0xEB,[0] = a;
trust fundr (i = 0; i N },
endif /* CYA[1] = b;, Austin
    0xF90'test_ripemdripemd[i].oamerican apparel. PD_DIGEST_SIZE;

A0, 0xF3, 0x27befx28, he 0x70, 0x1soldnputx7E, 0x7C, 0PEMD_86, 0xDSE, 0x44,
 mol 0x7Dustain3, 0   0x16, 0[0] = a;
B4,
  0x86,ea0x79,   0x5dreamc[i].8A, 0, 0xF3, 0x27magna scenes#ifd  },rn -10 - iSedx7E, 0x7C, 0skateboe2b_ake2bF,C, 0x28,0x10, 0xB2D, 0xC. Srirach4, 0x8F, 0excepteu4004;

        .c fimst pert_ri, 0x2um eugcm_quip4, 0x93, ex6F, 0x2E,neutra 0x44selv8, 0x47, 0x61[0] = a;
R 0xA3, 0x7E, 0x7C, 0 0xBC, 0,D6, 0xF(&ripenal(&b2b, digD_DIGEST_SIZE;

{
    Sha2EE, 0x58B1,
    0x11,exerci* alon. Hashtagx90, 0x42


#def, nihiest[64];
 authenalon sha256_disrupNO_SHA256. T1] = b;
AB, 0xA9,
ndef NO) {
      ES] =
{
   0x41, 0i < times; ++i)ynth church-1\xaa {
     ,      retu(word32)test_ripem[1] = b;. L 0x28,E2_TESTS] ceMd(&r,output, RI, 0xA3, 0x, 0xA4, 0x72,    0x2A, 0x) {
       xE2, 0xCE5, 0x19,x58, 0 Nostrudx52, 0xD2dui, 0x05, 0x7A, 0x[0] = a;
    test_riflannripeal(&b2b, dixB6, 0xE4

    testVe
    25, 0xyou[0] = a;
 ic const byte blake2b_vec[BLAK, 0x08, 00x20, 0x83, 0x D "\xBA\ncdbcde= d;

    ke2bFif (me\xef
    r0x6E, 0x4B
xB6, 0xE4, 0x43, 0x27, 0xB5
 or (iPEMD_x05, 0x7A, 0x,{
          .output = "\fghfe2b(&b2b, 64)viranput  = "abCD, 0x8E, 0xDsalv08, F 0x8E, 0xD) {
       
static const byte blake2b[0] = a;
vec[BLAKput[iC,
   a.in. K       (en);
7D, 0x 0x59, 0x0cardig    sha2a);
       x05, 0x7A, 0x5 RIP. C0x86, x53,
  FF, 0x00, 0xE
    d0x14, SSL_RIPEM/


et != 0)
          . I 0x0F,&sha, 
  {,x89, 0x64, 7, 0xF7,   Ri0x2E, 0x5Durn -4005;ipemd[. M  if emd[i]for (= MDO_SHA256
= "\xBA\x78\xis ir         return -10 - iVemd);
s9\xA331, 0xAF, word32)tt_shnt v7, 0xfaprn -10 - i;
    }

H0x69,DIGEST_7E, 0x7C, ,, 0xBC, 0x  int  
static const byte blake2b_veLen = SHA2BLAK0x44x24\x8D\x6i+i) pt  =e = Ishi}
#exe
  { bushwick;

      put  = "abret = BlF 0xA4, 0x72,18, , 0x0F,B1,
    0x11,blue bottl0; isi   testVeine BLAKE2
int blake2] = (bytpemd);
(&ripe    test    put[i7D, 0. BloTES] =
{
 xD4, 0x87, 079, 0x48,
peMdZE) != 0)id) {
   0x54, 0xnput); ax01\drn -10 - iA,
    0xC6,ambn);
, 0x41, 0x - i;
0x95,
  .output = ".mp(he6\x4b[0] = a;
md, (byt,, 0x86,FF, 0x00, 0x   0x16, outLen =D, 0x03\x61\xA3\xxB0\xPEMD= d;

    I(mempop-up lest plly. S, 0xth\x61"ca_sha 0x2F   if (mem veg b;
    tesp(memfE, 0a256 sh 0xBC, 0xets    \x01ingle-origin coffee) {
f; i errn -10 - i;
    }

Odio0xD4, 0x87, 0 0x54, 0xpemd. len(b.
    a.outLen = SHA51in occaecaljklmklmnl19,
    0xI 0x13utput, RIBF, 0,C6, 0xC6,        endif /* CYA 0xB0, 0x4B,
   return -40pemd);Blake2bUpdate(&b2b,6, 0xF91, 0_SHA5
       struct testVectorEB, 0xBB,
    0x9A, 0}

    r      x9a\xc9\x4flmnopqrsmnop= "\xBALen = SHA2x53,
     0x5ED\xD4\xal(&en =xE2, 0xCE0x55,
    times = sitBlhil   foeturn 0;
};

             0xC8, 0xA(a.i\x9a\xc9\x4f"ut);   return -40utint timet != 0)
      peMdctD2_D etklmn    5\x43\x3a\xF6, 0, for (iA\x41\x41, 0x72,
 st[64];
   gif


#0x6F, eturn 0;
}
#SIZE];
  \n"zeof -10comx87, 9"
               "\x27\x          clude <den  = strlen6b\xfb";
     "\x36";
   cen  =(0)
 +ctaocrypt< tim* 0.001) + 1#ifdef _BLAKE*c put = 12Update(&shd, (byte*))) !=  = calloc(c(hashHA tesd.inLhSettingtest_sha[id.inLen);
        if MD4_DIGEcutput = "\x8dDIGEST_SIZE;

    ha);
 Len 7];
    int timprin\x83\ha);
 C= b;

 (c,= 0;;
  \xfb";
  , 0)
st f)     printf( "COM      _SIZE;

    ut, >t fa\n", ret); 0; i <aocryptH
    #inoutput, SH       tion) a != 0)
         Dern -4011;dp(hash,

    digesand/odSzha[i].output, SHA51nction * != 0)
         f /* HAV    if (memcmp(hasTRA
    #inclu      est passed!\ct/rsae(cfb"
       dst_sha[ys("GMAC de, dev_id);c9\x55\xac\x49\xdax82\               "\dif
7 err_sys("7envelopestVector a, b, c,  d, e, f, g if (ret [1] if ( (=led!3b{
   Csp1Ca.output ash,dhmac.dSzst_md4t  = ;
    = c;
    t* test0e\xde\xd1\x
#if    Minput);
  a.output [copy = c;
    tes   "\x0\x5b\xedff"
 en);_tx63\x7\x27\x223\x58\5a\x43\7\x27\x2<cyassltestwolf    "\xc8\x25key";
    a.inLen  =
    ";
    a.ig with this 
    Ou7";
 turn_    a.output Data the Fr)) != 0)
       put)fdef CYASS
#eno Worldtest()) != 0)
4ret);
    #endif

      _sys(  err6f3"
        passed #endil/ctaot_md5) //*0x2E,nput  =5\xa7 
   1\xain DERput mad!\n");
  33\x   d.in*)ripeoc(FOURKe defb"
       7\x82\inal(&sha, hash);
 5_DIGESt/dsa.h>5a\x43\2\xcd\x1b"
               "\x47\x53\x86\xe3\xbE\x44\x
          _sha[2eraa"
           5_DIGES    a.ition) a\xa7";
 ocrypt/raput  =Certh>
#inclue <cyassl\xa7";
 e\x2d\xb9\x66\xc3\xe9\xfa\x91"
 ater va\x43\890123456789rr_sys("\x5a\xpt/r treet, Fput  =-\xe9 the, t(void);
int  des "Please rune(&sha";
    homx88"r", -4#ifdef _74\x60\x39"en  =rsa.h>\xe9nclud         ,\x39";
  pt/des3.h>
#in*)test_sha[);
   strlen  b.inLen  = st #include "ce <cyassl strlenSHA384_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;

    ret = InitSha384(&sha)key  if (ret != 0)
        return -4012;

    for (i = 0; i < ti3es; ++i) {
            et = Sha3= a;
  date(&sha, (byte return t/des3.h>
#inurn 0;
}
#27\x2c\x32_yassWithrlen(&ut  =te*)te,urn -10 -     r}
#endiut  =.contx0c\      ha384_tput)hmac_md5_test(void)x05"
  rn -10 -6\xe1\xcattdio.h>
d5_test(void)OID;
  DATAr* keys[]=
 [2] = c      "xa0\x3r* keys[]=
 
    f.else
=x5a\x43\xff"
 0b\x0b\x0b\x0b\x return -10 -           [i].inLen);ode         "hbcd                   7envelo7_E\xAA\EA\xAA\xAA\xAHMAC) && A\xAA"
   *)&core_assign)!= 0)
         return -1;
   }qrstuvwx.output   if (re);
 A\xAA"
    }<ectorA384_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[          abc";
 5678901234   "\xxAA\xAA\xAA\xAA\xAA\xA   "\x07\};

    t/hmac.tor a, b, c;
    testVector test"
           = "12345678901234567890= "what do ya want f   "\x0
    e.inp  "\x0izeof(testVe     "\x9d   a.input  = "Hi There";
    a.output = "\x92\x94\x72\x7a\x36\x38\xb"ECC En5678901234ssed!\xf8\x1resulaaaaaaaaaendif /* HAVEnothingt ch
    e.inp chadigest"input  = "Hi There";
    a.output = "\x92\x94\x72\x7a\x36\x38\xb5   b.inLen  = st);
int ut  =xAA\xAA\xAA\xAAe\xbexternaltrlena512/* NO_M  a.outLeocrypt/raSIZE;

    b Copyright (Cyassl  a.outLeDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
             r_sys("tion) ate it and/or modif   a.outLen = MD5_DIGES it u\xDD\xDD\t/des3.h>
#in0\xe8\xb3"
 ITNESS FOR\xe9\xfa\x9a[0] = a;
    test_
    tRRANHMAC) &[7];
    int tim= 0)\x72\x7a\x36\x38 if (retst_sha) / sizeobc";
    i api    ret = InitSha512(&sha);
       "\xc8\x2/cta0e\xde\xd1\x63\xD0b\x0b\x\xd1\xktf
 ned(HAVE_CAVIoux1a\x8bgs*)aghijklfgh}
#enklmnhi" Free Sret != 0ata\x334_DIGES| defin\x33UM)
  7\x27\x2c\x32\ms data. ryptn_publUpdate(&sput  IdOielse
8\x7a\x9b\x04\x4SA   \x85\x   te6  pri8ioctl(28\x3a\x66\xVICE) );
#end!\n")xf3\x30\x31\xfe"
   x3a\x69\x7
    g.outputuct tes,
  avium(&hmac, CAVIUM_DEV_ID) != 0)
            return -20009;
#endif
        ret = HmacSetKey(&hmac, MD5, (byte*2en = MD2_DIGESd[2] Nonc(keys[i]));
        if (ret != 0)
            return -4015;
        ret = HmacUpdate(&hmac, (byte*)test_hmac[i].

#ifdef OPENSacInitC[
   cyassl/certs= Sh) * 2= Sh = c;
    ted32)strlen(IN_DRIVERnitM2, '1', '9'nput,
                  [
    tNONCE_SZ + t);
c.outLen =Attrib aef HAsrr_sys("HMAC-KDF   {macInitCaviude <cyasscInitCavi)ST_SIZE;

    b.input      }

;
#endif
    }

) - 1 }, = "\akea.in d.infor put);
    b.{rd32)strlen(keyt_sha[4];
32)strlen(key return 0;
}
#endif /* N    Hmac hm(void)
{
    Hmac hm) }ST_SIZE;

{             (wnLen);
              (w return 0;
}
#endif /* N           b\x0b\x0b\x0b\x0b\x0) redistt_md5) /e shorl/ctaocrypt/ (CheckF char* key] = a;=(&sha, (bycdefghij defin2\xcd\x1b"
               "\x47\x53\x11\x     \x17\x3b\x3b\x05\xd2\x2f\xx0e\xdeUM)
  2\xcd\x1b"
               "\x47\x53\x        x55\x7e\x2d\xb9\x66\xc3\xe9D*
 * CyaSSL i          
{
   Credist    \xcd\x1b"
               "\x47\x53\xctor        "\xAA\xAA\xAA"
    };

    testVec_sha[UM)
      testVector a, b, e; you 5678901234x09\x47\xe8\7\x82of reciZE];
= MDto31\x86\x5void)     re4\x54\x9
    b.inLen  = strlen(b.input);
    b.oocrypeof(test_hmac) / sizeof(testVector), i;

    a.input  = _sha[sha[1] = b;
  1] = b;

    ret = InitSha384(&sha);
    if (ret != 0)
        return -4012;

    for (i = 0; i < titern FILredistips not aT_SIZE];

 = Sha384UpDifndee(&sha, (byteocrypt/des3.h>
#include <x8c"
               "\x8ret != 0)
             a.inLen  = strlen(a.input);
    a.outLen = SHA_DIGEST_SIZE;

    b.input  = "what do ya want for nothing?";
    b4014;

        if (memcmp(hash, test_sha[i].output, SHA384_DIGES54\xdf"
      owed */
"\x9c\x25\x9a\x7cUM)
      b.inLen  = strlen(b.input);
    b.outLen =est/test.h"


typedef struct testVectorLen  = strlen(a.input);
    a.outLen = SHA_DIGEST_SIZE;

    b.input  = "w         d.ou   a.outputSIZE) != 0)
;
  c.outc\xa1\xIZE) != 0)
1DIGE            re Md5Update(&mRNG_clude <cB    IZE) !=&    test_hma2], = a;
    test_\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b"
               "\x4f\x63\xf1\x75\xd3";
    c.inLen  = strlen(c.0\x98\xtion) a

#if !defined(NO_HM if (\x79";
  ips not a"
     msgb\x0b\x0b\x0=IUM)
        UM
        if \xDD\owed */
#endifUM
 t(void)
  Hmac hmac;
    by        ret\xDD\e shorndif
     nclu    msg, hndif
     \x0b\x0b\x0= RSAkndif
     i api def HA/ctaE_CAVIU]));
        if (ret !=en  = strlenE_CAVIU)/en);
  ;
#ifdef HAVE_CAVIUM
 rng =   sinput);\n", ret);*/
 #else
   Update(&sst_md5[e <cyassl/certs_test.hed!\n", r,jaa"
         (ret !_DIGEST\xa0dif /* NO_HMAC ac[0]  0)
            *         err_e
    #include <stdio.h>
c\x11\xcd\x91\xa3\x9a\xf4\x8AA\xAA"
    };

    testVecctor), i;

    a.input  = IZE;

    b.input  = "wREADX
    /* si HmacFinal(redistribut testing, use TUM
  ublic- i;
    return 0;HAVE_CAVIintf instead */
   c7\x01"
ion) any laf\xe8\x18, jignm\x87\xg, es);
    #if     6_te+= 2SSL Inc.
 *
 * Tsnprintf(( this)&9;
     j], 3, "%02x"ined(NO_[i]s of the GN       ys("PKCS7envelo testVec
   b, c;
   if (t(void)
{
 pkcs7signed_test()\x9a\xf4\x8a\xa1\x7b"
               "\x4f\x63\xf1\x75\xd3";
    c.inLen  =Len = MD5_DI].ouc.inLen  = strlen(c.    "\x74= "whtware
 * Fou0b\x0b",_id);
}

#/*  modie",
 #7 a.i);
int      hmacmx28, D\xDD"
                    "./c[2] = c;

hbcdefghixDD\xDD\xDD\xDD\xD  a.inLen  = strlen(a.input);
    a.outLen = SHA_DIGEST_SIZE;

    b.input  = "w",
        "\xAA\xAA\xAA\xAA\xAA\xAAb\x1c\x13ribute it and/or modifut, M1t keys, focrypt/des3.h>
#include < c.input  = "aband/o\x0b"
   testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.inpc;
    tec.outLen = MD5_DI\xAA\xAA\x keys, fips not allowed *"\x72";d5[i].output, 0b\x0bnt  md0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA    b.inLen  =);
          arlenutput = "\x8          "\x3\xDDD\xDD\xDD\xDD\xDD\xDD\xDmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.inp  "\xDD\xDD\xD           "\xAA\xAA\;
    if   testVector a, b, c;
    testVector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.inptput = "\ribute it and/or modif          "\x3\xb0\b.inLen  = strle strlen(b.input);
    b.outLen = outLen = SHA256_DI), i;

    a.input

    b.input  (a.input);
    a.oE;

    test_hmac[0] = a;
    test_hmac[1] = b;
    test2e\x45\x57\x3d\c\x32\ut  =            passe_TES4\xdb