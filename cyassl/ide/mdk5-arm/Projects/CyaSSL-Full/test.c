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
    #include "crypto_ntru.h"
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
#ifdef HAVE_CAVIUM
        if (i == 1)
            continue; /* driver can't handle keys <= bytes */
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
#ifdef HAVE_CAVIUM
        if (i == 1)
            continue; /* driver can't handle keys <= bytes */
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
#ifdef HAVE_CAVIUM
        if (i == 1)
            continue; /* driver can't handle keys <= bytes */
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
#ifdef HAVE_CAVIUM
        if (i == 1)
            continue; /* driver can't handle keys <= bytes */
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
        FILE* keyFile;
        FILE* pemFile;

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
			  FILE* file3 ;
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
        word32 rc = crypto_drbg_instantiate(112, pers_str, sizeof(pers_str),
                                            GetEntropy, &drbg);
        if (rc != DRBG_OK) {
            free(derCert);
            free(pem);
            return -450;
        }

        rc = crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                        NULL, &private_key_len, NULL);
        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -451;
        }

        rc = crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                     public_key, &private_key_len, private_key);
        crypto_drbg_uninstantiate(drbg);

        if (rc != NTRU_OK) {
            free(derCert);
            free(pem);
            return -452;
        }

        caFile = fopen(caKeyFile, "rb");

        if (!caFile) {
            free(derCert);
            free(pem);
            return -453;
        }

        bytes = fread(tmp, 1, FOURK_BUF, caFile);
        fclose(caFile);

        ret = InitRsaKey(&caKey, 0);
        if (ret != 0) {
            free(derCert);
            free(pem);
            return -459;
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
        if (!reqFile) {
            free(pem);
            free(der);
            return -469;
        }
        ret = (int)fwrite(pem, 1, pemSz, reqFile);
        fclose(reqFile);
        if (ret != pemSz) {
            free(pem);
            free(der);
            return -470;
        }

        free(pem);
        free(der);
    }
#endif /* CYASSL_CERT_REQ */
#endif /* CYASSL_CERT_GEN */

    FreeRsaKey(&key);
#ifdef HAVE_CAVIUM
    RsaFreeCavium(&key);
#endif
    free(tmp);

    return 0;
}

#endif


#ifndef NO_DH

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #ifdef FREESCALE_MQX
        static const char* dhKey = "a:\certs\\dh2048.der";
    #else
        static const char* dhKey = "./certs/dh2048.der";
    #endif
#endif

int dh_test(void)
{
    int    ret;
    word32 bytes;
    word32 idx = 0, privSz, pubSz, privSz2, pubSz2, agreeSz, agreeSz2;
    byte   tmp[1024];
    byte   priv[256];
    byte   pub[256];
    byte   priv2[256];
    byte   pub2[256];
    byte   agree[256];
    byte   agree2[256];
    DhKey  key;
    DhKey  key2;
    RNG    rng;


#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, dh_key_der_1024, sizeof_dh_key_der_1024);
    bytes = sizeof_dh_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, dh_key_der_2048, sizeof_dh_key_der_2048);
    bytes = sizeof_dh_key_der_2048;
#else
    FILE*  file = fopen(dhKey, "rb");

    if (!file)
        return -50;

    bytes = (word32) fread(tmp, 1, sizeof(tmp), file);
    fclose(file);
#endif /* USE_CERT_BUFFERS */

    InitDhKey(&key);
    InitDhKey(&key2);
    ret = DhKeyDecode(tmp, &idx, &key, bytes);
    if (ret != 0)
        return -51;

    idx = 0;
    ret = DhKeyDecode(tmp, &idx, &key2, bytes);
    if (ret != 0)
        return -52;

    ret = InitRng(&rng);
    if (ret != 0)
        return -53;

    ret =  DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    ret += DhGenerateKeyPair(&key2, &rng, priv2, &privSz2, pub2, &pubSz2);
    if (ret != 0)
        return -54;

    ret =  DhAgree(&key, agree, &agreeSz, priv, privSz, pub2, pubSz2);
    ret += DhAgree(&key2, agree2, &agreeSz2, priv2, privSz2, pub, pubSz);
    if (ret != 0)
        return -55;

    if (memcmp(agree, agree2, agreeSz))
        return -56;

    FreeDhKey(&key);
    FreeDhKey(&key2);

    return 0;
}

#endif /* NO_DH */


#ifndef NO_DSA

#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #ifdef FREESCALE_MQX
        static const char* dsaKey = "a:\\certs\\dsa2048.der";
    #else
        static const char* dsaKey = "./certs/dsa2048.der";
    #endif
#endif

int dsa_test(void)
{
    int    ret, answer;
    word32 bytes;
    word32 idx = 0;
    byte   tmp[1024];
    DsaKey key;
    RNG    rng;
    Sha    sha;
    byte   hash[SHA_DIGEST_SIZE];
    byte   signature[40];


#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    FILE*  file = fopen(dsaKey, "rb");

    if (!file)
        return -60;

    bytes = (word32) fread(tmp, 1, sizeof(tmp), file);
    fclose(file);
#endif /* USE_CERT_BUFFERS */

    ret = InitSha(&sha);
    if (ret != 0)
        return -4002;
    ShaUpdate(&sha, tmp, bytes);
    ShaFinal(&sha, hash);

    InitDsaKey(&key);
    ret = DsaPrivateKeyDecode(tmp, &idx, &key, bytes);
    if (ret != 0) return -61;

    ret = InitRng(&rng);
    if (ret != 0) return -62;

    ret = DsaSign(hash, signature, &key, &rng);
    if (ret != 0) return -63;

    ret = DsaVerify(hash, signature, &key, &answer);
    if (ret != 0) return -64;
    if (answer != 1) return -65;

    FreeDsaKey(&key);

    return 0;
}

#endif /* NO_DSA */


#ifdef OPENSSL_EXTRA

int openssl_test(void)
{
    EVP_MD_CTX md_ctx;
    testVector a, b, c, d, e, f;
    byte       hash[SHA_DIGEST_SIZE*4];  /* max size */

    (void)e;
    (void)f;

    a.input  = "1234567890123456789012345678/* test.c
 *
 * Copyright (C) "
 lfSSL Inc.
 *
"/* test.c
 *
 * Copyri";olfSSa.output = "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6wolfSSL Inc.
 *
 *\x7aCyaSSL.
 inLen  = strlen(U Geput)yaSSL.
 *
 nera= MD5_DIGEST_SIZE;
olfSSEVP_MD_CTX_init(&md_ctxas publndatDigestIher version,the Lmd5())are FoundaticenseUpdate
 * (at yoicense L is dLen 2 of the LicenseFinal
 * (at yohash, 0) any laif (memcmp(l,
 * 
 *
 * C,* the Free Softw) != 0)olfSSL Inreturn -71are Foubcense al P"a A PARTICULAR PURPOSE.  See the
 * GNU General Public LicwolfSSL Inc.
 *
 * A PARTICULAR PURPOSE.  See the
 * GNU General Public Licecense for more details.
 *
 * CyaSSL.b *
 * CyaSSL AD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7 it under the terms 5dati redE\x26\xA CyaSSL. FITneral Public L FITNESas publprogr by
 *SHAe Free Software Foundation; either version 2 of the License, or
 * (at your osha1on) any later version.
 *
 * CyaSSL  FITNESsing md in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; program;,lude <config.h>
warranty of
 * MERCHANTAB2;
re FoudFITNESS FOR bcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqCyaSSL.d *
 * CyaSSL 24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0on, MA93\x0C\x3E\x60 it under the terms 39\xA3\x3C\xE4\x59\x64\xFFor modtwarF6\xE.h>
D\xD4\x19o th it under the terms h>
#C1pt/md2.h>, USA
 */

#ifdelude <cas publh>
#i #include256 <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef XMALLOC_USER
256on) any later version.
 *
 * CyaSSL lude <cdes3.hd in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; h>
#incl   #il/ctaocrypt/ranwarranty of
 * MERCHANTAB8;

#iasn_ CYASSL_SHA384re Foueude <cyassl/ctaublia.h>
#iiclude <jyassl/ckaocryptlhc128.hm
#inclunhiwolfSSL Inc.
 *
 *<cyaso <cyasoplude <cqassl/ctrocrypt/swdbasedth>
#incuCyaSSL.e *
 * CyaSSL 09\x3ryptc>
#ifdf7\x11\x4s fr8\x3d#inclu2f\xc7\x82\xc<cyab it under the terms #incloor    1b\x17\x3b <cyas05\xdare;f\xa0\x8e2.h6you cab#include <cyassl/ctaoECC
 2\xfctaocryocry1aredist7/or d\xblude6\xc3\xe9\xfa\x91 it under the terms o4h>
#aocrassl/ctao, USA
 */

#ifde/ctaocras publaocry #include384 <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef XMALLOC_USER
384on) any later version.
 *
 * CyaSSL /ctaocrEXTRA
d in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; aocrypt/   #iing to use MS ewarranty of
 * MERCHANTAB9ocryendif /*.h>
#include < */
crypt/dh.h>
#includ512re Foufctaocrypt/dsa.h>
#include <cyassl/ctaocrypt/hc128.h>
#include <cyassl/ctaocrypt/rabbit.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctf *
 * CyaSSL 8e\x95\x9b\x7aocrayou ca13      8ce softECC
28\x1 cercst.cinclude <cyassl/ctaocf\x8f\x7ware9\xcndifb\x9    blak1\x72or, Boae\xah>
#6\x8 wolfSSL Inc.
 *
 *\x90\x18\x5    ds_test9ebute i00certs_e4>
#ifdnclu, Bode\xcitial data, so other
b5\x4/shaactaocrd3\x29\xeemands d    6\x5#incta.hndif5\x5
#endif
#ifdef HAVE_B87\x4 youde <rypt/pkc) ||neral Public L) || deas publnclud #include512 <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef XMALLOC_USER
512on) any later version.
 *
 * CyaSSL ) || dede "cad in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; nclude "   #i   #define fopewarranty of
 * MERCHANTA80/openssl/des.h>
#endif
512if defITHOUT ARAND_bytesRANTY; sizeofRANTY)warra1ty of
 * MERCHANTAB3are FoucFITNESS FORwhat do ya want for nothing?CyaSSL.c *
 * CyaSSL     ef He
 *3e\x6a#ifdined(C0fdefa\xa8\x6e\x3modipt/ch>
#nklin Street, Fifth F38f insteadpen(const char *ince juas publad */ by
 * the Free Software FouHMAC(ur option, "Jefe", 4, (e
  *)ince ju, (intconstLenful,
 * but WITHOUT ANY WARRANTY; ad */
  even the implied warranty of
 * MERCHANTAB4are Fou{des.des testif dest/tonst e
   vector[] =;
int "now is the timeADX lall " w/o trailing 0t(void);sha30x6e,0x6f,0x77,0x20st(v9id);3int  hma74,nt  sha384_t8st(v5est(void);
mac_md56d_test(void)nt  sha384_t6st(void);2int  hmac1ac_sc;
int  h20oid);}LITY or ha_tplain[24]ONFIG_Hha_tcipherac_blaoid);
int _DES_cblock key =oid);
nt  sha384_0);
i2test4t(vo6
int8_md5ab,0xcha25ef512_test(voidvoid);
int ivc4_test(void);
int 1_tes3nt  5mac_7a_te9 hmaabbit_test(void);
int  des_tekey_schedule _testt  hkdf_test sha_tesrifyid);_test(void);
int 8bbit7t  h5_tesb hma hc128bbitnt  hb8void);
int  4oid)0oid)ebbitftestfbbit5oid)8s_tes3void);
int  1t(vo8t(vobtest(_tes4bbitest(vint  4btest(void);
int  gmac_test(&key, &_test) any lavoid);c_encrypt(est(vo,t(void)lude <stdest(vo) /* test, &iv,pi */ENCRYPTas publi */
int pbkdf1_d);
int t  hmt pkcs12_test(void);
int pbkdf2_tesDEvoid);
#WITHOUT ANY WARRtest(votest(voipkcs12_test(vowarranty of
 * MERCHANTAB5int  ecc_encrypt_td);
int id);
i  #endif
#e);
i
#ifdef HAVE_BLAKE2
    in6int  ecf
#i/*4_testchangvoidivt(void);voidn
int pbkdf1_test(void);
int 8id);
int pbkdf2_test(void);
#ifdef HAeloped_test(void);
 +kcs7(void) char*16id);
int pbkdf2_test(void);
#blake2b_test(void);
#endif
#ifdef HAVE_LIBZ
    int compress_test(void)7\n", ms}ifdefend  md4_test(vooid);
i     vp_ msg, i_test(void);of the LCIPHERn; e ctx    #incid);
int  sha_tmsgid);
int  sNa256_test(void);
int  sha512_test(void);
int  sha38ha384_test(void);
int  hmac_md5_test(void);
int  hmachmac_sha_test(void);
int  hmac_sha256_test(void);
int
int  hmac_sha384_test(void);
int  hmac_sha512_t12_test(void aesccm_test(void);
int  cameltest(void);
inha384_9t(vo9nt  9_tes5
intdom_t4_tes8);
i5id);
int  pha384_2t  hct  h9ha254s_tes
inta);
intestcoid);


#if !defined(N_testkeint   "* test.c
 sa.h>
*
 *;
    alignunc_args fro_testiv[]S FOR test.c
 *Build vs runtime fastmathh FP_MAX_BITS (void);AES_BLOCKSoftw * _blake2bvoid);
int  hm G_INT */


#ifndef NO_olfSSL Inm test.h, so dither vion 2 of tITHOUT Am tesvoid), or
 at your oaes_128/
inst c;   /kdf21) =ranty of
 * Me <mqx.h>
   ILITY orret);
    else
    printfd);
int ;
    cmsges)

#endif

#ifdef CYASSL_MD2
  
   lfSSL In2b_test(void);
#endif
#ifde_INT */


#ifn)f

#ifdef CYASSL_MD2
      /* serr_sys("MD5      test failed!\n", ret);
    else
        printf( "MD5      test passed!\n")0
#endif

#ifdef CYASSL_MD2
  t(void);ret = md2_test()) != 0)
 test(vod);
int      test failed!\n", ret);
   t  blake  ecc_encrypt_test(voi"MD2 ssed!\n");
#endif

#ifndef NO_MD4
    ;
#emsg)
        exreturn;
}

/* func_se
  ERCHANT0;
}openssl/des.OPEN#incEXTRAif definenld vNO_PWDBASED

int pkcs12__tes(void)
(void)
int  sha_tpasswdid);
in0x00, (voidest passe6d\n");
#endi5\n");
#endi7mismatch\n", -= sha384_test())st passe00test        printf(saltid);
);
i0x0a\n")58\n")CF#endi4", re!\n");f

#i82\n")3ftest(void    printf( "SHA-2256  test passed1\n");
#end7ASSL_SHA384
 ( (ret = sha5olfSSL Inc.
 *
 ha384_test()) != 0)
  67\n");
#end      err_sys("SHA-384  t

#ifdailed!)
{
( "SHA-3CpassefC", rebHA-384assedetestc5    err__test derived[6int  hkdf_testest(void);
int  llia_test(voidAtestA testE test29assedBt fai
#endBpasse46(void);
int  SHA-3A    e5    e0led!\7t);
 5HA5122t);
 4Evoid);
int  Bled!\1SHA-38  els1 test2 test7  elsB
#endA3512_test(voidccm_test(void);
i

#ifdevoid);
int  t);
 3DtestD testEret);1ret);Dled!\DEt()) LAKE2
    if 8");
#e
    8    eAt);
 Ft);
 6SHA-3F!\n")FBvoid);
int  F    eD
#end2    eC    e2
#end0SHA-39ASSL_7F512_test(voidled!idr_sys("SH=  1  err_led!kneral
      24else
     iterations     else
     reCyaSPKCS12_PBKDF((ret = ,( "SHA-  #endif
 "SHA-),84  tpkcs7test passe!= 0)
        err_sys("SHA-51       #i, it mini apUT Adif
<anty of
 * MERCHANTA10    /* sUT A      = NY WARR_SHA
    if
#ifde    
#ifdef HAVE_BLAKE2
    i10t(void);test passed!\1000  err_dif

    #ifndef NO_SHA
    if ( (2ret = hmac_sha_2test())2 != 0)
        err_sys("HMAC-SHA test fa!\n", ret);
    lse
        printf( "HMAC-SHA test t  blake2b_t
    #endif

    #ifndef NO_SH2, 24       if ( (ret = hmac_sha;
#endif (ret = sha25iled!\bkdfret);
    else
     har( "SHA-256  " "SHAordf insteays("SHA-384  test fled!ndif

#led!\ NO_HM5n", ref

#i6!\n")cf

#i06    err_led!st()) != 0)
   204812_test()) !     tf( "HMAC- if ( (ret = ripemd_test()) != 0)
        err_sys("RIPEMD B  elsn");
#6    eE2b  t4intf(Fled!\EHA5121intf( 
    0ret);   errE2void);
int  0 test_sys("5ASSL_E
#end3SHA-37se
   ret);3 testF  elsE2b  tys("HM43\n");
#failed!\n",dif

  ef N2   #ifndef;
    cif ( (re*  ouublic Lc_sha_test()) != = 0)
        err_sys("SHA-512      if ( (ret = hkdf_test())
        eed!\n");
 endif

    #ifdrranty of
 * MERCHANTret\n", msg, es);
     #ifndef NO_SHA2f HAVE_LIBZ
    int compress_test(void10 else
  ed!\n", ret);
        e1se
            printf( "HMAC-SHA384 test passed!\n");
    #endif

    #ifdef CYASSL_SHA512
        if ( (ret = hmac_sha512_test()) != 0)
                 es("HMAC-SHA5116test failed!\n", ret16emd_test()) != 0)
        err_sys("RIPEMD )) != est pa8
    7");
#0ASSL_Ct failintf(2  elsAe2b_tepasseE    eret = hmac_md54 testrintf( != 0)ha512_test(voide
   1        printf( "HMAC-BLAKE2 test passed!\n");
    #en0)
        err_sys("HMAC       err_s
        else
            printf( "HMAC-KDF    test passed!\n");
    #endILITY ored!\n", ret);
     wdbasedet);
    else
          elsESGCM
    if endif
dif
+=     else
    test pd!\n", ret +!\n", ret);
 )sha256_test()) 256  test fif de#if defined(HAVE_HKDF) && (!       eNOclud) ||   test failed!\256));
    hkdfet);
    else
           ef NO_RC4
L = 42test failedokm1[42blake2b_testi   i2256  test hmac_s        err_sys("DES3     test failed!= 0)
        err_sys("S0)
        err_sys("DES3     test failed!\n", ret);
    else
        printf( "DES3     test passed!\n");PEMD
    if (4  t1[13] =test passe0HA512
SHA-30!\n");E_BLAKASSL_S test0    if ( (ret = sha384_te0x0t);
 KE2
  \n", r   err_cPEMD
    if (info1[10iled!\nf!\n");HA512fSHA-3f!\n")f
    fASSL_f testf test passed!\n");

#ifdef ft);
 f9PEMD
    if (res if (6  test n", rcHA512adef CY, ret)SHA-3b!\n")dled!\61ret);
    else
        pridHA512eASSL_5sys("Ht);
 dn", r9f

#iff( "AES est passed!\n");

#ifdef bret);aASSL_est fa  else7SHA-32passea!\n");        printf( "AES-CCM  tepassedf

#i6f

#i8led!\eled!\ndef C2HA512d    ((func_argsf ( (ret = ca   if , ret)!\n")3f

#iamelli3;
    else
d mismatch\n", -");

#ifdef 42b  te8 test passed!\n"2;
#endif

#idif

#   if "AES-Cn", r1f

#id!\n")M  tes69       printf( "AES-CCM  t3f HAVE_Cvoid);d!\ntest edef CaASSL_antf( "st()) != 0)
        err_sysa faileHA5124)) != endif
def Cif

#iKE2
  1 != 0)
        err_sys("S_sha_) !=ret);cf

#id 0)
       est())ff

#iaf ( (ret =     else
       cendif
ASSL_D   te2else
 led!\n!\n");\n");
ssed!\n");
#endif

    if (AES-GC9ha512_tesssed!\n"3;
#endif

#8#endif
    e);
#enef NO_ASSL_(ret = HA5128f       printf( "AES-CCM  tSHA5125def C8passe2   if test 3crr_sys("RA3st()) != 0)
        err_sysbprintf  #ifd      test fASSL_eDSA
  led!\9e
#ifndef NO_DH
    if ( (re!\n")4ASSL_4sed!\ndef C test d!\n")test p2d       printf( "AES-CCM  tt);
  

#ifd1!\n")HMAC-Mfn", rassed!btest 1ar_sys("PWDBASED test failedtest c random_test()) !4;
#endif

# test be2b_terr_sysse
        ptest dndif
#ASED test passed!\n");
#endi     p ( (redef Ce
    d "CAME!\n", rr_sysASED test passed!\n");
#end2     errCM
    ifret);
cdef C1n", ren", r4c       printf( "AES-CCM  t if ( berr_syE_ECC!\n");
test c
    cASSL_b  if ( (ret = dsa_test()) !3E_BLAKpassed");
#eled!\n      print
#endi1endif

    #ifdef HAVE_HK ret);
 6IPEMDdif

    el\n")ndif

        edef NO_        e3test failed!\n"t(voys("SHA-256SHA    err_syss("D(ret);
km1, 22, NULL, 0\n");
    #    , Lr_sys("HMAC-KDF    test failed!\n", -20 != 0)
  UT ANY WARRdif

#\n")
#if
    if ( (ret = compress_if

#endif
ECC Enc  test passe11est())( "C3,t()) !, d!\ndif

#ifdef HAVE_LIBZ
    if ( (ret = compress_passed!\n");)
        err_sy2("COMPRESS test failed!\n", re4;if ( (ret = deSH  err_
            p256rintf( "ECC Enc  te2!\n" passed!\n");
    #endif
#endif

#ifdef HAVE_LIBZ
    if ( (ret = compress_t  blake2b_test(voi   err_sy3("COMPRESS test failed!\n", reest failed!CS7enveloped test passed!\RESS test passed!\n");
#endif

#ifdef HAVE_PKCS7
    if ( (ret = pkcsf (msg)
ned    test failed!\4("COMPRESS test failed!\n", re7t failed!\n", ret)256
    if ( (ret = sha256_test()) rr_sys("Dif defined(USrr_syECC;
    eccet);
    else
    RNG CYASSngtest failed!  sharedA[10c_blake2b_testM_DEV_ID)B
      return -1;
   ig
      return -1;
  dcense[20  return -1;
  exportBuf
      returt pa32  x, yef NO_RC4
    ief NO_SHA2\n");
#en;

  arcuserA,NMENTB, pubKeyf( "PKCS7sign, orRng(&rngfdef HAVE_LIBZ
    if ( (ret = compre1s_test()) ;

 ther vMENT,_VER
   IUM_DEV_ID);
B   return CspInit       test paS7signrn CmakeSSIGsign), 
   ID);

    0)
         return -1;
   }
   CspSh1t(void);/* HAVE_CAVIUM */

    /* so overaze(d 0)
         return -1;
   }
   CspShu else
  xl Pue <stdEV_ID))endif

/* HAVE_CAEV_ID)_secreV_ID);

  {

   ,DEV_ID)), &n 2 ests can pull in test function */

   t  blakeyint ret = OpenNize(dma_mce(CAVIUM_DIRECT, CAVIUM_DEV_Bo overal    if (gs.a

#endif         return -1;
   }
   CspShupassed!\n");yF   xrn -1;
   }
   CspShu256_test(d_test())   if (retrgc;
    xdif

#ifnde}
   CspShut  blake int ret = ) {
     #endif /* HAVE_CA) {
  _x963M_DEV_ID)) {
     et != 0gs.argv = argv;

        ctaocrypt_tetf( "PKCS7signrn Csmifdef CYASnt md2_testx, id);
}

#endif         return -1;
   }
   CspShuf (msg)
 failed", -1236);
#endif /* HAVE_CAVIUM */

        args.a      ;
#endif

     args.argv = argv;

        ctaocrypt_teaocrhutdown(CAVIUM_DEV_ID);
#endif

 y      return args.ret1 #in
#ifdef HAVEDSAe))
nul,
 t(void);DX l(i = 0; i <AKE2 tee <stdif (de); i++ty of
 * Mif (deviendi;
   )i        int ret = Oi)!= 0)
 ce(CAVIUM_Dign_l,
 b.outpuf( "HMAC-.outputf( "get !,     /*overall tests can pull in test function */

   ;
#endifLIBZ
  b.inxc0"
          LIBZ
  "\xb5rlen(/desxd1";
    b.inLen  = st&if
#ifdeoverall tests can pull in test function */

   test()) != 0    c.oendif


#ifdef THREADX101
        int ret = dif /* NO_MAIN_DRIVER */


#ifdefprivate_onlySSL_MD2
int md2_test()
{
    Md2  md2;
    byte hash[MD2_DIGE1    /* srn Cfree_id);
}

#e    d.inLen  =ialize(dma_mode,
    d.outll tests  (ret = sha2562             st(void)device;

  pbkdf1   if (CspInitialize(CAVIUM_DIRECT,_DEV_ID]1_GET_CORE_ASSIGNMENT,
       return -1;
  junk48  return -1;
  t  hmae.inLen  = strlenout[8ce != NPpkpdev_houtSz     ;
    boypt/test/pkpdev_ht  hmSznput  = "At  hm
{
    MDEV_ID],  (Uint32 *)&core_assign)!= 0)
         return -1;
   }
   Csp3hutdown(CAVIUM_DEV_ID);

   return CspInitialize(dxc0"
    HAVE_CAVIUM */

    /* so overall tc0"
    +t argc, char** argv)
    {

        func_args args;


#ifdef HAVE_CAV3UM
       ;

    b.input  48 = "\x32\xec\x0junk4a\x645"
         bkdf1     to Bt(void);RIVER */


pbkdf1__DEV_ID);
      "MD2 ;
    bmsg),
   , &    f\n");

    f.output = "\xda\x33\xde\xf2\xa4\x2    /* snt  m67890";
  from   errut = "\xd5\x97   g.ou    args.argc = a66\xf"
     test(vo&TUVWXYZ            "\xef\xd8";
    g.inLen  = strlen(CspShutdown(CAVIUM_ret);
    elx80\x6c\x3cOMPRESS test failed!\n",3turn_c#endif
    let's
    c.omessage ex_PKCSeKLMNks, A56_tclient, B56_tserverunc_args froecEncCtx*(bytCt intrn Cctx_new(REQ_RESP_CLIENTinput)d!\n", ret)2)test_md2srv.inLen);
        Md2Final(&SERVERash);

   */
#endif /* !liS  teEXCHANGE_SALT_SZNO_MD5
    if ( srvturn -155 - i;
    }

    return");
    #e* tmpturnelse
        pr[i].inLe=n");
", rash, tesDIGESTf

#ifdef CYASSL_MD2
 3EST_SIZE];put);
 get;
#en   gs  exto pe.input, (word3  Md5  Len);
     get_own_4  thash[MDd!\n", ret);
  _md5) / s testVector a, b, c, d, e;
    7!\n", ret)NY Wpyhashturn,t_md5) /, -155 - i;
    }
!= 0)
      _md5) / sizeof(testVector), i;
ash, t.input  = "abc";
    a.output = "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96
#endifd\x28\xe1\x7f"
               "\x72";
 /* in actualNMEN, we'dt_md5est(es ='s5[5];
o].inest(vrans{
  unc_args fro38\xcd";
      set_es =), i;

    a,}
#endifd!\n", ret)  f.outLen en = MD5_DIGEST_SIash, t,  return!= 0)
      HMAC-KDF    test faile, c, d, e;
    80\x69"
or test_md5\x6f\x7ed";
  (requtput
    int tim.output =tLen =  f.iput  = "ABCDEFGHIJKut = "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9\x80\x6c\x3c\x66\xf3"
    
    a.input  = "abc"\x92\xe4\x00\x7d\xfb\x49\x6c\xca\l/op2\x5a\x2f\xB    g.ousb";
    c.inLen= MD2_DIGEST_Srlen(e.inYZabcdefghijklmnopqrstuvST_SIZE;

    test_md2[0] = a;
    test_md2[1] = b;
    test_md2[2]    a.outLen = MD5_DI\x92\xe4\x00\x7d\xfb\x49\x6c\xcainput);
     test_md2[5] = f;
    test_md2[6] = g;

    InitMd2123456789012345  if ( (ret tings() != 1)
/*d\xc21234sponsex1c\x2cB tim\x9f\x41\x9d""\x94\x0b";
   2put);
     FP_MAX_BITS len(e.in e.inLen  = strlen(e.input)out2MD2_DIGESTd5[0] = _SIZE;

    f2.input  = "ABCD2;
    d.inLHIJKLMNOPQRSTUVWXYZ2abcdefghijklmnost_molfSSL Inc.
 90123456789012345678"
                      2 "90123+  er2b\xe3\xc9\x55\x         "\x3b";
    da\x2e\x  = strlen(c.input);
   ut = "\xd5\x97\x6f\x79\xd8\gs.argc = a++i)test_md2[6]  els tesndif

    #ifdef HAVE_HKDF
     3"
    (me   a.outLen = MD\xd7\x61\x92\xe4\x00\x7d\xfb\x123456789012345 else
      9\x55\xA2\x77\xd9\xf5\xa5da\x2e\x21\x07\i].inLen);
        Md5Fintest_md2[0] =ID);
      st_mdest_md5 b;
   so omd5[3] =ndif

    #ifdef HAVE_HKDF
    
    a.input  = " - i;
    }

    return 0;
}
#endif /* NO_MD5if ( (ret =     test_md2[5] = f;2   if (memcmp(hash, 4567890";
    e.outp123456789012345 "HMAC-sg)
 x74\xab\x98\xcleanupnput, (word32)opqrstLen          return -5input);
    a
    a.input  "\xc0"  a.inLen  = strle2_DIGEST_SIZE;Len = MD2_DIGEST_SIZE;

    e.input  = "abcdeent core_assigqrstuvwxyz" md4               "\x;
    el         LIBZ

");
    #endimple_textest 74\xa"Biodiesel cupidatat mar    cliche autf( ut a bird on it incididuice;lit\nwolfSS"polaroid. S\x0atattooed boid)kd!\nprehen(rett. Swxyztwee organic id\x7a\xa6\= "\x. Commodo veniam ad esse gastropub. 3 wolf moon sartorial
   o,\x7a\xa6\xlaiexitlectus babc";
   squid +1 vice. Post-iro   ckeffiyeh legS7
 s\x7a\xa6\selfies cray fap hobc";,nitM    anim. Carlen  c.output shoreditch, VHS4b";
    dmt  sbatch m    "\x kogi dolord);
od truck9d";
    = "message\x7a\xa6\\x7a\xa6\Terry rintf(dson adipisicvoidxaa\xfly typewrtest tumblr,.inputstinever\x7a\xa6\four loko you probably haven't hea\xd8f.inLm h>
# life. Mput nger bag\x7a\xa6\ strlen(      "\x9deep v mlkshk. Brooklyn pintertestassumenda chillwave\x7a\xa6\eloc anksy ullamcoi) {
KLMNOPQRS umami pariatur directen  dd);
iage8a\xa5\xbbT "\xa9";
 culpa try-63\x  if53\xe7\swxyzb        opqrstuv. Gent);
ie.input);
 tput = "\next level, tousled \x01y n    emiotics PBR ethical d.ou creoutLen = MreadymadDEFG  e.ec  e.brunch lomo odd future, {
  landt);
    cta8\x      "901\x63\xdf\x\xe8      "\xx41\x2d"
    ennui raw de    banjo hella. GodaroutLen = MDixtape x72"
   x3b\x"\xd    123456789t);
    c = st  "\xa9";
 helveticae.input);
    e.outcdefghijkstreet art yr farm-to-tabl  "\xe4";
 \x7a\xa6\Vinylassetar\x06\ tofu. Locav  e.Len = MD4_DIGEST_SIZE;

    f.inputpuSTUVWXYZabpickl     = st tonx lab  e.truffaut DIY012345"\x4f\xcosby swea";
 .out\x04\x3f\x8 m34567890". E4f\xswag8901234567SP1_inLen  = ste*)te d.output nisi ugh\x7a\xa6\nesci\x0apugDIGEST_SIZE;wayfarermd2[inLen x64\x54\. E45678"
(d.inp4b";
    d.itan fiLMNOsta8\x0kaleoutpps. xa8\xed\x63\xdf\x4rtisan williamsburgxd9\x13\x0eiusmod fanny paoid)01234Md4Up  "\x3lo-fi\x5f\xc1\x0at_md YOLO      "90123456789018-bFinaed2345   cb

    fficiaxe1\ur-   b.iphonee*)tebutc
int\x04\x3f\x8;
   3] =party qestVetterpressest_mdp
   ent jeanSIZE;d9\x2345"\x7a\xa6\l] = g;
8a\xa5\xbb\xcd\xee\Narwhal flexit);
 nt  = "abc";
,g, ugluten-Len  voluptate89012345678\x7a\xa6\banh mi];

  x5f\xc1\x0acn = MDDIY. O = "\xe3\ n\x41;
    i int tu_md4[i].incillum ++i) {
 v\xe8,  testimes = 
    InitMd4(&md4);

    for (i = 0\x7a\xa6\trust fund = "message Nt_md41\x2d"
         "\x, Austinest_md4[90'x4b";
    ddefghijklmnamerican apparel. Pxaf\x21\xd8\x52\put, (word32)tbefe(&mdhe\x19\x9c\xsoldctorDIGEST_SIZE;xyz"; = strlSt_md4[3] =mol4Finaustain_md4Len = MD4_\x7a\xa6\*)tetor), ieaEST_S int tdreamcjklmen  ut, (word32)tmagna scenes";
 st_m8a\xa5\xbbSedDIGEST_SIZE;skatebo
   aaaaaa,pdate(&moutput = yte has. Srirach;
    testexcepteu\x4B\x5C\x16\x4,
     deser\x0adate(um eue faquip2345678"
e_md4[i].inneutra89012selv    "\xe4";
 \x7a\xa6\R";
    g.IGEST_SIZE;d4, (byt,T_SIZE]a\x81\aaaaaa"
     xaf\x21\xd8\x52aaaaaaaaaaa12345678 "\xA9\x99\x3exercit pass. Hashtag = f;
   strlen(, nihien(a.inputauthent, i;aaaaaaadisruput  = "aa. T    "\x9  return -d.input2\x6E\xBA\TUVWXYZabc        e digest";
    ynth church- arc d.output,\x1c\x30\x      "\x4b";
         "\x. Late(&m  = "ABCD cT_SIZE,nopqrstuvw6";
    g.f /* NO_MD4 * i < times; 2\x6E\xBA\xcc\x05"
 

#endif       Nostrud2\x41\xdbdui);

        if (\x7a\xa6\x5f\xc1\x0aflannx18\aaaaa"
    4[1] = b;aaaaaaaaaaaat = "82\xf2you\x7a\xa6\x MD4_DIGEST_SIZE;

    f.input MD4_DIGE
    test_md4[ D       n    foutLen = MDaaaaaa\x7B\    c.inpump(hash, te4[1] = b;BA\x3E\x25\x71\x78\x = "axyz";
        if (, "\x2A\x25\xe*)test_sha[ i <x51\x29"
    viraxC2\x83\x9Dsh[SHA_DIGESTsalv= siFSHA_DIGEST2\x6E\xBA\xLen = MD4_DIGEST_SIZE;

  \x7a\xa6\ f.inputnomno  tesx78\x. K         = stVector     "6789cardign(b.aaaaa   "aaaaaa
        if (m1\x7. C= strl2345678
{
    Sha  s = "\x.outpu         d.ouut  = "aaa\x2A\x25\. Iha) / sizeofd4[i,89012345678t);
    f= "\;

    tes d;
    te;
    . M = "\\x87\x  = " past  = "aaa
            is irnputx1c\x30\x8a\xa5\xbbV
    ds(memc "12345678     "\xtestnt v4[5] fap8a\xa5\xbb\xcd\xee\H     
    e.IGEST_SIZE,md4, (byteGEST_SILen = MD4_DIGEST_SIZE;

    fa);
    ifnput9012i].input, i   dpte*)ehashshif\x4xed4[i bushwick= strlen(C2\x83\x9Dinput);
F /* NO_MD4 *nt rsha) /, "\xA9\x99\x3blue bottlipemsiDIGEST_SIe.input);
           pnopq";


    da\x81\d";
    rlennomnoVecto. BloSTUVWXYZab  = "abc";
 );
       ut);tput = "\id timesen = MD4_ghijhija9\x5d8a\xa5\xbbA;
    f.outamb= st          x5d\x0  g.outLe*)test_sha..inpinput \x7a\xa6\x64\x54\,  = str
{
    Sha  Len = MD44\x48\x0al(&mDIGEST_SIZE; SHA_xyz"utLen = MD47B\xpop-up ltest lly. Sl(&mthu  = ca d.o "\x3IZE;

     veg  c.input  p    fGESTaaaaaaad4, (byteetst = 99\xingle-origin coffee timfcdecer8a\xa5\xbb\xcd\xee\Odiot  = "abc";
 en = MD4_\xe8. ;
}

#inLen  = strlen(d.inpin occaeca
        SDIGEST_SIZI01234opqrstuvw
    ,output = "s = siz41\x2d"
              "90x98\xBA\x82\x

    ;
    b.outLen = SH_SIZE]27\xe\xa8"6E\xBA\x   c.output = "\x81\x6A\x*/

#ifndef Nn(c.inpu345678\x39\xf4\xd    InitRipe
      a);
    if2345678 int tT_SIZE) aaaa8\x0cc\x05"
 b\x4d\xdc   "aaaaaa1\xFhilnput t);
    c.";
  \x2A\x25\x;

    a.ib";
b\x39\xf4\xdb  d.x98\xBA\x82\xuthighijhut  = "aaa56789\x2ectRCHA et tesnput)
         inLen,t  = "axA0";
   \x35\x1c\n(a.input);g72\xb88\xf2\ed\x63\xdf\x);
    b.\n" for= "\combc";
"DES      test passed!\n"output = "pkpdev_dYZabcdefghijIZE;

    cEFGHIJKLMNOPQRcYZabc(
   + (pkpdev)2, 0x* 0.001) + 1st_md5[2_test*c DIGEST0, 0xE1, 0x5d, 0x47, 0 err_s = calloc(c e.ine <std\xac\c4.h>
#i 0x17, 0xFd, 0x1F, 0x54, 0x19,x69"
    c5_DIGEST_SIZd.output = "\x90\x02, 0x0     0)
           endiS    2, 0x0C  0x78,(c,52, );
#E;

    c,,
  intf) printf( "HMAC-SH, 0x93test()) != 0x6F,>ntf(    else
 2, 0xD2
    0x\n");
#en4, 0x44, 0put = " "\xc0"0xB0, 0x4B,
    Dex3A, 0x68d 0xB7, , 0x5BOMPRE*  oudSz   0xD5, 0x6F, 0x70 else
  0xB0, 0x4B,
    else
   , 0x14, 0x48, 0xB7      return a, 0x93passed!\n");cx1c\
   
{
    Md2 d, 0x90,t mini apd!\n", ret);ignment core_assigen =nput);
    b.outL   #7ailed!\n",7enveloptest failed!\n", reet);
    el, 0x4E, 0{
  msg, i=s7en3bqrstuvwxyz8, 0xBC, B7, decod2, 0t);
   0x69C, 0x20, 0xE1, 0* cer");
#en  },
 f\x4     st failed!8, 0xBC, [      return -1;
9, 0x05xAB, 0xA 0x8D1F, _t  {
 , 0x7A,  0x25, 8, 0x79, 0x7A, FILE*   {
 File0x09, 0xB2, 0key 0xE0, 0xFF, 0x00, 0x2 0xE0, 0xF");
  ntf(*xCD, 0Ou, 0xEA384  0x28, 0xBC, Data.der=
{
2b  test failedutpuid);
int  xe5\o World;
int  sha384_4a_test(vont  hmac_svoid)  hmaBuild6  if ( (ret384_tesnt  hm4512_test(void/*;

  (byte*)  {
  \xdc arcin DERn -4mast(void);
x3D,x6d\xac*)defgoc(FOURK_BUF
{
    Md2 
  }
}3, 0x89, 0x64, 0x44ompressILITY or8, 0x79
};



int blake2b_test(void)
{
    Bbyte    i testVe0xE2, 0xCE
0x90, erut  = "abcdefghompressdef NO_ "\xc0"xBF, 0xE = fop "ctyte*)Cert, "rb"
{
    Md2 !xBF, 0xE (int)sizeof(input); i++)
      0x90,8, 0x79n = MD4_DIGErr_sys("caSIZE0; i ./t); s/< BLAK-t);  0xE, wolfSSL Inc.
 *
  "Please run1c\x2cCyaSSL hom Ripr", -4st_md5[2e)i;

    fYZabcf1234ut); , 1, b_test(vo,    for (const chclosput); 4);
   0x2B,, 0xEF,i = 0; i < BLAKput =TS; i++) {
     , 0xEF, InitBlake2b(&b2b, 64);
        if (ret != 0)
            return -4002;

        ret = BlakeyUpdate(&b2b, input, i);
        if (ret != 0)
            ret3rn -4003;

      0x9A, et = Blak8, 0x79inal(&b2b, digest, blake       if (re   testVecx7A, 0x50,_, orWithE2_T(& 0xEAest, 6,  {
    0     rVector  0xEA.cont5D,       ;
    cutputest_sha) / sizeof( f.inpu {
    0;
    b.ata(test_sha) / sizeof(OIDtLenDATAtest_sha) / \x6f\x7x01\xCF0x2E, test_sha) / f\x49\x     =08, 0x79, 0x8D       "\x23\xB0 },
  {
    0   0x9A, 0xt);
    en 0x06, 0x41, 0xAE, = "\xbd\D, 0x82, 0

    #7_E   "\E5\xAD";
    t ret;
   = strlenndif

    #ifdef HAVE_HKDF
        if ( (ret =message , 0xBC, x19,
   own( = strlen(a.<rantInitBlake2b(&b2b, 64);
        if (ret != 0)
           input[i], ret);"a";
    b9, 0x0x15\xAD";
    a.inLen 9, 0x05, .input);
D, 0x0outLen = SHA256_DIGEST_SIZE;

  x7D, 0x82, 0xdif

    #ifdef HAVE_HKDF
        if ( (ret9, 0x05
    b.inL, 0x05omnopnopq";
\x67\xF6\x = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
    "HMAC-"a";
    b_test\xA3\x3resullen(b.inp    else
    EST_SIZ= "\
    b.inL "\xOMPRESSx24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
   5n -4005;

    fo*
 * Cy 0xEAx15\xAD";
    aDX lexternalor (ivoidIGEST_SCD, 0x8E,i = 0; i  0x7D, 0x15,, "w; i++) {
     CD, 0x8E,st_sha[i].input,(word32)test_sha[i].inLen);
        if (ret != 0)ret = a "\xc0"0x44, *  oufxa9";
    b.out;
    b.inLen nal(   if (mem       if (reCYASSL_SHA51456789input); i++)
  if (ret != 0)
     put);
Fen  =  0x2= 0)
           9B, 93\x0C\x3E\x60"
, 0x4E, 0x44, 0x11, 0x50x4C, 0x2    , 0xB4,
    0xF5, 0xA0, 0xF3, 0x27, 0x0xB2, f0xE0, 0xF  },
  {
 D          },
 key.input  = "abc"ou");
#enntf( , 0xAB,
 \xe5\0x08, 0CyaSSL., 0x03,
ata#ifd"
        a.in#ifd;
    , 0x7A, 0x50, msDIRECT,ze(CM_DIR 0x8D, 0xCn  = IdOi-256 olfSSL Inc.
 *
 led!\S     n", r6passe8t failAVE_AEDSA
  s("HMAHAVE_BASSL_Sst()) != 0)
        _AESGCM
 7e
        pri) {
      f\x4b\x55"
               "\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3"
               "\xfe\xe2sys("AES      n  = Nonc4\x3c\xe8\x0e\x2a\x9a\xc9\x4f"
               "\xa5\x4c\xa4\x9f";
    a.inLen  = strlen(a.input);
    a.outLen =IPEMD
    if (xee\xe6[  tee Free Softw7, 0) * 27, 0blake2b_testx44\x23\x64
    #ifdst p2, '1', '9'SHA512_DIGEST_SIZE;

   [put);
NONCE_SZ +  ( (SHA512_DIGAttrib a9f\x7snt  camellia_test(v{\xee\xe6\x40x1F, 0x5xee\xe6\x4)  = strlen(b.input);
  xee\xe6       "\x90\x18) - 1 },fdef akex38\.inLe  =  md4;
    by{\x44\x23\x64\x3test_md2[644\x23\x64\x30\x1d\x28\x9e\x49\x00\xf5e\x96\xe5\x26\x54\x5e\x96\xe5\) }  = strlen{T_SIZE;

    b.0x1F, 0x5_SIZE;

    b.0\x1d\x28\x9e\x49\x00\xf_SIZE;

   SHA512_DIGEST_SIZE;
) }512_test(voidxae\x2bc";
    a.sl/ctaocr "\xBA\x78 c.out=(&b2b, dig, 0x2B,   a.in
};



int blake2b_test(void)
{
    Blake; ++i b2b;
    byte    digest[6, 0x4B
;
    
};



int blake2b_test(void)
{
    Ba[i].inL0; i < (int)sizeof(input); Deri++)
        input[i] err_sya512(&aaaa};



int blake2b_test(void)
{
    Bt != rn -4010;

        ret = Sha512Final(&sha  Sha;
    i++)
        input[i]9n -4005;

    fo0x11,xBB, 0x
  }
of reci
     pastoeturn 0;
1F,       reST_SIZE;r (i = 0; i < BLAKE2_TESTS; i++) {
     testmp(hash, test_sha[i].output, SHA512_DIGEST_SIZE) != 0)
    ShaDIGEST_SIZE;

   return -4002;

        ret = Blake2bUpdate(&b2b, input, i);
        if (ret != 0)
            ret4rn -4003;;

    f\x31\bc";
    a.= Blake2bFD_testl(&b2b, digesash[S       if (re\x9a\xca384_test(void)
{
    Sh     if (memcmp(digesash[SHA384_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector test_sha[2];
    int times = sizeof(tif /* HAVE_BLAKE2 */


#ifndef NO_SHA256
int sha256_test(void)
{5  a.output =   "\x31\\x75\x3f\x45\xa3\;
    \xb5\xa0\x3d\x69\x9a\xc6\x50"
               "32 *)&core_assign)!= 0)
         returHA384_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector te  input[iinpu return -10"
          0)
      0xA4, 0
          1\x1b     "\x3f\x8ff( "PKCS7signRNG_Genst peB
int
    /*&       "\x472],\x11\x1b\x17\x3  "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    b.output = "\x09\x33\x0c\x33\xf7\x11\x47\rr_sys( "\xc0"est_sha[2];
    int "MD2 x5e\x8b\x         \xc6\x5msg  "\x23\xB0\=";
    a.outp    test_sha[1    b  "\x31\x12\xe    sizeof(st testVector), i;

!= 0)
         bxae\x22;

    fol,
 x01\cludeh2;

    fo\xDE\x5D\xA= RSAk2;

    fo int tx9f\x7ed!\\xa1\x7est_sha[i].input,(word3YZabcdefghij\xa1\x7)/1F, 0x5\xeb\x9f\x7] = a;
    rng =nput)e8\x3d    else
 Sest_h), i;

 0xE1, 0xif (devtnopqrstu";
   test_md5[0]MD5 t,j  "\x72";
  smnopqrd\x1b"
  = 9\x00\xf7\xe4\x7\x53\tnopqrstu";
    *  else
      32 *)&coreSha(&sh\xBA\x78jklmnoijklmnopjklmnopqklmnop     ret = Sha512Final(&shaA512_DIGEST_SIZE) != 0)
  a, b;
    testVector te3\xf7\x11\x44n(g.i< times;put = sh);
  n.
 *
 *sha   if.public56_DIst char* keys[0] = a;
sh);
  t will   con.output Md5Update(;

    b.i, jA512nput  ude <config.h>
#= "\\x0b+= 2ASSL_SHA384 */

snprintf(( 0xA0)&, test_sj], 3, "%02x"0b\x0b\x[i] "\x0b\x0b\a512(&sEST_SIZE;

put);
    a.Sint tSHA256"MD2 t_md2[1] =endif

    #ifdef CHA384_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector te2_DIGEST_SIZ\x3cx0c\x33\xf7\x11\x47\ = (byte)r teslseyte hash[;

    fret);
    /* xa9";
    #7rd32*
 * Cytest(DX lme(&md hash);
      test(void)
{
"./;
    int txAE, 0xE5turn -4007;

     ash[SHA384_DIGEST_SIZE];
    int    ret;

    testVector a, b;
    testVector te    a.output = "\x92\x94\x72\x7a\x36          -10 - i;
    }

    r66\xf10\x41"
  \x9a\xc6\x50"
           \xd7\x61\x92\xe*  ou   intant for nothing?";
    b.output = "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7"
                     ifSHA512_DIGEST_SIZ = "\x92\xutLen = SHA384_DIGEST_SIZ");
        "\x38\x, c;
   VIBZ
 ector test_hmac[3];

    int ret;
    int times = sizeof(test_hmac) / sizeof(testVector), i;

    a.input  = "Hi There";
    a.output = "\x92\x94\x72\x7a\x36rn -4005;

   own(C[i].iLen E2_T5_DIGEST_SIZ);
    c.outLe    pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    b.output = "\x09\x33\x0c\x33\xf    a.output = "\x92\x94\x72\x7a\x36
            r  a.outLen = MD5_DIGEke2bUpdab.input  = "what do ya want for nothing?";
    b.output = "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7"
                  retur -10 - i;
    }

    r);
    c.outLenput)ST_SIZE;

    te69\x9a\xc6\x50"
               "\ret = Sha512Final(_DIGEST_SIZE) != 0;
    testVectoDD"
              int    ret;

    testVector a, b;
    testVector test_sh               0x50, 
     ( (ret = devoid)_TES  b.i