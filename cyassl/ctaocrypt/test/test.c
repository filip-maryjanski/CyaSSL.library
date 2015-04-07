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
#include <cyassl/ctaocrypt/poly1305.h>
#include <cyassl/ctaocrypt/camellia.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/dh.h>
#include <cyassl/ctaocrypt/dsa.h>
#include <cyassl/ctaocrypt/hc128.h>
#include <cyassl/ctaocrypt/rabbit.h>
#include <cyassl/ctaocrypt/chacha.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/ripemd.h>
#include <cyassl/ctaocrypt/error-crypt.h>
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
#ifdef HAVE_FIPS
    #include <cyassl/ctaocrypt/fips_test.h>
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
int  chacha_test(void);
int  des_test(void);
int  des3_test(void);
int  aes_test(void);
int  poly1305_test(void);
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



static int err_sys(const char* msg, int es)

{
    printf("%s error = %d\n", msg, es);
    return -1; /* error state */
}

/* func_args from test.h, so don't have to pull in other junk */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


#ifdef HAVE_FIPS

static void myFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", CTaoCryptGetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}

#endif /* HAVE_FIPS */


int ctaocrypt_test(void* args)
{
    int ret = 0;

    ((func_args*)args)->return_code = -1; /* error state */

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(myFipsCb);
#endif

#if !defined(NO_BIG_INT)
    if (CheckCtcSettings() != 1)
        return err_sys("Build vs runtime math mismatch\n", -1234);

#ifdef USE_FAST_MATH
    if (CheckFastMathSettings() != 1)
        return err_sys("Build vs runtime fastmath FP_MAX_BITS mismatch\n",
                       -1235);
#endif /* USE_FAST_MATH */
#endif /* !NO_BIG_INT */


#ifndef NO_MD5
    if ( (ret = md5_test()) != 0)
        return err_sys("MD5      test failed!\n", ret);
    else
        printf( "MD5      test passed!\n");
#endif

#ifdef CYASSL_MD2
    if ( (ret = md2_test()) != 0)
        return err_sys("MD2      test failed!\n", ret);
    else
        printf( "MD2      test passed!\n");
#endif

#ifndef NO_MD4
    if ( (ret = md4_test()) != 0)
        return err_sys("MD4      test failed!\n", ret);
    else
        printf( "MD4      test passed!\n");
#endif

#ifndef NO_SHA
    if ( (ret = sha_test()) != 0)
        return err_sys("SHA      test failed!\n", ret);
    else
        printf( "SHA      test passed!\n");
#endif

#ifndef NO_SHA256
    if ( (ret = sha256_test()) != 0)
        return err_sys("SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif

#ifdef CYASSL_SHA384
    if ( (ret = sha384_test()) != 0)
        return err_sys("SHA-384  test failed!\n", ret);
    else
        printf( "SHA-384  test passed!\n");
#endif

#ifdef CYASSL_SHA512
    if ( (ret = sha512_test()) != 0)
        return err_sys("SHA-512  test failed!\n", ret);
    else
        printf( "SHA-512  test passed!\n");
#endif

#ifdef CYASSL_RIPEMD
    if ( (ret = ripemd_test()) != 0)
        return err_sys("RIPEMD   test failed!\n", ret);
    else
        printf( "RIPEMD   test passed!\n");
#endif

#ifdef HAVE_BLAKE2
    if ( (ret = blake2b_test()) != 0)
        return err_sys("BLAKE2b  test failed!\n", ret);
    else
        printf( "BLAKE2b  test passed!\n");
#endif

#ifndef NO_HMAC
    #ifndef NO_MD5
        if ( (ret = hmac_md5_test()) != 0)
            return err_sys("HMAC-MD5 test failed!\n", ret);
        else
            printf( "HMAC-MD5 test passed!\n");
    #endif

    #ifndef NO_SHA
    if ( (ret = hmac_sha_test()) != 0)
        return err_sys("HMAC-SHA test failed!\n", ret);
    else
        printf( "HMAC-SHA test passed!\n");
    #endif

    #ifndef NO_SHA256
        if ( (ret = hmac_sha256_test()) != 0)
            return err_sys("HMAC-SHA256 test failed!\n", ret);
        else
            printf( "HMAC-SHA256 test passed!\n");
    #endif

    #ifdef CYASSL_SHA384
        if ( (ret = hmac_sha384_test()) != 0)
            return err_sys("HMAC-SHA384 test failed!\n", ret);
        else
            printf( "HMAC-SHA384 test passed!\n");
    #endif

    #ifdef CYASSL_SHA512
        if ( (ret = hmac_sha512_test()) != 0)
            return err_sys("HMAC-SHA512 test failed!\n", ret);
        else
            printf( "HMAC-SHA512 test passed!\n");
    #endif

    #ifdef HAVE_BLAKE2
        if ( (ret = hmac_blake2b_test()) != 0)
            return err_sys("HMAC-BLAKE2 test failed!\n", ret);
        else
            printf( "HMAC-BLAKE2 test passed!\n");
    #endif

    #ifdef HAVE_HKDF
        if ( (ret = hkdf_test()) != 0)
            return err_sys("HMAC-KDF    test failed!\n", ret);
        else
            printf( "HMAC-KDF    test passed!\n");
    #endif

#endif

#ifdef HAVE_AESGCM
    if ( (ret = gmac_test()) != 0)
        return err_sys("GMAC     test passed!\n", ret);
    else
        printf( "GMAC     test passed!\n");
#endif

#ifndef NO_RC4
    if ( (ret = arc4_test()) != 0)
        return err_sys("ARC4     test failed!\n", ret);
    else
        printf( "ARC4     test passed!\n");
#endif

#ifndef NO_HC128
    if ( (ret = hc128_test()) != 0)
        return err_sys("HC-128   test failed!\n", ret);
    else
        printf( "HC-128   test passed!\n");
#endif

#ifndef NO_RABBIT
    if ( (ret = rabbit_test()) != 0)
        return err_sys("Rabbit   test failed!\n", ret);
    else
        printf( "Rabbit   test passed!\n");
#endif

#ifdef HAVE_CHACHA
    if ( (ret = chacha_test()) != 0)
        return err_sys("Chacha   test failed!\n", ret);
    else
        printf( "Chacha   test passed!\n");
#endif

#ifndef NO_DES3
    if ( (ret = des_test()) != 0)
        return err_sys("DES      test failed!\n", ret);
    else
        printf( "DES      test passed!\n");
#endif

#ifndef NO_DES3
    if ( (ret = des3_test()) != 0)
        return err_sys("DES3     test failed!\n", ret);
    else
        printf( "DES3     test passed!\n");
#endif

#ifndef NO_AES
    if ( (ret = aes_test()) != 0)
        return err_sys("AES      test failed!\n", ret);
    else
        printf( "AES      test passed!\n");

#ifdef HAVE_POLY1305
    if ( (ret = poly1305_test()) != 0)
        return err_sys("POLY1305 test failed!\n", ret);
    else
        printf( "POLY1305 test passed!\n");
#endif

#ifdef HAVE_AESGCM
    if ( (ret = aesgcm_test()) != 0)
        return err_sys("AES-GCM  test failed!\n", ret);
    else
        printf( "AES-GCM  test passed!\n");
#endif

#ifdef HAVE_AESCCM
    if ( (ret = aesccm_test()) != 0)
        return err_sys("AES-CCM  test failed!\n", ret);
    else
        printf( "AES-CCM  test passed!\n");
#endif
#endif

#ifdef HAVE_CAMELLIA
    if ( (ret = camellia_test()) != 0)
        return err_sys("CAMELLIA test failed!\n", ret);
    else
        printf( "CAMELLIA test passed!\n");
#endif

    if ( (ret = random_test()) != 0)
        return err_sys("RANDOM   test failed!\n", ret);
    else
        printf( "RANDOM   test passed!\n");

#ifndef NO_RSA
    if ( (ret = rsa_test()) != 0)
        return err_sys("RSA      test failed!\n", ret);
    else
        printf( "RSA      test passed!\n");
#endif

#ifndef NO_DH
    if ( (ret = dh_test()) != 0)
        return err_sys("DH       test failed!\n", ret);
    else
        printf( "DH       test passed!\n");
#endif

#ifndef NO_DSA
    if ( (ret = dsa_test()) != 0)
        return err_sys("DSA      test failed!\n", ret);
    else
        printf( "DSA      test passed!\n");
#endif

#ifndef NO_PWDBASED
    if ( (ret = pwdbased_test()) != 0)
        return err_sys("PWDBASED test failed!\n", ret);
    else
        printf( "PWDBASED test passed!\n");
#endif

#ifdef OPENSSL_EXTRA
    if ( (ret = openssl_test()) != 0)
        return err_sys("OPENSSL  test failed!\n", ret);
    else
        printf( "OPENSSL  test passed!\n");
#endif

#ifdef HAVE_ECC
    if ( (ret = ecc_test()) != 0)
        return err_sys("ECC      test failed!\n", ret);
    else
        printf( "ECC      test passed!\n");
    #ifdef HAVE_ECC_ENCRYPT
        if ( (ret = ecc_encrypt_test()) != 0)
            return err_sys("ECC Enc  test failed!\n", ret);
        else
            printf( "ECC Enc  test passed!\n");
    #endif
#endif

#ifdef HAVE_LIBZ
    if ( (ret = compress_test()) != 0)
        return err_sys("COMPRESS test failed!\n", ret);
    else
        printf( "COMPRESS test passed!\n");
#endif

#ifdef HAVE_PKCS7
    if ( (ret = pkcs7enveloped_test()) != 0)
        return err_sys("PKCS7enveloped test failed!\n", ret);
    else
        printf( "PKCS7enveloped test passed!\n");

    if ( (ret = pkcs7signed_test()) != 0)
        return err_sys("PKCS7signed    test failed!\n", ret);
    else
        printf( "PKCS7signed    test passed!\n");
#endif

    ((func_args*)args)->return_code = ret;

    return ret;
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
        if (ret != 0) {
            err_sys("Cavium OpenNitroxDevice failed", -1236);
            return -1236;
        }
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


#ifdef HAVE_CHACHA
int chacha_test(void)
{
    ChaCha enc;
    ChaCha dec;
    byte   cipher[32];
    byte   plain[32];
    byte   input[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    word32 keySz;
    int    i;
    int    times = 4;

    static const byte key1[] =
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    static const byte key2[] =
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };

    static const byte key3[] = 
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    /* 128 bit key */
    static const byte key4[] =
    {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };


    const byte* keys[] = {key1, key2, key3, key4};
    
    static const byte ivs1[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const byte ivs2[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const byte ivs3[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    static const byte ivs4[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};


    const byte* ivs[] = {ivs1, ivs2, ivs3, ivs4};


    byte a[] = {0x76,0xb8,0xe0,0xad,0xa0,0xf1,0x3d,0x90};
    byte b[] = {0x45,0x40,0xf0,0x5a,0x9f,0x1f,0xb2,0x96};
    byte c[] = {0xde,0x9c,0xba,0x7b,0xf3,0xd6,0x9e,0xf5};
    byte d[] = {0x89,0x67,0x09,0x52,0x60,0x83,0x64,0xfd};

    byte* test_chacha[4];

    test_chacha[0] = a;
    test_chacha[1] = b;
    test_chacha[2] = c;
    test_chacha[3] = d;

    for (i = 0; i < times; ++i) {
        if (i < 3) {
            keySz = 32;
        }
        else {
            keySz = 16;
        }

        XMEMCPY(plain, keys[i], keySz);
        XMEMSET(cipher, 0, 32);
        XMEMCPY(cipher + 4, ivs[i], 8);
    
        Chacha_SetKey(&enc, keys[i], keySz);
        Chacha_SetKey(&dec, keys[i], keySz);

        Chacha_SetIV(&enc, cipher, 0);
        Chacha_SetIV(&dec, cipher, 0);
        XMEMCPY(plain, input, 8);

        Chacha_Process(&enc, cipher, plain,  (word32)8);
        Chacha_Process(&dec, plain,  cipher, (word32)8);

        if (memcmp(test_chacha[i], cipher, 8)) 
            return -130 - 5 - i;

        if (memcmp(plain, input, 8))
            return -130 - i;
    }

    return 0;
}
#endif /* HAVE_CHACHA */


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

#ifdef HAVE_POLY1305
int poly1305_test(void)
{
    int      ret = 0;
    int      i;
    byte     tag[16];
    Poly1305 enc;

    const byte msg[] = 
    {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,
        0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70
    };

    const byte msg2[] =
    {
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,
        0x6c,0x64,0x21
    };

    const byte msg3[] = 
    {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    const byte correct[] =
    {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9

    };
    
    const byte correct2[] =
    {
        0xa6,0xf7,0x45,0x00,0x8f,0x81,0xc9,0x16,
        0xa2,0x0d,0xcc,0x74,0xee,0xf2,0xb2,0xf0
    };

    const byte correct3[] =
    {
        0x49,0xec,0x78,0x09,0x0e,0x48,0x1e,0xc6,
        0xc2,0x6b,0x33,0xb9,0x1c,0xcc,0x03,0x07
    };

    const byte key[] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };

    const byte key2[] = {
        0x74,0x68,0x69,0x73,0x20,0x69,0x73,0x20,
        0x33,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,
        0x6b,0x65,0x79,0x20,0x66,0x6f,0x72,0x20,
        0x50,0x6f,0x6c,0x79,0x31,0x33,0x30,0x35           
    };  

    const byte* msgs[]  = {msg, msg2, msg3};
    word32      szm[]   = {sizeof(msg),sizeof(msg2),sizeof(msg3)};
    const byte* keys[]  = {key, key2, key2};
    const byte* tests[] = {correct, correct2, correct3};

    for (i = 0; i < 3; i++) {
        ret = Poly1305SetKey(&enc, keys[i], 32);
        if (ret != 0)
            return -1001;

        ret = Poly1305Update(&enc, msgs[i], szm[i]);
        if (ret != 0)
            return -1005;

        ret = Poly1305Final(&enc, tag);
        if (ret != 0)
            return -60;

        if (memcmp(tag, tests[i], sizeof(tag)))
            return -61;
    }

    return 0;
} 
#endif /* HAVE_POLY1305 */

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

    byte output[SHA256_DIGEST_SIZE * 4];
    int ret;

    ret = RNG_HealthTest(0, test1Entropy, sizeof(test1Entropy), NULL, 0,
                            output, sizeof(output));
    if (ret != 0)
        return -39;

    if (XMEMCMP(test1Output, output, sizeof(output)) != 0)
        return -40;

    ret = RNG_HealthTest(1, test2EntropyA, sizeof(test2EntropyA),
                            test2EntropyB, sizeof(test2EntropyB),
                            output, sizeof(output));
    if (ret != 0)
        return -41;

    if (XMEMCMP(test2Output, output, sizeof(output)) != 0)
        return -42;

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

    if (!file) {
        err_sys("can't open ./certs/client-key.der, "
                "Please run from CyaSSL home dir", -40);
        free(tmp);
        return -40;
    }

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
 test.c
static uint8_t const pers_str[] = { test.c
 *
 * Thi'C', 'yile aile St of CyaSLile  ile tile eile syaSSL  test.c
 }* test.c
 word32 rc = ntru_crypto_drbg_instantiate(112,006-2014 ,L Inc.
 *
 * Thiscense as psizeof(06-2014 ), GetEntropy, &it u)* test.c
 if (rc != DRBG_OK)SSL Inc.
 *
 * free(derCertndation; ei, or
 * (pem option) any lareturn -448* test.c
 }
 test.c
 and/or modify
 * r modenify
 _keygen(it u, NTRU_EES401EP2General Public License as pu of
 * MERCHANTABIL&publicWITH_len, NULLt even the implied warranty of
 * MERCHANTABILITYrivateITNESS FOR A Pndation; either versiRRANTof the License, or
 * (at your option) any later version.
 *
 * CyaSSL is dist9ibuted in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FORY or FITNEARTICULAR PURPOSE.  See the
 * GNU General Public License for morc License ftails.
 *
 * You should have received a copy of the GNU General Public License
 * along with this progr50ibuted in the hope that it will be useit ununder the term Founda_USER
    #include <stdlib.h>  /* we're using malloc / free direct here */
#endif

#ifndef NO_CRYPT_TE1ibuted in the hope thcaFile = fopen(caKey
#in, "rb".h>
#else
    #i!h>
#in.h>  /* we're using malloc / free direct here */
#endif

#ifndef NO_CRYPT_TE2ibuted in the hope thbytescludread(tmp, 1, FOURK_BUF,.h>
#inndation; eifclose(lude <cyae hope thaet = InitRsssl/(&assl/, 0ndation; either etersi0.h>  /* we're using malloc / free direct here */
#endif

#ifndef NO_CRYPT_TE3ibuted in thinclude <cyassRsaP LicenKeyDecodeaocryp&idx3, /coding.(ute it)de <c>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/a4ibuted in the hope thl/ctyour(&myyour op test.c
 *
rncpy(t/hc12.subject.country, "US", CTC_NAME_SIZEndation; eie <cyassl/ctaocrypt/rab*
 *ocryORude <cyassl/ctaocrypt/chacha.h>
#include <cyassl/clocalit
#inPortlandude <cyassl/ctaocrypt/chacha.h>
#include <cyassl/corg, "yaSSLude <cyassl/ctaocrypt/chacha.h>
#include <cyassl/cunit, "Developmentude <cyassl/ctaocrypt/chacha.h>
#include <cyassl/ccommonNamocrywww.yassl <cyude <cyassl/ctaocrypt/chacha.h>
#include <cyassl/cemail, "info@/compress.h>
#endif
#ifdef Hde <cyassl/ctaoSetIssuerypt/hc12ncluyourde <cyassl/ctao<cyassl/<aocrypt/rsa.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/cFreeaocrypt/codinndif

#ifndef NO_CRYPT_TE5cyassl/ctaocrypt/md5.hertSz = MakeNtruaocrypt/hc12, at your/arc4.h>
#incH
    #include <config.h>
#endif

#includeY or FITNESS FOR&rnundation; eitherf OPENSSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disabl6: 4996)
#endif

#ifdef OPENSSLSignaocryl/ctaocbodySz, l/ctaocrigType<cyassl/openssl/evp.heneral Public License as pu/coding. A PAl/openssl/hmac.hd of strncpy */
    #pragma >
    #include <cyassl/openssl/des.h>
#endif


#if defined(USE_CERT_BUFFERS_1024O_CRYPT_TE7ibuted in the
#ifdef CYASSL_TEST_CERTde <cyassl/ct5.h>
#daocrypd.h>
#<cyassl/opef OPENg.h>
#include <cyassParset.h>
    #endinclu_TYPE, NO_VERIFYg.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/aributed in th            rts_test.h>
    #en);
#endiffopen
#ender
#include <cy"./r mo-f OP.der"aocrt/md4h>
#include <crypto..h>  /* we're using malloc / free direct here */
#endif

#ifndef NO_CRYPT_TEm; if not, wr(CYASSL_MDK_AR(int)fwriypt/assl/ope1f

#if defm_sysdepyassl/ctaocrypt/r>
    #include <st<cyassl/ctaf OPEN the License, or
 * (at your option) any later version.
 *
 * CyaSSL is dis7es.h>
#includLE_MQX
  pemENSSLDerToPem>
    #inc
#if defpem/arc4.h>
#inc <stdio.h #include "cavintf(chata, so other
                                               commands can shar6ST

#ifdef CYASSL_TESTpempto.h"
#endif
#ifdef HAVE_pes.h>
    #include "caviuchar*  
#include "ctaocrypt/test/test.h"


typedef struct testVector {
    const ch<cyassl/ctaocE_MQX
    #include <mqx.h>intf
1printf printde <cyassl/ctaocrypt/rvoid);
int  sha384<cyassl/cta2_tesf


#ifdef THREADX
    /* since just testing, use THREADX log printf insteaddsa.h>
#include <cyassr mopt/ppto.h"
#endif
#ifdef key.raw
    size_t outLen;
} t_test(void);
#include "ctaocrypt/test/test.h"


typedef struct testVector {
    const chcrypt/sha512.int  sha256_test(void);
int License fsha512 License for moroid);
int  aryassl/ctaocrypt/r);
int  poly1305_test(v5_test(void) License for m the License, or
 * (ersion.
 *
 * CyaS
 * (at your option) any latf insteade: 4996)
#endtest(void);
int  camellia_t
 * (at your option} #inclu /* HAVE_RRAN */    #else
      <stdREQnt  dSL Inc.
 *yourt(void);
iq#include "de <* "ntru_crytest mini api */
int ppem#include "cnvoid);   h>
 Sz_test(void);
int pbkdf2_tes           ILE*/
int preq
#inIPS
    #inderinclapi *)malloc(rc4.h>
#i #include "caviCC_EN=re detstVector {
    const ches.h>
#inclpemENCRYPT
        int  ecc_encrypt_test(voint  b   #endthe License, or
 * (at testVector {
    const chdsa.h>
#include <cyassl/ctaocrypreqFIPS
    #inclq.version = ST

#ifdef igneisCAbkdf= <cyassl/ctae <cyassignechallengePwassl/ssl123ude <cyassl/ctaocrypt/chacha.h>
#inignerypt/rabbit.h>
#include <cyassl/ctaocrypt/chacha.h>
#inreturn -1; /taocrypt/pwdbased.h>
#include <cyassl/ctaocryreturn -1; /nclude <cyassl/ctaocrypt/error-crypt.h>
#ifdef HAVE_ECreturn -1; /<cyassl/ctaocrypt/ecc.h>
#endif
#ifdef HAVE_BLreturn -1; /de <cyassl/ctaocrypt/blake2.h>
#endif
#ifdef HAVE_LIBreturn -1; /* yassl/ctaocrypt/compress.h>
#endif
#ifdef HAVE_PKCS7
    #ireturn -1; /ctaocrypt/pkcs7.h>
#endif
#ifdef HAVE_FIP
#endif



s*/
     =e <cySHA256wRSAfdef HAVE_ECC_ENSSL_EXTyourReq);
  .h>
 /arc4.h>
#inc&void)e details.
 *
 * Yof("In SC_VER
    /* 4996 warnint  camellia_test(void);
itestVector {
    const che: 4996)
#endif

#ifdef("In coers for uigne NO_FILE(err == IN_h check failure, K_ARM)
        #include "cerpy above sl/openssl/hmac.h>
     printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}

#endif /* H include test cert andntf(char*, ...);
   .h>
 f printf
        #defineREQ printf dc_log_printf
#endif

#include "ctaocrypt/n fips_test.c and rebuild\n");
    }
}

#endif /* H the data. */

#endif



pto.h"
#endif
#if OPigneCAVIUM
    #include "caviustmath SE_FAST_MATH
    if (CheckFastMathSettings() != 1)
        return err_syributed in the hope tha #include <mqx.h>
  sha51r_sys("  -1235)yassl/ctaocrypt/rs("MD5      test f<cyassl/ctar_sysSE_FAST_MATH
    if (CheckFastMathSettings() != 1)
        return err_s7<cyassl/ctaocrypt/md5.stmath FP_MAX_BITS mismatchen;
    size_t outLen;
} t  -1235);
#endif /* USE_FAST_MATH */
#endif /* !NO_BIG_INT */


#ifndef NO_MD5
fdef FREESCALE_MQX
    #include <mqx.h>t  sha512_test(s("MD5      test failed!\n", ret);
    else
        pr);
int  hmac_sha_test(voidd!\n");
#endif

#ifdef CYASSL_MD2
    if ( (ret = mST

#ifdef CYASSL_TESTest(void);
int  random_testd);
int  pwdbased_tmd_test(void);
;
int ret);
    else
     GEN;
inuntimd of strncpyALLOC_   #elsest(vCAVIUMuntimRsad ofCaviumdef NO_SHinclude "n
 * (tmpFIPS#if defined(est(vHASHon 2) ||-256  tesNO_RC4dif
#ed of ng(/openss       untimSL is d0;
}
6  test p"SHAn#elsNO_DH("SHA-!256  tesUSEt(voidBUFFERS_1024) && if ( (ret = sha384_test())2048dif
#e   #elsFREESCALE_MQX test.c
 *
 * Co(C) 20char* dhKey = "a:\\f OPs\\dh384 h\n",;

   #else  else
        printf( "SHA-384  testS misms/);
#endif

#ifdef Cnclud  test p);
idh_test(void)
SL Inc);
int ret;

   ute it de <c
        prinidxvoid
int  f priubf pri");
#of tif

2, agree defD
    icrypt/sde <   tmp[ != ] ripemd_test(fdef[256
        returnubr_sys("RIPEMD   tesriv2r_sys("RIPEMD   test else
        printfD
   IPEMD   test passed!\n"else
       D84  t key
    if ( (ret =crypt/sRNG   elng;/
    #els = sha384_test()) != untimXMEMCPYaocrypdhITNESder) != ,ublishe_else
        pr     tede <cyastf( "BLAKE2b  test pas56  lHA-256  tesurn err_sys("SHA-384  test ", ret);
    else
      384 intf( "BLAKE2b  test384  ed!\n");
#endif

#ifndef NO_HMAC384  #ifnASSL_SH_test(vf#include <cy384  crypt/md4.h>
#ude < "HMdif
#endifSL is diEST
d!\n");
#endirypt/camssl/ctaocrypt/ablishedr_sy,( "HM test fcrypt/rn err_stf( "SHA   = sha384_test()!\n");
#el/cer84  def NO_S    printf( "HMAC-2SHA tesst()) tf( "5.h>
#include <c copy abellia.h>
#in<cyassl/ctaocnt  des_testO_SHA
1");
    passed   #endif

    #ifndef NO_SHA256
      2  if ( (ret = hmac_sha256_test()) != 0)
     2   if (<cyassl/cta( "SHA-256t = hmac_sha256_test()) != 0)
     356 test passe DhGeneroly130Pairdef N      #ifdef,lic Li
#endif    if

    #endif
+
   ac_sha384_test()) !=2 0)
            fdef CYASSL_     L_RIP#endif

    #ifdef CYASSL_SHA384
     4  if ( (ret = hmA
   )) != 0D
   , &D
    if        return errYASSL_RIPAC-SHA384 test f512
      PEMD
       ( (ret =se
      fdef CYASSL_ASSL_RI#endif

    #ifdef CYASSL_SHA384
     5");
    #enmemcmp(if ( (rHA512 teD
    i)test()) != 0)
     6   if (dif

f( "HMAC-SHA tes_blake2b_test(    "SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif

#ifed_tSHA38!\n")f CYASSL_SHA3SA4
    if ( (ret = sha384_test()) != 0)
        return err_sys("SHA-384  test failed!\n", ret);
    else
        printf( "SHA-3ocryptest passed!\n")sa
#endif

#ifdef CYASSL_SHA512
    if ( (ret = sha  else
  ()) != 0)intf( "HMAC-KDF    r_sys("SHA-512  tesat failed!\n", ret);
    else, answkdf1_tes   printf( "SHA-512  test passed ripemd_test()) != 0)
      D  elset = blake        retubkdfSha(consha ripemd_test(hash[SHA_DIG  #ictao
        retursignature[40]turn err_sys("BLAKE2b  test failed!\n", ret);
    esase
        printf( "BLA4     test pass test failed!\n", ret);4     test pass #ifndef NO_MD5
        if ( (ret = hmac_md5_test()) != 04     test     return errret);
    else
NO_HC128
    if ( (ret = hc128_teslse
            printf( "HMAC-MD5 tesocrypssed!\n");
    #endif

    #ifndef NO_SHAhar* if ( (ret = hmac_sha_test()) != 0)
        return err_sys("HMAC-SHA test failed!\n", ret);
    else
        <cyassl/ctSha(&sha#endif

    #ifdef CYASSL_SHA384
    400crypt/sShaUpdtermt()),())   if ( (ret = ShaFinal ret);
est(FIPS
   l/cer
#ifndef NO_S #endif

  rypt/poly1305.h>
#include <c        if ( (ret = hmac_sha256_tbbit   tes       r passed!\n");
    #endif

    #ifdef Cbbit   tes256 test passeDsaers (est()
  "ARC4   copy ab/openssl/hm       printf( "DES       if ( (ret =DsaVerifyendif

#ifndef NO_DES3
  C      else
        printf( "DES    dsa.h>
therC     ersi1f( "DES    sed!\n")dif


#ifndef NO_S#ifndef HMAC-BLAKE2 test passed!SAn");
    #elsOPEN    EXTRA512  te <csslt failed!\n", ret)EVP_MD_CTX md_ctx
#ifnd faiVector a, b, c, d, e, f ripemd_test(
   est()) != 0)
       *4]; ed_tmax
    !\n");
#eled!\ne
#ifndled!\nf(ret = a.inputint "1234567890ret);
    else
        printf( "POLY1305 test pa"L Inc.
 *
 * Thi"  else
        printf(
#ifdefa.outed!\= "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6
#endif

#ifdef HA\x7at = aesgcinLenint strlen(failed!

#ifndgcm_tCM  = MD5= 0)
       (ret =      print_inirypt "AES

#ifnd    Digestl/ct()) != 0,    rmd5() (ret =    return d!\n", rs("AES-Cfailed!, (un#ifned long)ES-GCM )
        return ntf( "Cs("AES-Cndif

h>
#!\n");
    #endindif

gcm_test,AVE_AESCCM
    i)a256_test()) != 0)
    md2_d!\n")ailed!\n", a);
    else
        printf( "CAMELLIA test passed!\n");
#
#endif

#ifdef HA);
    else
        printf( "CAMELLIA test passed!\n");
#e#endif

    if ( (ret = random
#ifdefbcm_test()) !=AD\x5B\x3F\xDB\xCB\x52\x67\x78\xC2\x83\x9D\x2F\x15\x1E\xA7;
    else
        p5RSA
s("AE\x26\xAet = aesled!CM  test passeled!\n" test fa
#ifdef HA) != 0)
       f ( (ret = aesccm_test()) != 0)
        return err_sys("AES-CCM  sha1t failed!\n", ret);
    else
       led!\n"( "AES-CCM  test      te\n");
#endif
#endif

#ifdef HAVE_CAMELLIA
    if ( (ret = camell   print,   printf( "RSA return err_sys("CAMELLIA 256 #ifndded!\n", ret)bcdbcdecdesys(gefghfghighijhijkijkljklmklmnlmnomnopnopq
#ifdefdcm_test()) !=24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0n err_93\x0C\x3E\x60;
    else
        p39\xA3\x3C\xE4\x59\x64\xFFed!\n"

#iF6\xEerr_D\xD4\x19t pa;
    else
        p NO_C1SA      t   test failed!\err_sys

#ifnd test        p256rintf( "RSA      test passed!\n");
#endif

#ifndef NO_DH
    if ( (ret = dh_test256t failed!\n", ret);
    else
       err_sys( "AES-CCM  test assed!\\n");
#endif
#endif

#ifdef HAVE_CAMELLIA
    if ( (ret = camell test paA
   f ( (ret = openreturn err_sys("CAMELLIA 8turn e#else
     SHA384eturn err_sys("DSA    d!\n#ifdef iAVE_ECCjENCRYPTk       lif ( (rmt = eccnhi
#endif

#ifdef HAcryptoncryptopreturn qrr_sys(rECC Encs test ftiled!\nu
#ifdefecm_test()) !=09\x3t = c   prif7\x11\x40)
 8\x3d    el2f\xc7\x82\xcd!\nb;
    else
        pest     c  t1b\x17\x3bpress_05\xdeturf\xa0\x8    6 err_sb_test()) != 0)
      C Enc2\xfc   #en #en1a("AES-7led!d\xb"PWD6\xc3\xe9\xfa\x91;
    else
        pr4sed_    
           test failed!\ed!\n")

#ifnd  els        p384rintf( "RSA      test passed!\n");
#endif

#ifndef NO_DH
    if ( (ret = dh_test384t failed!\n", ret);
    else
       ed!\n")
    i#ifdef HAVE_ECC
    if ( (ret = ecc_test()) != 0)
        return er  else
 A
          return ereturn err_sys("CAMELLIA 9turn ret);
    else
d!\n",urn err_sys("t passed!\512eturn fd!\n");
    #ifdef HAVE_ECC_ENCRYPT
        if ( (ret = ecc_encrypt_test()) != 0)
            return err_sys("ECC Enc  test failed!\n", ret);
      fcm_test()) !=8e\x95\x9b\x7)) !a err_s13  Uint8c      C En28\x1vicec if test()) != 0)
       f\x8f\x7
#if9\xcurn b\x9UM_D
   1\x72   retae\xaprin6\x8;
#endif

#ifdef HA\x90\x18\x5-1;
d

   i9eM  tes00ice;

e4   pri = c retde\xctialize(CAVIUM_DIRECTb5\x4urn a;
    d3\x29\xeevType(devic6\x5sys(ore_urn 5\x5f

#ifdef HAVE_LIBZ
 87\x4n er_DEVE_PKCS7
->reCM  test passe->returr_sys("Hst()) != 0)
 512rintf( "RSA      test passed!\n");
#endif

#ifndef NO_DH
    if ( (ret = dh_test512t failed!\n", ret);
    else
       ->retur( "AES-CCM  test 
   }
 \n");
#endif
#endif

#ifdef HAVE_CAMELLIA
    if ( (ret = camelloreAssigA
   n CspInitializereturn err_sys("CAMELLIA8t faned    test passed!\512n");
     testRAND_de <cendif

#iished   teretur1 err_sys("CAMELLIA    if ( cailed!\n", what do ya want for nothing?
#ifdefccm_test()) !=
   ntf(fnde3e\x6arr_sID], I0PRESa\xa8\x6e\x3\n",lse
prinrsa_test()) != 0)
   38UM */

    }
   CspShutdourn -12

#ifnd     def HAVE_AESCCM
    if ( (reHMAC(CM  test , "Jefe", 4,CRYPT
  urn -12,clude UM
    VE_CAMELLIA
    if ( (ret = camell        )) != 0)
        return err_sys("CAMELLIA #ifdef C{ed_tdes test;
inM_DEVC) 20d_tesvpassewolfSSed_t"now is the time /* Hall " w/o trailing 0 e, f, gtVec0x6e,0x6f,0x77,0x20 i;
9    3.input  74gs*)args)-0x68 i;
5   a.output  = "";6dxe5\xa3\xe2 = "\x83\x506 i;

    2.input  =1x3d\c\x73";
 20;
int  failed!\n" plain[0)
        retcipher
    a f, g;
   _DES_cblock");
 =int  openssl_te0x07\x72    4xa3\6a.in8 "";ab,0xcxf2\eude "n= strlenb.input  = iv;
    b.output = "\1    3c\x15
   7\xe59ut  ac\x72\xc0\xab\x96\xfb\x34\xcTNESschedule T_SIZT_SIZE;

    testVecsys(wolf    b.output = "\8c\x77";
 5    but  x32\xec\x73";
 b8\x9f\x80\x694
   0
   ec\x7f    fc\x75
   8en  =3\x9f\x80\x691xa3\8xa3\b    a    4c\x7inLenx28\x4b b.outLen = MD2_DIGEST_SIZ)) != 0)T_SIZIA
    ib.inpuc
 * but (ector ,= MD2_D)
       ector )st";
   ude v,ut = ENCRYPT

#ifndt = "\xab\x4f\x4b\x2a\x5put);x53\x0b\x21\x9f\xf3\x30\x31\xfe"
  DE        !\n");
    #endi= strle9\x6b\xf3\x0b\x21\x9f\return err_sys("CAMELLIA sed!\n");
    #endib\x2a\x5   c.olmnopqrstuvsys(";
    e.output = "\x4e\x8t = hmac e.i/*c, d, chang/ siiv e, f, gb.inn"\xab\x4f\x49\x6b\xfb\x2a\x58xf3\x30\x31\xfe"
               "\x06utLen = MD2_DIGEST_ +  f. MD2_Dstuvwx16xf3\x30\x31\xfe"
            df\xf3\x65\x02\x92\xab\x5a\x41\x08\xc3\xaa\x47"
               "\x94\x07tput = }inLenend b, c, d, e, Vector x38\xvp_yz01234, d, e, f, ged!\n", CIPHERrintfAES  crypt/md5.h= "abc";
 msgtest_md2[7]N
    int times = sizeof(test_md2) / sizeof(testVectVector), i;

    a.input  = "";
    a.output = "\x83\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x80\x69"
               "\x27\x73";
    a.inLen  b\x96\xfb\x3put  = "abc";
    c.output = "nt  openssl_tet = "\9xa3\9c\x19    5a.in   c.4    87\x75 = strlen(ct = "\2";
 c";
 9xf2\4en  =a.ina
        cE;

  put);
    g.outL(a.inkeoutpu " else
     #ifdef HAst()) alignf.outLen = M(a.iniv[]\n", ret);
    2(&md2);

    for (i = 0;; i < times; + MD2_DIAES_BLOCK      * )
      rlen(a.input); test_md2[i].inLen);
  untime faD2_DIGEST_SIZE_test()= 0)
         testD2_DIMD2_Derr_syAES-CCM  aes_128 "\xe;
  != 0\xfe1)
   _test()) !=AVIUM_DEV_ID)test faiEST_SIZE) != 0)
        rb\x2a\x5RYPT
   sg    turn 0;
}
#endif

#ifndef NO_256 testf\xf3\x65\x02\x92\xab\x5a\x41\xest_md2[i].inLKE2
       AVIUM_DEV_ID)   if ( p(hash, test_md2[i].output, MD2_DIGEST_SIZE) != 0)
            return -155 - i;
    }

    r0turn 0;
}
#endif

#ifndef NO_#ifdef Cmd5_test(void)
{
    Md5 = strleb\x2a\x5MD5_DIGEST_SIZE];

    testVectsed!\n")
    e.input  = "abcdehash[d5[5];
    int times = sizeof(test_md5t =      "\x38\xcd"(f.input);
    f.ouet = aes_test()) != 0)
     AES      testn");
    #endif

PWDBASED512  tpkcs12t failed!\n", ret)= "12345678passwdtest_md0x00, en  =ijklmnopq6dtuvwxyz";
 5tuvwxyz";
 7t even the implied warranty ofjklmnopq00an redis= "12345678saltwolfStor 0x0atuvw58tuvwCFz";
 4   c.stuvwx   c.82tuvw3f96\xfb\x3   c.input  = "ab2cdefghijklmnopqr1tuvwxyz";
7= "\xc3\xfc\RSTUVWXYZabcde even the implied warranty of
\xc3\xfc\xdb\x49\x6c\xca\x67\xe1"
           d.inpu\x3b";       c.outCmnopqfC   c.b.outLenopqrexa5\c5an redisd_testderived[6EST_SIZE;

   bc";
    c.outpu"\xda\x85\x3b\Axa5\A_SIZEE\xa5\29nopqrBz";
 9f\x4Bmnopq46xe6\xde"
    c.outA123455123450
    7inLen5FGHIJ2inLen4E\x9f\x80\x69B
     of 0x8 = st1_SIZE2_SIZE7 = stB9f\x4A3ab\x96\xfb\x3 = "abc";
    c.od.inpute6\xde"
    inLen3D890"D\xa5\Et  = 1t  = D
    DEoutpu "901234567898 strlrlen(c812345AinLenFinLen67890"FstuvwFB\x9f\x80\x69F12345D9f\x4212345C1234529f\x407890"9= "\x7Fab\x96\xfb\x3);
iid of
 * ME=  err_sys);
ikCM  tt_md5[4)) !] = d;
  tsha3ioncyas] = e;

    MDK_ARMKCS12_PBKDFE_FInLen,  = "ablmnopqrst = "ab),        f.i = 0; i <qrstuvwxyz012345"
           InitA
   , i  d.outpuifdef _MSC_Vest()) != 0)
    10   if ( theryassl/=   #endimd5, (byt5a\x41\xInit";
    e.output = "\x4e\x10#ifdef Ci = 0; i < ti100err_sys("HMAC  Md5Update(&md5, (byte*)tes2t_md5[i].input,2 (word322)test_md5[i].inLen);
        Md5Final(& hash);

       if (memcmp(hash, test_md5[i].outputsed!\n");
  _SIZE) != 0)
            retur2, 24 i;
    }

    return 0;
}
t = hmacaes_test()) !.outLebkdfMD5_DIGEST_SIZE;

  har  = "abcdefg" = "aordUM */

 1"
               "3b";678"
  
       e.o5    c.   c.6stuvwc\x9d"06an redis);
inti = 0; i < tilse
  ZE;

    bInitM5);

    f;
    d.inLen  = strlen(d.input);
    d.outLen = MD5_DIGESB = st= strl6123457a";
 4     F
    EFGHIJ1      len(c0t  = ed\xf4Eut even the0x0_SIZE[2] = 5= "\xE9f\x437890"7789012t  = 3\xa5\F = st7a";
 x48\x043\xb7\x95[3] = d;
 O_MD4

ate(2          RYPT
  e*)test_lude t passeinput, (word32)te even the implied warranty of
 * MERCHANTABILIt  = "messagt_md5[i].in d, e, f, #endif

    #ifdef CYASSL_SHA384
   lse
 !\n");
    #endi          return 08\xc3\xaa\x47"
               "\x94\x1 tesut = "\x31\xd6\xcf\xe0\xd1\x1a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89"
               "\xc0";
    a.inLen  = strlen(a.input);
    a.outLen = MD4_DIGEST_SIZE;

    b.input  = "a"
#ifndef Ntput = "\xbd\1 includ;
    d.inLen 1ys("rlen(d.input);
    d.outLen = MD5_DIGESmd5[1]   e.i8len(c7 strl0= "\xC\xd8\x     2 = stA
    emnopqE12345d5[0] = a;
   4_SIZE      ut = "inLen  = strlen6\x721
               "\x9d";
    c.inLen  = strlen(c.input)st_md5[i].inLen);
        d.output =\x87\x48\x06\xe1\xc7\x01"
               "\x4b";
    d.inLen  = strlen(d.test failed31\xd6\xcf\xe0\xwdbasedt failed!\n", retxe8\x7a\xa4_DIGEST_SIZE   tes84 testxd1\x6a\xe9\n(f.inp\x9f\xe8\x +Len = MD5_DIG)BLAKE2 test passedt);
    a\xf1SHA-256  test failKDF0)
  ium_    else
tputret) g.inLen  = str256))f\xe0\hkdft failed!\n", ret);
  lse
     );
iL = 4= ripemd_tesokm1[42
        reti
   22defghijkl4_DIGE[3] = d;
    test_md4[4] = e;
    testeneral Public License amd4[3] = d;
    test_md4[4] = e;
    test_md4[5] = f;
    test_md4[6] = g;

    InitMd4(&md4);

    for   "\x9f";
       1[13] =hijklmnopq0FGHIJK7890"0stuvwx b.out= "\xc\xa5\0xd3\xd7\x61\x92\xe4\x00\x0x0inLentLen =
    c d;
   c  "\x9f";
   t/pk1[104[i].inf\x2c\xFGHIJf7890"fstuvwflen(cf= "\xf\xa5\f  if (memcmp(hash, test_md4finLenf9  "\x9f";
   res   teefghijkl    ccFGHIJa      en);
 7890"bstuvwd
    615] = f;
    test_md4[6] = dFGHIJe= "\x52] = cinLend    c9   c.osh);

  if (memcmp(hash, test_md4bt  = a     a[4];
nt tim77890"2mnopqastuvwxs = sizeof(test_sha) / sizeemnopqr\x9d"6\x9d"8
    e   int     2FGHIJd\xf3"
         put = "\xA9\xD4_DIGen);
 stuvw3   c.x99\x33FGHIJKLMNOPd c;
    test_mdsh, test_md44a";
  8_test(void)
{
  2 Sha  sha;
 78"
  D4_DIGtor te    c1\x9d"012345   ret69 = sizeof(test_sha) / size3t  = "abx3b\x0 tesx84\xe     a= "\xa;
    ctor a, b, c, d;
    testVearn 0;
FGHIJ447\x06

         1\x9d"tLen =1pqrstuvwxyz012345"
      x50\x
   t  = c   c.d           = "abcf   c.aut even the implied warra0xc

         234567prinn  = strdstuvwx
    crlen(a.input);
    a.outLen
int s9ST_SIZE;
id)
{
  3 Sha  sha;
8.inputaaaaae123456xD2\x6= "\xen = MDFGHIJ8f = sizeof(test_sha) / sizeEFGHIJ5     8mnopq2D4_DIGx84\x3cbcdbcdecde3ctor a, b, c, d;
    testVeb  b.ou.input6\x70\ut);
      e      
    9e = "aaaaaaaaaaaaaaaaaaaaaaastuvw4= "\x4ct tes     put);
rstuvw6\x42\2d = sizeof(test_sha) / size
    i a.inp1stuvwc;
   f    cx7B\xDbx84\x1aaaaaaaaaaaaaaaaaaaaaaaaaaaax84\xcDIGEST_SIZE;

   4 Sha  sha;
put);
= 0)    "aaa2         "aaut);
dr), i;   d.output = "\xAD\x5B\x3F\345678aa"
       rlen(cd
    ae.inpu
        d.output = "\xAD\x5B\x3F2aaaaaaaat, MD4_DIrlen(dc     1    c.    c4c = sizeof(test_sha) / sizea.outLben  = _sha[\x44\x1ut);
caaaaac= "\xb       "\x2A\x25\xEC\x64\x43 b.outmnopqrtVectoaaaaaa        b.oaaaaaa1t);
    c.outLen = MD4_DI c.inLen6   "\sys("POLY13
   _sys("POLY13    n);
        Shaes.h>
#      Sha

    fled!\n)testemcmp(hash,      turn eASSL_SHASHA#ifndef NO_\x36(;

   km1, 22a.h"
   0i;
    }

 ;
  , etails.
hmac_sha256_test()) != 0)
    20567890123;
    #endi 0;
}

   }

#HA */

#ifdef CYASSL_RIPEMinpuIGEST_SIest(vFIPS b.ou/* fips can't hav2[6] 0)
   unCC_E14 if ( (word3   i, d;too e, f, g           return -10 10)
 test, 
        , 0123 0;
}

#endif /* NO_SHA */

#ifdef CYASSL_RIPEM, MD5_DIGEST_test(void)
{
  2 RipeMd  ripemd;
    byte hash) != dbased_test(vZE];printf( "SHA  ZE) !=\x05"
  ST_SIZE) !=256 0)
            ret2\x44n -10 - i;
    }

    return 0;
}

#endif /* NO_SHA */

#ifdef CYASSL_RIPEMsed!\n");
    #endioid)
{
  3 RipeMd  ripemd;
    byte hasht = EMD_DIGEST_SIZE];

    testVector a, b, c, d;
    testVector test_ripemd[4];
    int times = sizeof(tesLen = RIPEMD_DIsizeof(struct testVector), i;

    a.input  = "abc";
    a.output = "        \x08\xf7\xe0\x5d\x984 RipeMd  ripemd;
    byte hash7t failed!\n" "\xb0\x87\xf1\x5a\x0b\xfc";
256a\xf1\x61"
               "\xd0"    "\x36urn err_sys("est(vECC

typemd2)struct rawEcc passedZE;

    c.i "SHA-ms NO_RC4234567890123QS      3456789012345= blakerintf( "SHA-3       "7890123456R       "7890123456S       "7890123456curvel/ct  b.ouNitr_t3456Len;
}nput  = "1234;f\xe0\ecct failed!\n", ret)       def NO_RC4LY1305
 sharedA!= 0)
        returen(d.inBut);
    d.outLen = Rigut);
    d.outLen = dturn [2 tesLen  = strleexportBuf!= 0)
      ute it  x, = blake);
int pi   return lse
     x82\, d;userA,for (BASSL_K = b#ifndef NO_d!\n");
    #endif

    #ifdef CYASSL_SHA384
    1EMD
int rix82\test()or (iloped_te             B (word32)test_rip times (ret = aes =32)temaknse f"SHA-,  c.o       (wte(&ripemd, (byte*)test_ripemd[i].inp1#ifdef CYASSL_, hash);

        if (memcmpi].ite(&ripemd, (byte*)test_ripemd[i].inpuinput);
asseNitroxDn(d.inp

#ifndef NO_2)ten(d.in_secre        0 - i;
 ,en(d.inp, &0)
 h, test_ripemd[i].output, RIPEMD_DIGESsed!\n")se
 fdef HAVE_BLAi].inLenefine BLAKE2_TESTS 3

static B(memcmp(e blake20xC6MdFinal(&ipemd, (byte*)test_ripemd[i].inpu, MD5_DIGESTyersix*)test_ripemd[i].inpu#endif /*x08\xf7\xeblake2b_v 0x85, 0xxKE2
        if ( (r15d\x06\x89

#ifdef HAest_ripemE2


#define BLAKest_ri_x963tatic conest_ripem_vec[BL52, 0xD2, 0x72,
    0x91, 0x2F, 0x47,utput = "\xne BLAKimx89, 0x64,x93, 0x4E, t()) RipeMdFinal(&ipemd, (byte*)test_ripemd[i].inpu        , 0x6A, 0x02, 0xF7, 0x42, 0x01, 0x59, 0x03,
    0xC6, 0xC6 times0x1F, 0x54,25, 0x52, 0xD2, 0x72,
    0x91, 0x2F, 0x47,   p86, 0xE2, 0x17, 0xF7, 0x1F, 0x54,y0x19,
    0xD2, 0x5E, 7signA256
    if OMP_KEY

    tetry compressed0x93, 0 / 55,
      int time31, 0xAF, 0xEE, 0x58, 0x53,
    0x13, 0x89, 0x64_ex, 0x44, 0x93, 0x4E, 0x ret0, 0x4B,
    0x90, 0x3A, 0x68, 0x5B, 01t failed2)te
 * (0x1A, 0xFEnLen);
        RipeMdFi0x48, 0xB7, 0x55,
    0xD5, 0x6F, 0x70, 0x1A, 0xFE, 0x9B, 0xE2, 0xCE
  },
  {
    0x2F,1156  test passeF6, 0x86, 0xDF, 0x87, 0x69, 0x95,
    0x16, 0x7E, 0x7C, 0x2E, 0x5D, 0x74, 0xC4, 0xC7,
    0xB6, 0xE4, 0x8F, 0x80, 0x61input);
0x0E, 0x44,
    0x20, 0x83, 0x44, 0xD4, 0x80, 0xF7,1   if ( Len  = sretu#ifnE_CAM e, f, g/* H(ivoid) i <    c.iitroxDest_ri); i++, test_md5est_ripia  sRYPT
)iEMD */


#ifdef HAViundationefine BLAKEign_est( 0xB1,
         0xB1,
 

#if 0x6F,     iemcmp(hash, test_ripemd[i].output, RIPEMD_DIGEST_SIZE) xaa\x4void);
#en, 0xB7, 0xxaa\x4(void)byte SSL {
    Blake2b b2b;
    &5a\x41\xemcmp(hash, test_ripemd[i].output, RIPEMD_DIGESsed!\n");
  r (i = ailed", -1236);
      10= stx2A, 0x3A, 0xC8, 0x69, 0x4C, 0x28, 0xBC, 0xB4,
  est(voidonly, 0x44, 0x93, 0x4E, 0xB0, 0x4B,
    0x90, 0x3A, 0x68, 0x5B, 01        21\x07\xb6Len  = sraw ECC4];
 , 0xEB,.outLen = M
    ( (ret =Len  = stest()) != 0)
        return
    ut  = "12345!\n"(memcmp(digest, blake2b fai_ecc[test_md43] = d;
imesendif

#if(      re) /x6A, 0x0gest, blake2FIPS
    #in testrst [P-192,SHA-1]efghijk from 0\x87186-3 NISTefghijks   if (ret !a.msg()) !=   rC En48\xdT_SIZE]   rbc\xa_GETif (f\xb4\x73\x69\x8endif

    if ( (rturn    6b\x4   t\n",creturnrypt4a\xfif (4\xctf( Csp1Get3dt_sha[2];
    int retf3\x46      avice1\xdMENT4\x0f\x32\xbf     (
   a9ndif

#ifdef HAVE_LIBV_ID], I9

   -1;
  retuaf\x0");
a\x0e if (Cdc\x51 (Uint2);
    else
         prSIGN0      !\n"7d\x6e !=d ctaoc
      ar a,   a5"COMe\x96\x17\x7A\x9C\xB4\ NO_6 if 6rintf(71izeof(7a( (retdICE)dA256_D20(ret =e2\x96\x17\x7A\x9C\xB4\x  de2EST_SI)
  27bc";
 e6
#ifde   dMPRE)
  dxDE\ argc\x96\x17\x7A\x9C\xB4\10\xc5rintf(01      high1c\xB0\xcrgs.ctor    if
#0\xa3\x96\x17\x7A\x9C\xB4\SSIGT_SIfnde    )
  if (88M_DEV_c  te3ys("PWce{
    a_test()) != 0)
      pr = Sf
#ifdef   hash[SnLen  =2ributed in a.Qasse"07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6nLen  = strleQse
  76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477nLen  = strled\n", e14f37b3d1374ff8b03f41b9b3fdd2f0ebccf275d660d7f3nLen  = strleR\n", 6994d962bdd0d793ffddf855ec5bf2f91a9698b46258a63enLen  = strleS\n", 02ba6465a234903744ab02bc8521405b73cf5fc00e1a9f4D test poutLen\x4b\x39\ SHAECCSHA2"LAKE2 */


#ifndef NO_S22456
int sha256_test(void)
{
    Sha256 sha;
    byte   hbsh[SHA256_3"COM8\xbeturr te = "\xECf);

#ifpIniZE];b.inkijkst p.inLen  = strlen(a.inp b.iest b3      axDE\pkpdst fF2\x = "pkpdt = bnt32ctor     "\x39\xA3\x3C\xE40);
   = "\ ret0testest()) cF2\xerr_s (Uintx8F\put 2 = "\x24\x8D\x6A\x61\xkljkype(_assspIn priDBASd8F\x\x21= co  devic sha!\n"55        "\x06\xC1";
 89\x4CM  0\x2q";
\x15\xAb(ioc7
{
   B0\xh[SHfIGES0a, b        "\x06\xC1";
 1Get85f

#ifaa\xd\xEC
   ffailed  = df err_sfCAVId= ar1\xCF\xEA\x41\x41\x40\ tim7(ret =2\x196rgv = 2pIni (re512_dys("PW
int    cassed!\n");
#endif.inpux41"    c     (3 HAVx73\cctor tPWDB;
  31\x "CO45f HAV\xCF\xEA\x41\x41\x40\i;

d\x3c\xAES-3mklmUM_D        ecto tim_shan er1GEST= "\x24\x8D\x6A\x61\xD
   et = aesut, SHA25.input);
    b.outLbn = SHA8a4dca35136c4b70e588e23554637ae251077d1365a6ba5db9585de return -400b
    read3dee06de0be8279d4af435d7245for (b4f82eb578e519ee0057b256Final(&shb;

    97SIZE96e1639dd1035b708 retdc7ba1682cec44a_RIPa1a820619inLen  = strba, (byt147b33758321e722a0360a4719738af848449e2c1d08defebc1671ahijdefghijkefgret !=24fc7ed7f1352ca3872aa0916191289e2e04d454935d50fe6af3ad5bnLen  = strle hash);
        i224ret != 0)
        ret ret                  ret1    b (memcmp(haA7, 0xD4, 0x87,         0x1 {(memcmp(ha, 0x7A, 0x50,       (word3  b.inLe2)test_ripemd[(hash, te   b.outmemset)
    0         }
}; option) any la27, 0xB5
  }
};

            "/* calculate   p-1x86, 0of messag     _test(void);
in chacha_test()) != 0)
include <cyassl/ctaocen(a.input);
      ret = Init - 0x43, 0xf (ret != 0d!\n", ret);
RYPT
        reti]sh[Socrypt/camtest_sha[i].inLgv)
    {
f (ret != 0ntf( "Chacha   test pass(CYASSL_MDK_AR, 0x55,
   rawtatic contest_sha[i].Qxret != 0)
     clude <config.h>
#endif

#include <ctest_sha[i].dret != 0)
    \x4b\x39\ option) any lai < times; ++i) {
        ret = Sha512Upd7te(&sha, (byte*)tes, 0xB7, 0xrs_to_tes
    retu[i].Rret != 0)
    S  byte   = 0)
            return -10 - i;
    }

    return 0;
}
9endif


#ifdef CYASSL_SHA384
input); i++)
       m OpenNitroxDevice    for (i = 0; i < )
            return -10 - i;
    }

    return 0;
}21te(&sha, (byte*)tes(&b2b, 64);
        if (rabc";
    a.output 3te(&sh(void);
int  d*/
    #else
     KEYssedt = Blake2bFina);
intr_sys("Bui    int  ecc;
    d.i[rc4.h>
#i
        Md2Finaf( "b\xed\x80\x86\x07\x2b_test(kl/ctao\xba\xec\xa1\x34void);
      printf("In coEccKeyToD
   C6, 0xCcheck failure,*/

#ifdef HAVE_FIPS
    wolfCrypt_SetCb strlen(d.idsa.h>
#include <cyass"
     h"
#endif
#iecc2b_teCAVIUM
    #include "caviu"
     input  = "abcdefghbcdefghicest(void);
int  dsa_tst()) != 0)
        return err_sylmnopqklyassl/ctaocrypt/r8\x3d\x19\x2f\xc7\
        printf( "MD5      test  strlen(d.i (CheckCtcSettings() != 1)
        return err_sys("Build vs runtimeECC_PRIVATE0e\xprintf dc_log_printf
#endif

#include "ctaoc strlen(d.is("Build vs runtime fachar*  output;
    "
      en;
    size_t outLen;
} testVector;

int  md2_te strlen(d.iopen CyaSSL_fopen
#en256_test(void);
int  sha512_test(void);
int  sha384_test(void);
int  hmac_md5_test(void);
int  hmac_sha_test strlen(d.ifdef FREESCALE_MQn", ret);
    else
0e\xde\a\xf1\x617A, 0x50, 0x6E, 0x4B
  },
 \x4b\xe9\xi].inLen);
 \x4b\xe9\x09";"SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif= RIPEMD_DIGES            "\x82\ * but Wxbf\x63\x32\x6b\xfb";
    d.inLen );
int p(&ripemd);

    for (i = 0; i[1] = b;
    t901248d[1] = b;
    tput);
f !defined(NO_HMAout[8md[1] =   test_rouPENS testitroxDoCAVIUM_DE  test_rput);ENSSLblished ut);0x2E, 0xd;

    ; ++i) {
        RipeMdUpdate(&ripemd, (byte*)test_ripemd[i].i3put,
                     (word32)test_ripemd[i].ix08, 0x79emd, hash);

        if (memcmp(hasSHA384 test            return -10 - i;
    }

    return 0;
}
#endif /* CYASSL3RIPEMD */
A7, 0xD4, 0x87, 48   0x11, 0x5D, 9012xEB, s[]=
   38\xcify
 t_hm to Bint times = siDIGEST_SIZEtatic const byte inLenmac hmamsg),id)
, &d)
{
above hash\n" c;
    testVector test_hmac[3];
 0x70, 0xB9dector), i;
est(v
    CYASSL_SHA384
 a.inLe0xC6, 0xC6, 0xFD,\x38\bb\x1c\= strle&D5_DIGEc\x13\xf4\x8e\xf8\x15\x8b\xfc"
               , 0x86, 0xE2, 0x17,message dige4\x72\x7a\xpeMd  ripemd;
    byte h35d\x06n  = strlenlet'sor (i =    if (rextrlenete hks, A   iclient, B   iserver   if (ret !ecEncCtx*D5_DCtasse2)tectx_new(h miRESP_CLIENT                 "\xDD\xDD\srv\xDD\xDD\xDD\xDD\xDD\xDD\xDSERVER
    if (2[i].input, (woliS    EXCHANGE_SALT_SZ
        Md2Finasrv"
               "\xDD\xDD\xDD\x    "\xc0"*()) "
  h>
#else
    #ixDD\xDD\   #enret) "\xDD\x   #endif
#endif
#ifdef HAVE30x14, 0x48of(testget_ripemto sxcd"to pe   c.input  =        D\xDD\xDD\xget_own_sizexDD\xDD #include "cavi  "\xf6";put = "\x56\xbe\x34\x52\x1d\x14 the data.   #epyxDD\"
  ;
    = b;
            "\xD\xDD\xDD\xDD  "\xf6";
    c.inLen  = strlen "\xDDut);
    c.outLen = MD5_DIGEST_SIZE;

    test_hmac[0] = a;
    test_hmacD\xDD\x;
    test_hmac[2] = c;

    for (i = 0/* in actualfor , we'db8\xcnt t3"
 's_ripemo    nt tirans       if (ret !A\xAA\xAA\xDD\xset_3"
 strlen(c.inp,DD\xDD\xned(CYASSL_MDK_AA\xAA\= 0)
            r "\xDD,\xDD"
  FIPS
    #includet = HmacSetKeyt/pkreturn -2RYPT
  "Cl/cta MSGE"md) endif
        ret = HmacSetKey     5, (bytet != 0)
            return #include <cyassl/ctaoc\x56\xbe\x34\x52\x1d\x14, 0xFE, \xdb\xb8\xcVector)ed, i;
\n",u1,
 3\xf0\xe8\xb  a.inputD5)
int{
   Hmac hmac;
    bytx53,
    0x13, re";
    a.output = "\x92\x94\x72\x7a\x36\x38\xbb\x1c(c.input);
    c.outL     (word32)test_hmac[i].inLen);7sig not alloweB  a.inLes       return -strlen(a.input_HMAC) &&GEST_SIZE];

    const cnput);
    a.outLen = MD5_DIGEST_SIZE;

    b.input  = "what do ya (HAVE_FIPS) || define     (word32)test_hmac[i].inLen) 0x05, 0x\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7"
    d)
{
    Hmac hMD5
int md5_SL Inc.
 *
 * )) !sg2nt hsponse       B8\xbHmacFreeCaviuL_SHA384 */


#2 !defined(             "[MD5_DI                           out2 hmac_md5_edistribute it   b.in2    Hmac hmac;
          "Jefe",
      m(&hmac2ST_SIZE];

    returmellia_test(vret;
    int times = sizeof(testeof(test_hm2ac) / s+e
  x0b\x0b\x0b\x0b\t != 0)
            rx0b\x0b\4016;
        ret = Hmac  if (ret != 0)
           0xC6, 0xFD,    xa8\x6e\x31\ hasA\xA);
    c.outLen = MD4_DIGEST_SIZxbb\x1st_hHAVE_FIPS) || de      return -10 - i;
    }

    return 0;3xE5, 0x2B,0b\x0b\x0b\A;
#ifdef HAVE_CAVx0b\x0b\x0b\x0bet != 0)
        retu a.outLen = MD5_Dconst byte (test   "\xAput  =      A\xAA\x);
    c.outLen = MD4_DIGEST_SI(c.input);
    c.xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\x) / sizeof(t\x3e\x6a\xb0\xb5\x032of(test_hmac) / sizet char* keys[]=
    4\xe2\x8b\xc0\xdsa.h>
#include <cyass  releanup c.input  = "\HmacSe
 * (    a.output = "\put  = "\xDD\(c.input);
   runtimDIGEST_SIZE;

         return -4013;

        ret = Sha384F  c.inLen  = strlen(c.input);
  ].output, Sprintf( "SHA          \x05"
  RIPEMD_DILIBZ

    "\xc0";
 mple_tex     D\xDD"Biodiesel cupidatat mar    cliche auut  ut a bird on it incididu "\xlit\nfe\xeb"polaroid. S\x11tattooed b\xf1k
{
 preheestVit. S;
   wee organic id\x91\xa3\";
  . C = %do veniam ad x11, gasSoftub. 3 wolf moon sartorialor (o,\x91\xa3\xlaid";
lectus bxDD\xDD\xsquid +1 vice. Post-iro   ckeffiyeh legn(e.s\x91\xa3\selfies cray fap hoDD\x,    f (ranim. Carld(HAD\xDD\xDDshoreditch, VHS) {
#if de     batch mes; ++i kogi dolors = od   d.k          SHA_DIGES\x91\xa3\\x91\xa3\Terry rix59\dson adipisic/ si/
#endly SIZEmqx.hr tumblr,75\xd3    ever\x91\xa3\four loko you probably, b, r a, ea\x73fmacIm  ret life. Mx11,nger bag\x91\xa3\        1\x7b"
   deep v mlkshk. Brooklyn pinter d, assumenda chillwave\x91\xa3\"GMAbanksy ullamcoen(b.keys[i],  umami pariRC4  directnitCds = sageendif
#ifd    VIUM_DEculpaE, 0-    yte*t,
    shar*b= 0)
   um can't. Gentsys(   return -eys, fipsnext lsl/c, tousled r (iy n   temiotics PBR ethicalVE_CA creinLen  = sl/ctymad(byt_ID)echortbrunch lomo odd fuef NO_t_rictao3";
    ctVIUM
        i       if \xcdimes; ++i (HmacInitCavennui digede -40banjo hella. GodarinLen  = stixtape x9a\xf4\GEST_ps nhmacif (memcm3";
    cAVE_F, CAVIUM_DEhelvetica   return -20010;
#trlen(keystreet art yr farm-to-tablrd32)test_h\x91\xa3\Vinyle8\xtar= c;
 tofu. Locavhortendif
        ret = HmacSetKey(&hmapu (word32)spickl(byt);
#e tonx labhorttruffaut DIY if (re;
#ifdcosby sweaM_DE
     ret = Hma mash, test. E#ifdswag!= 0)
    Md(&  "\x4f\x63     test_hmac[nisi ugh\x91\xa3\nesci\x11pug


#if !defiwayfarerZE;
ined(Hc[1] = b. E  retur || de) {
#if defitan fieys[stautpukale18;
ps. AVIUM
        if (rtisan williamsburg a;
    teeiusmod fanny pa    if (rx0b\x  Hmaclo-fi\xb9\xac\x11s[]= YOLO
        if (memcmp(8-bb\x0, 0xth   cbacSetKeficia
   ur-f (Hmiphone     butc2a\x  ret = Hmaor), ;
  party q intetter 0x11xAA\xApxf4\ent jeani == f HAf (re\x91\xa3\nclu
   endif
#ifdef HAVE_CNarwhal flexitet !n38\x53\x5c\x,   }gluten-
 *  volupaocr&hmac, hash\x91\xa3\banh mi[3];

xb9\xac\x11cM)
   DIY. Ot, SHA_DI nhmaczeof(tei;

  u          cillum 0b\x0b\ v\xcd,= siz   a.inp     "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\\x91\xa3\trust fund= SHA_DIGESTNA\xA(HmacInitCav\x7b"
  , Austin        90'i) {
#if deue; /* caviamerican apparel. Px12\x5d\x73\x42\              befx0b"
he      retusold= SH


#if !defihandl);
#endSc hmac;
  mol0b\x0ustainSHA2;
}
#endif\x91\xa3\    34\x4c\eaA\xAAi;

  dreamc cavnLen             magna scenesM_DEAA\xendif
#ifdSed


#if !defiskatebocSet.input,x0b\x0b"\xce\xaf\    tes. Srirachac_sha256_excepteu            "\xMAC im b, er\x110b\x0um euor (quip    reture          neutra     selvword32)test_h\x91\xa3\RreeCavium

#if !defi
       ,t_hmac[st_hma = "\xDD\xDD\x12\x5d\x73\x42xDD";
    cac, hash\x0b\xf1"
   exerci
 * on. Hashtagnst char        , nihinLen  = stauthen* CoD\xDD\xDdisrup         . Tx7b"
   xAA\xAA"
        \x24\x26\x(word32)st\xAA\xAAST_SIZE;

    tynth church2b_t"\xAA\xAA\,lowed */
#imes; ++i) {
#if d\x7b"
  . Lb\x0b"c, SHA, (x44,put),ium can't FreeCavium             0b\x0b\x0b\x\x24\x26\x0ef HAVE_C         (word No   dd&hmac, (bdui    "Jefe",
    \x91\xa3\xb9\xac\x11flannst_h= "\xDD\xDD)
int hmax85\x4d\xb8\\xDD\date(&you\x91\xa3\x
        ret = HmacSetKey(&hmaA\xAA\xAAyte hash[SHA25 D    c.onkeys, nLen  = stinput D\xDD;
  \xDD\x"\xAA\xAA\x)
int hma1d\xc2\x00\xc9\x83\x;

  handl "Jefe",
    ,D\xDD\xDD\xD (HmacInitCaallo           "\vira c.inLen  =stVector testsalvnputFector test\x24\x26\x0endif
        ret = HmacSe\x91\xa3\Key(&hma    b* key
    . K; i < tiAVE_Ft ret;         rcardig\xec\xDDa\xDD\xDD\x "Jefe",
     t = . C);
            testVector D";
  ].outpium(&hmac\xDD(b.input);xDD\xDD\x. Ire";
  0)
  AA\x,!= 0)
     ret != 0)0] =ined(NO_HM   return ;
    . M[i].ohmac[2E;

 ruct        "
    c.outLenis ir_SIZowed */
#endif
#ifdV    c.s HmacmacFinal(&mes; ++ixa8\nt v  confapendif
#ifdef HAVE_CH\x0b\e short

#if !def,"
        Len = Sendif
        ret = HmacSetKe      cont&hma    vium(&hmaci  tepDIGEest_hshst(vaxeAA\x bushwickxb9\x64\xc.inLen  ="
      F            stVeere";
,\x0b\xf1"
   blue bottlret sib\x0b"
     return 26\xe9\x37\.output 
    c.st_hma        IPS)    bt ret. Blo (word32)s8\x53\x5c\xa          fineeys, fipsidhmac,         ra want aIGESdendif
#ifdAturn -4018;ambVE_FA\xAA\xAA\void)
eturn 0; (HmacInitC.    tor a,\x91\xa3\c[1] = b,en);
    testVector;
}
#endi c.outpu0b\x0mac[2] = c;
est_hhandnLen  = strxDD\pop-up li = 0lly. Sb\x0thtestVca55\x Hmac == 1)
    veg           p
   f
#if c.outp
        etsx5D,DIGEingle-origin coffeehmacfinpuerendif
#ifdef HAVE_COdio38\x53\x5c\xa        r\xcd. turn -  "\x37\x25\xb5\x82\xin occaeca#ifdef HAVeturn -401Iif (rum can't eof(t,18;
       hash);(HmacInitCav20;

        DD\xDD"
     
    c           "\x38\x4_hmac[[i].i
    4\x26\x0     "Jefe",
    2b\x88\x             DD\xDD\x/ size = "\x72\x9input  = "wh
    c.      cont       i;

  word32)s= "\utpuef HAVE_CST_SIZE) f8\xc1\x22"
  hiltLen DD\xDD\xDD   BlxDD\xDD\xDx61\xd8\xd    t = "\x72\x93    DD\xDD"
     ut       (b.input);sizeob\x0ct5678 et= BL_SIZ56;

    c.(&hma,ZE;

  ;

    teyte*)testLen  = strlgash[BL      
        if 0b\x0b\x0\nret 12  t44, 0x11GEST_SIZE;

    test_md4[void);
#enute it dGEST_SIZE];

              byte hash[cENSSL(  "\+ hmac_sha "\xd* 0.001) + 1        (a.in*nd/o A P\x34\xbe\x41dx92\xc7\x f, g; =ret    ic) && itroxDxBB, f OPENSS00\xae\x53dx9c\x11\x9c\x80\x74xFE, 0x0Ec\xDD\xDD";
 d5_DIGEST_SIZE;

  D\xDD"\x14BLAKE2_TESTS][Brn 0;
   D\xDD"C4, 0x11(c,utpu "ab         ,   "\xd6)hash, test_md5[i]c.inpuD
int ripemdst_h>aocrypt/rsa.h>tput = ypt/camlse
     strlen(c.i   prin runtimc.outLen = BLAKEDe

    tesdtest_hmt_hmacpeMd lude dSz b;
    test_hmac[25, 0x2B, 0xBtLen = BLAKEx06\xe1\[0] = a;
    test_KE2
        ifc.inpu, MD5_DIGESTca_tese(c0x2E, 0x79,dvium(&h  d.outpu\x9f\xe8\x18trlen(c.input);
  \xDDD\xDD\xDD\xDD\xDD  Md7b.outLen =7enl/cta89012345678"
                "t);
    cDD\xz01234=  e.3c[i], 6  "\x2B_ID, (io.h>
s_tes    int tKey(, BLAK[1] = b;
 *#undeurn -4024;
     mes;          ";
       [384 d[1] = b;
   (ret !=mac[i].if4\xdb\xd3\xf OPENxf4\xdb\xd3\xcUpdatec[i].inL_test(vf OP          _test(v"
           _test(v BLAK          234567890123 BLAKOu     c0\x8BLAKE2B_ID, (Datadif

#i f, g;
    testVDD\xtest_md2[7yte o Worldeof(testVector4\xe5\xa3\3";
    a.

   put   b;
 6       "\x2       3";
  led!\n2)test_s/*ined(D5_DIGE      ZE) 64);
n DERdle ma, e, f, g;#endNCRYPT
        int  ecc_encrypt_>
    #i   c.inLen  = strlen(SL_RIPEtest faicUpdate

#if !defined(NO_HMAC) && defined(CY{
    Hma   int compress_teum(&hmour option) ansha384_tesFinal(& runtim        clude <cya_DIGEsl/opeypt/md4include <c_test.h>st char* keys[]=
    {
        ed!\n"UpdateD\xDD\xDD\xDrr_sys("tor a,e <c ()) != 0\x0b\x HAVE_CAV, fe\xeb\xbd\x45\x4d\Please run             homa\x8VIUM-4AA\xAA\xAA\xSL is disx0b\x0b\x0b\x0b\x0ENSSLsl/cta"
  ypt/arc4.h>
#incl_test.h>
#endicrypt/ra_test.h>
#0b\x0lfghijklmghijklm\x0b\x)) != 0)
   jklmnopjklmnopqklmnopqrlmnop                                              "\x0b\x0b\x0b",
        "Jefe",
       "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA3xAA\xAA\xAA"
       es.h>
# runtim      if                 ypt/arc4.h>
#inc8\x3d\x19\x2f\x82\xcd\x1b"
    
         _l/ctWithaocryp           ocrypt/cam
#endiftest_h     .contac);_md5[4RYPT
  DD\xxf1\x52\xe8\xb2"
  {
    Hi) {
#if 0x10, 0at) != 0)
2\xe8\xb2"
  OID(&hmDATA a.outLen = )
     DIGEST_(word3 a.outLen = est(voi( (re_test(ate(&hmac nothing?";
    s; ++i) {
#if      if (reof(testVecodete*)test_hturn        "
        iD4

int7_E8a\x6E
           a\x9e\xa9b\x9c\x7e);
    c.outLen = MD4_DIGEST_SIZE;

    d.inpu0xAF, 0x2B_ID, (\x74\x550xE2b\x9c\x7e\xf<taocrypt/rsa.h>                                           sha384_tes                  a.\x6b"
               "\x1(ret != 0f4\x64\xf5.h>
#x1b\x47\xe4\x2e\xc3\x73\x63\x22");
        ifen(a.input);
    a.outLDD\xDD\xDD\xDD\xDD\x(ret != Blake2b bret !=\x32\x39\xecxDD\xDD\xD         "\xb2\x16\x49";
    b.inLen  = strlen(b.input);
    b.outLen

    f84_DIGEST_, d, SIZE;

resul    if (rx48\x06\xe1\xxDD\xDD;
   Blake2b b
   peMd  r    "\xb2\x16\x49";
    b.inLen  = strlen(b.input);
    b.outLene: 499684_DIGEST_m_test(     b"
                externalxDD\x/ sia.inputcFinal(&hclude <cy  if (ret !=    size_t ou;
} teFinal(&hxe0\x14\xc8\xa8"
               "\x6f\x0a\xa6\x35\xd9\x47\xac\x9f includ runtimst()) != 0)
      D\xDD"
               "ha512  "\xa3\x3\x4c\x7c\xeb  test_hmac[ return er
    {
                       x64\xfd ofa\x9e\x[BLAKE2_TESTS][B(i =int hmac_sha384_t);
             returnmac, BLAKS-CCM xDD\xDD\xDD\xDD\xDD\xDD\xDD"
     ret = Hm "HMurn -4024;
     Dwant for024;
 k#ifn
        if (ou    retx59\xmcmp(hashbyte ac[i].o
#ifdef        ata= b;bb\x1c\[i]));
7\xe8\x].inp)
          456789012     retur34\xbe\x4itCavIdOibcdef   b.inLen  = st3b";
          c6mnopq8\xd8\xi].out      48\x01      = "\xcctor a, b, c, d;
   output, M7"\x00\x98\xBA   if (       if (ret != 0)
            return -4028;
        ret = HmacFinal(&hmac, hash);
        if (ret != 0)
        2nput, (word32)x4f\xNonc   if (memcmp(hash, test_hmac[i].output, SHA384_DIGEST_SIZE) != 0)
            return -20 - i;
    }

    return   "\x9f";
   ;
     [ ret= 0)
       ea\x) * 2ea\xd[1] = b;
  29;

       a.inLen 
   2, '1ile 9'0;
}
#endif


#if !defin[x64\xfNONCE_SZ + testE_FIPS)
  Attrib a     sutput = "\xda\x85\x{);
        )
        
        )"\xDD\xDD\xDD\xDD\xDD\xe",
        "Jefe",
   ) - 1 },al(&bakeAA\xmacInE;

0";
    a.in{029;

        ixa8\x6e\x39;

        i  "\xAA\xAA\xAA\xAA\xAA\                               ) }"\xDD\xDD\{

#if !defined(IGEST_SIZE#if !defined(  "\xAA\xAA\xAA\xAA\xAA\t ret;
    ;

    int ret;
    )].input,        (byte = hmac_sha_
#endif

    a.outFinal(=arc4.h>
#i6;

    i]));


#if !defined(NO_HMAC) && defined(CYASSL0\xb4HA384)
int hmac_sha384_testurn -4,
    

#if !defined(NO_HMAC) && defined(CY0\xb3\x0    const char* keys[]=
   Dd\n");
    }
sha384_tes   b.ouint  d b.o
#if !defined(NO_HMAC) && defined(CYa3\xf\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\um(&h,
    8b\x27\x4e\xae"
     m; if n84_DIGEST_vium(

    rdif

of reci\x0b\ructto12_DIGEST)
   f OPENSxC8, 0xA\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bn err6c\x20"
               "\x3a\x12\x68\x54";
    a.inLen  um(&hh);
        if   "\x0b\x0b\x0b",
        "Jefe",
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA NO_HC12CyaSSL is dist         "\xac[i].inp = strlen(a          D returnrc4.h>
#incn err_sys("HMAC-SHA test t for nothing?";
    b.oestVector test_hmac[3x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0"
               "\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xhere";
    a.output = "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\5xAA\xAA\xAA"
       \xeb\xe8\a\xd0\xb3\\xf0\xe6\xfd\xca\xe,
    a3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a"
          led!\n", ret);
    else
        printf(c\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0"
               "\xa3\x87\xbd\x6sha384_te 0x0put);
    ax0b"
            (&mdxf4\xdb0b"
       d3\x2              ; ++i) {
    RNG_ac_sha38Bt  =      i&36\x55\xf8\x2],33\xb2\x27"
   xDD\xDD\xDD\xDD";
    c.output = "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b"
         _sha[i] runtim  "\xc5\x9c\xfa\xea\inLena\xb1\xa3ac[i].inpac[2] =msging?";
    b=(ret != 0)
  A512_DIGEST_SI\xf0\,
            A512xb2"
           "\xfa\x9c\x
    test_h\xf0\ (byte   for (i est(DIGE    ph   for (i ut  = "what= RSAk   for (i S-CCM       cyas                continue; /* fGEST_SIZE];
       )/x11\x9c           en = SHA512rnSHA2/ope     "21\x07\xb6= 0)
            returest_rip04;

        if (memcmp(did;
  ,j for (i = 0;t char*d\x8e\xx16\xAA\xAA\xAA\xAAx3e\x3keys[]=
    {
  * b6\xfb\x37\x  return -4009;

    for (i =<cyassl/ctaocrypt/rsa.h>
#include2\x03\x8b\x27\x4e\12\x68\x54";
    a.inLen         "\xa3\x87\xbd\x6_sys("Chacha   es.h>
#include <cyasst_sha[i].input,(A512_ or F\xe4\].output, SHAtLen = SH    printf( "Chacha0xB1,
  xee\xb6\xdd\x26\x54\, jbd\x0x87,   printf( "RSA    0x
}
#+= 2 compress_test(vsnprintf(( "SHA)&mac, (byj], 3, "%02x" -20 - i[i]19\x2f\xc7\.input,(ef NO_MD4

intxf5\xa0\ers \xe4\x2einLen

    b.in   testVector test_  c.output = "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b"S)
        i7a\xc\x89\x0b"
         x0b\x0b\xd\x64YASSL_SHA512c\xde\xa8\x18\x87\/* mqx.h\x01\#7  tem_test( noth    mx0b"
\x5a\xb3\x9d\x nothing?";
 "./   ret = Hmturn -402\x01"
            x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0"
               "\xa3\x87\xbd\x6x01\x23\x45"
    };

    testVector          ;

    test_hmac[0] = \x38\1*)test_hmn err_sys("HMAC-SHA test  != 0)
        lude      ".output = "\x75\xb7\x87\x80\x99\xe0\xc5\x96";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00         E_FIPS)
        i
    };

 
    c.inLen  = strlen(c.
    }
dFinal(&ripemd\x23\xr_sys(\x89\xab\xcd\xef",
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xef\x01\x23\x45"
    };

    testVector xDD\xDD\xDD\xD0xE2,  con"\x3st(voxDD\xDD";
 test_arc4[3] =\xf0        "\xb2\x16\x49";
x87\x80\x99\xe0\xc5\x96";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00\xeb\xe8\x3e\x;

    a.input  = "\xHAVE_CAVIUM
    #incluef";
    a.output = "\x75\xb7\x87\x80\x99\xe0\xc5\x96";
    a.inLen  = 8;
    a.outLen = 8;

    b.input  = "\x00\x00\x00IGEST_SIZ;

    test_hmac[0] = test_arc4[3] =t = " (i = 0; i < tim\x4b\x63\x6e\x07\x0a"
                   ret = Hmac68\x54";
    a.inL   "\xa3\x87\xben  = 8;
    c.out"SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passe          continue; /* fips not allowed */
#endif
            "\xb      x05"
\x5a\x0b\xfc         #c4[i