/* cyassl.h
 *
 * MorphOS version copyright (C) 2015 Filip "widelec" Maryjanski
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

#ifndef LIBRARIES_CYASSL_H
#define LIBRARIES_CYASSL_H

typedef struct CYASSL          CYASSL;          
typedef struct CYASSL_SESSION  CYASSL_SESSION;
typedef struct CYASSL_METHOD   CYASSL_METHOD;
typedef struct CYASSL_CTX      CYASSL_CTX;

typedef struct CYASSL_X509       CYASSL_X509;
typedef struct CYASSL_X509_NAME  CYASSL_X509_NAME;
typedef struct CYASSL_X509_CHAIN CYASSL_X509_CHAIN;

typedef struct CYASSL_CERT_MANAGER CYASSL_CERT_MANAGER;
typedef struct CYASSL_SOCKADDR     CYASSL_SOCKADDR;

/* redeclare guard */
#define CYASSL_TYPES_DEFINED


typedef struct CYASSL_RSA            CYASSL_RSA;
typedef struct CYASSL_DSA            CYASSL_DSA;
typedef struct CYASSL_CIPHER         CYASSL_CIPHER;
typedef struct CYASSL_X509_LOOKUP    CYASSL_X509_LOOKUP;
typedef struct CYASSL_X509_LOOKUP_METHOD CYASSL_X509_LOOKUP_METHOD;
typedef struct CYASSL_X509_CRL       CYASSL_X509_CRL;
typedef struct CYASSL_BIO            CYASSL_BIO;
typedef struct CYASSL_BIO_METHOD     CYASSL_BIO_METHOD;
typedef struct CYASSL_X509_EXTENSION CYASSL_X509_EXTENSION;
typedef struct CYASSL_ASN1_TIME      CYASSL_ASN1_TIME;
typedef struct CYASSL_ASN1_INTEGER   CYASSL_ASN1_INTEGER;
typedef struct CYASSL_ASN1_OBJECT    CYASSL_ASN1_OBJECT;
typedef struct CYASSL_ASN1_STRING    CYASSL_ASN1_STRING;
typedef struct CYASSL_dynlock_value  CYASSL_dynlock_value;

#define CYASSL_ASN1_UTCTIME CYASSL_ASN1_TIME

typedef struct CYASSL_EVP_PKEY {
    int type;         /* openssh dereference */
    int save_type;    /* openssh dereference */
    int pkey_sz;
    union {
        char* ptr;
    } pkey;
    #ifdef HAVE_ECC
        int pkey_curve;
    #endif
} CYASSL_EVP_PKEY;

typedef struct CYASSL_MD4_CTX {
    int buffer[32];      /* big enough to hold, check size in Init */
} CYASSL_MD4_CTX;


typedef struct CYASSL_COMP_METHOD {
    int type;            /* stunnel dereference */
} CYASSL_COMP_METHOD;


typedef struct CYASSL_X509_STORE {
    int                  cache;          /* stunnel dereference */
    CYASSL_CERT_MANAGER* cm;
} CYASSL_X509_STORE;

typedef struct CYASSL_ALERT {
    int code;
    int level;
} CYASSL_ALERT;

typedef struct CYASSL_ALERT_HISTORY {
    CYASSL_ALERT last_rx;
    CYASSL_ALERT last_tx;
} CYASSL_ALERT_HISTORY;

typedef struct CYASSL_X509_REVOKED {
    CYASSL_ASN1_INTEGER* serialNumber;          /* stunnel dereference */
} CYASSL_X509_REVOKED;


typedef struct CYASSL_X509_OBJECT {
    union {
        char* ptr;
        CYASSL_X509_CRL* crl;           /* stunnel dereference */
    } data;
} CYASSL_X509_OBJECT;


typedef struct CYASSL_X509_STORE_CTX {
    CYASSL_X509_STORE* store;    /* Store full of a CA cert chain */
    CYASSL_X509* current_cert;   /* stunnel dereference */
    char* domain;                /* subject CN domain name */
    void* ex_data;               /* external data, for fortress build */
    void* userCtx;               /* user ctx */
    int   error;                 /* current error */
    int   error_depth;           /* cert depth for this error */
    int   discardSessionCerts;   /* so verify callback can flag for discard */ 
} CYASSL_X509_STORE_CTX;


/* Valid Alert types from page 16/17 */
enum AlertDescription {
    close_notify            = 0,
    unexpected_message      = 10,
    bad_record_mac          = 20,
    record_overflow         = 22,
    decompression_failure   = 30,
    handshake_failure       = 40,
    no_certificate          = 41,
    bad_certificate         = 42,
    unsupported_certificate = 43,
    certificate_revoked     = 44,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illegal_parameter       = 47,
    decrypt_error           = 51,
    protocol_version        = 70,
    no_renegotiation        = 100,
    unrecognized_name       = 112
};


enum AlertLevel {
    alert_warning = 1,
    alert_fatal = 2
};

typedef int (*VerifyCallback)(int, CYASSL_X509_STORE_CTX*);
typedef int (*pem_password_cb)(char*, int, int, void*);

#ifdef HAVE_SECRET_CALLBACK
typedef int (*SessionSecretCb)(CYASSL* ssl,
                                        void* secret, int* secretSz, void* ctx);
CYASSL_API int  CyaSSL_set_session_secret_cb(CYASSL*, SessionSecretCb, void*);
#endif /* HAVE_SECRET_CALLBACK */

#define CYASSL_DEFAULT_CIPHER_LIST ""   /* default all */
#define CYASSL_RSA_F4 0x10001L

enum {
    OCSP_NOCERTS     = 1,
    OCSP_NOINTERN    = 2,
    OCSP_NOSIGS      = 4,
    OCSP_NOCHAIN     = 8,
    OCSP_NOVERIFY    = 16,
    OCSP_NOEXPLICIT  = 32,
    OCSP_NOCASIGN    = 64,
    OCSP_NODELEGATED = 128,
    OCSP_NOCHECKS    = 256,
    OCSP_TRUSTOTHER  = 512,
    OCSP_RESPID_KEY  = 1024,
    OCSP_NOTIME      = 2048,

    OCSP_CERTID   = 2,
    OCSP_REQUEST  = 4,
    OCSP_RESPONSE = 8,
    OCSP_BASICRESP = 16,

    CYASSL_OCSP_URL_OVERRIDE = 1,
    CYASSL_OCSP_NO_NONCE     = 2,

    CYASSL_CRL_CHECKALL = 1,

    ASN1_GENERALIZEDTIME = 4,

    SSL_OP_MICROSOFT_SESS_ID_BUG = 1,
    SSL_OP_NETSCAPE_CHALLENGE_BUG = 2,
    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 3,
    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 4,
    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 5,
    SSL_OP_MSIE_SSLV2_RSA_PADDING = 6,
    SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 7,
    SSL_OP_TLS_D5_BUG = 8,
    SSL_OP_TLS_BLOCK_PADDING_BUG = 9,
    SSL_OP_TLS_ROLLBACK_BUG = 10,
    SSL_OP_ALL = 11,
    SSL_OP_EPHEMERAL_RSA = 12,
    SSL_OP_NO_SSLv3 = 13,
    SSL_OP_NO_TLSv1 = 14,
    SSL_OP_PKCS1_CHECK_1 = 15,
    SSL_OP_PKCS1_CHECK_2 = 16,
    SSL_OP_NETSCAPE_CA_DN_BUG = 17,
    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 18,
    SSL_OP_SINGLE_DH_USE = 19,
    SSL_OP_NO_TICKET = 20,
    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 21,
    SSL_OP_NO_QUERY_MTU = 22,
    SSL_OP_COOKIE_EXCHANGE = 23,
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 24,
    SSL_OP_SINGLE_ECDH_USE = 25,
    SSL_OP_CIPHER_SERVER_PREFERENCE = 26,

    SSL_MAX_SSL_SESSION_ID_LENGTH = 32,

    EVP_R_BAD_DECRYPT = 2,

    SSL_CB_LOOP = 4,
    SSL_ST_CONNECT = 5,
    SSL_ST_ACCEPT  = 6,
    SSL_CB_ALERT   = 7,
    SSL_CB_READ    = 8,
    SSL_CB_HANDSHAKE_DONE = 9,

    SSL_MODE_ENABLE_PARTIAL_WRITE = 2,

    BIO_FLAGS_BASE64_NO_NL = 1,
    BIO_CLOSE   = 1,
    BIO_NOCLOSE = 0,

    NID_undef = 0,

    X509_FILETYPE_PEM = 8,
    X509_LU_X509      = 9,
    X509_LU_CRL       = 12,
    
    X509_V_ERR_CRL_SIGNATURE_FAILURE = 13,
    X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 14,
    X509_V_ERR_CRL_HAS_EXPIRED                = 15,
    X509_V_ERR_CERT_REVOKED                   = 16,
    X509_V_ERR_CERT_CHAIN_TOO_LONG            = 17,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT      = 18,
    X509_V_ERR_CERT_NOT_YET_VALID             = 19,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 20,
    X509_V_ERR_CERT_HAS_EXPIRED               = 21,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD  = 22,

    X509_V_OK = 0,

    CRYPTO_LOCK = 1,
    CRYPTO_NUM_LOCKS = 10
};

/* extras end */

enum { /* ssl Constants */
    SSL_ERROR_NONE      =  0,   /* for most functions */
    SSL_FAILURE         =  0,   /* for some functions */
    SSL_SUCCESS         =  1,

    SSL_BAD_CERTTYPE    = -8,
    SSL_BAD_STAT        = -7,
    SSL_BAD_PATH        = -6,
    SSL_BAD_FILETYPE    = -5,
    SSL_BAD_FILE        = -4,
    SSL_NOT_IMPLEMENTED = -3,
    SSL_UNKNOWN         = -2,
    SSL_FATAL_ERROR     = -1,

    SSL_FILETYPE_ASN1    = 2,
    SSL_FILETYPE_PEM     = 1,
    SSL_FILETYPE_DEFAULT = 2, /* ASN1 */
    SSL_FILETYPE_RAW     = 3, /* NTRU raw key blob */

    SSL_VERIFY_NONE                 = 0,
    SSL_VERIFY_PEER                 = 1,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    SSL_VERIFY_CLIENT_ONCE          = 4,

    SSL_SESS_CACHE_OFF                = 30,
    SSL_SESS_CACHE_CLIENT             = 31,
    SSL_SESS_CACHE_SERVER             = 32,
    SSL_SESS_CACHE_BOTH               = 33,
    SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34,
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35,

    SSL_ERROR_WANT_READ        =  2,
    SSL_ERROR_WANT_WRITE       =  3,
    SSL_ERROR_WANT_CONNECT     =  7,
    SSL_ERROR_WANT_ACCEPT      =  8,
    SSL_ERROR_SYSCALL          =  5,
    SSL_ERROR_WANT_X509_LOOKUP = 83,
    SSL_ERROR_ZERO_RETURN      =  6,
    SSL_ERROR_SSL              = 85,

    SSL_SENT_SHUTDOWN     = 1,
    SSL_RECEIVED_SHUTDOWN = 2,
    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,
    SSL_OP_NO_SSLv2       = 8,

    SSL_R_SSL_HANDSHAKE_FAILURE           = 101,
    SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102,
    SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
    SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104,

    PEM_BUFSIZE = 1024
};

#ifndef NO_PSK
    typedef unsigned int (*psk_client_callback)(CYASSL*, const char*, char*,
                                    unsigned int, unsigned char*, unsigned int);


typedef unsigned int (*psk_server_callback)(CYASSL*, const char*,
                          unsigned char*, unsigned int);


    #define PSK_TYPES_DEFINED
#endif /* NO_PSK */

enum {  /* ERR Constants */
    ERR_TXT_STRING = 1
};


/* I/O callbacks */
typedef int (*CallbackIORecv)(CYASSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(CYASSL *ssl, char *buf, int sz, void *ctx);


#ifdef HAVE_FUZZER
enum fuzzer_type {
    FUZZ_HMAC      = 0,
    FUZZ_ENCRYPT   = 1,
    FUZZ_SIGNATURE = 2,
    FUZZ_HASH      = 3,
    FUZZ_HEAD      = 4
};

typedef int (*CallbackFuzzer)(CYASSL* ssl, const unsigned char* buf, int sz,
        int type, void* fuzzCtx);

#endif

typedef int (*CallbackGenCookie)(CYASSL* ssl, unsigned char* buf, int sz,
                                 void* ctx);

/* I/O Callback default errors */
enum IOerrors {
    CYASSL_CBIO_ERR_GENERAL    = -1,     /* general unexpected err */
    CYASSL_CBIO_ERR_WANT_READ  = -2,     /* need to call read  again */
    CYASSL_CBIO_ERR_WANT_WRITE = -2,     /* need to call write again */
    CYASSL_CBIO_ERR_CONN_RST   = -3,     /* connection reset */
    CYASSL_CBIO_ERR_ISR        = -4,     /* interrupt */
    CYASSL_CBIO_ERR_CONN_CLOSE = -5,     /* connection closed or epipe */
    CYASSL_CBIO_ERR_TIMEOUT    = -6      /* socket timeout */
};


/* CA cache callbacks */
enum {
    CYASSL_SSLV3    = 0,
    CYASSL_TLSV1    = 1,
    CYASSL_TLSV1_1  = 2,
    CYASSL_TLSV1_2  = 3,
    CYASSL_USER_CA  = 1,          /* user added as trusted */
    CYASSL_CHAIN_CA = 2           /* added to cache from trusted chain */
};

typedef void (*CallbackCACache)(unsigned char* der, int sz, int type);
typedef void (*CbMissingCRL)(const char* url);
typedef int  (*CbOCSPIO)(void*, const char*, int,
                                         unsigned char*, int, unsigned char**);
typedef void (*CbOCSPRespFree)(void*,unsigned char*);

/* User Atomic Record Layer CallBacks */
typedef int (*CallbackMacEncrypt)(CYASSL* ssl, unsigned char* macOut, 
       const unsigned char* macIn, unsigned int macInSz, int macContent, 
       int macVerify, unsigned char* encOut, const unsigned char* encIn,
       unsigned int encSz, void* ctx);


typedef int (*CallbackDecryptVerify)(CYASSL* ssl, 
       unsigned char* decOut, const unsigned char* decIn,
       unsigned int decSz, int content, int verify, unsigned int* padSz,
       void* ctx);


/* Atomic User Needs */
enum {
    CYASSL_SERVER_END = 0,
    CYASSL_CLIENT_END = 1,
    CYASSL_BLOCK_TYPE = 2,
    CYASSL_STREAM_TYPE = 3,
    CYASSL_AEAD_TYPE = 4,
    CYASSL_TLS_HMAC_INNER_SZ = 13      /* SEQ_SZ + ENUM + VERSION_SZ + LEN_SZ */
};

/* for GetBulkCipher and internal use */
enum BulkCipherAlgorithm { 
    cyassl_cipher_null,
    cyassl_rc4,
    cyassl_rc2,
    cyassl_des,
    cyassl_triple_des,             /* leading 3 (3des) not valid identifier */
    cyassl_des40,
    cyassl_idea,
    cyassl_aes,
    cyassl_aes_gcm,
    cyassl_aes_ccm,
    cyassl_chacha,
    cyassl_camellia,
    cyassl_hc128,                  /* CyaSSL extensions */
    cyassl_rabbit
};


/* for KDF TLS 1.2 mac types */
enum KDF_MacAlgorithm {
    cyassl_sha256 = 4,     /* needs to match internal MACAlgorithm */
    cyassl_sha384,
    cyassl_sha512
};


/* Public Key Callback support */
typedef int (*CallbackEccSign)(CYASSL* ssl, 
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

typedef int (*CallbackEccVerify)(CYASSL* ssl, 
       const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx);


typedef int (*CallbackRsaSign)(CYASSL* ssl, 
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

typedef int (*CallbackRsaVerify)(CYASSL* ssl, 
       unsigned char* sig, unsigned int sigSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

/* RSA Public Encrypt cb */
typedef int (*CallbackRsaEnc)(CYASSL* ssl, 
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, unsigned int* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

/* RSA Private Decrypt cb */
typedef int (*CallbackRsaDec)(CYASSL* ssl, 
       unsigned char* in, unsigned int inSz,
       unsigned char** out,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx);

/* SNI types */
enum {
    CYASSL_SNI_HOST_NAME = 0
};

/* SNI options */
enum {
    CYASSL_SNI_CONTINUE_ON_MISMATCH = 0x01, /* do not abort on mismatch flag */
    CYASSL_SNI_ANSWER_ON_MISMATCH   = 0x02  /* fake match on mismatch flag */
};

/* SNI status */
enum {
    CYASSL_SNI_NO_MATCH   = 0,
    CYASSL_SNI_FAKE_MATCH = 1, /* if CYASSL_SNI_ANSWER_ON_MISMATCH is enabled */
    CYASSL_SNI_REAL_MATCH = 2
};


/* Fragment lengths */
enum {
    CYASSL_MFL_2_9  = 1, /*  512 bytes */
    CYASSL_MFL_2_10 = 2, /* 1024 bytes */
    CYASSL_MFL_2_11 = 3, /* 2048 bytes */
    CYASSL_MFL_2_12 = 4, /* 4096 bytes */
    CYASSL_MFL_2_13 = 5  /* 8192 bytes *//* CyaSSL ONLY!!! */
};


enum {
    CYASSL_ECC_SECP160R1 = 0x10,
    CYASSL_ECC_SECP192R1 = 0x13,
    CYASSL_ECC_SECP224R1 = 0x15,
    CYASSL_ECC_SECP256R1 = 0x17,
    CYASSL_ECC_SECP384R1 = 0x18,
    CYASSL_ECC_SECP521R1 = 0x19
};


typedef int (*CallbackSessionTicket)(CYASSL*, const unsigned char*, int, void*);

#include <cyassl/callbacks.h>

typedef int (*HandShakeCallBack)(HandShakeInfo*);
typedef int (*TimeoutCallBack)(TimeoutInfo*);

#endif /* LIBRARIES_CYASSL_H */
