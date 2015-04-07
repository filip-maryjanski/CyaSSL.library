/* internal.c
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

#include <cyassl/internal.h>
#include <cyassl/error-ssl.h>
#include <cyassl/ctaocrypt/asn.h>

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endif

#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif


#if defined(CYASSL_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #error \
CYASSL_CALLBACKS needs LARGE_STATIC_BUFFERS, please add LARGE_STATIC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif

static int BuildMessage(CYASSL* ssl, byte* output, int outSz,
                        const byte* input, int inSz, int type);

#ifndef NO_CYASSL_CLIENT
    static int DoHelloVerifyRequest(CYASSL* ssl, const byte* input, word32*,
                                                                        word32);
    static int DoServerHello(CYASSL* ssl, const byte* input, word32*, word32);
    static int DoServerKeyExchange(CYASSL* ssl, const byte* input, word32*,
                                                                        word32);
    #ifndef NO_CERTS
        static int DoCertificateRequest(CYASSL* ssl, const byte* input, word32*,
                                                                        word32);
    #endif
    #ifdef HAVE_SESSION_TICKET
        static int DoSessionTicket(CYASSL* ssl, const byte* input, word32*,
                                                                        word32);
    #endif
#endif


#ifndef NO_CYASSL_SERVER
    static int DoClientHello(CYASSL* ssl, const byte* input, word32*, word32);
    static int DoClientKeyExchange(CYASSL* ssl, byte* input, word32*, word32);
    #if !defined(NO_RSA) || defined(HAVE_ECC)
        static int DoCertificateVerify(CYASSL* ssl, byte*, word32*, word32);
    #endif
#endif


#ifdef CYASSL_DTLS
    static INLINE int DtlsCheckWindow(DtlsState* state);
    static INLINE int DtlsUpdateWindow(DtlsState* state);
#endif


typedef enum {
    doProcessInit = 0,
#ifndef NO_CYASSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    runProcessingOneMessage
} processReply;

#ifndef NO_OLD_TLS
static int SSL_hmac(CYASSL* ssl, byte* digest, const byte* in, word32 sz,
                    int content, int verify);

#endif

#ifndef NO_CERTS
static int BuildCertHashes(CYASSL* ssl, Hashes* hashes);
#endif

static void PickHashSigAlgo(CYASSL* ssl,
                                const byte* hashSigAlgo, word32 hashSigAlgoSz);

#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINOR)
        return 1;
    if (ssl->version.major == DTLS_MAJOR && ssl->version.minor <= DTLSv1_2_MINOR)
        return 1;

    return 0;
}


#ifdef HAVE_NTRU

static byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    /* TODO: add locking? */
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

/* used by ssl.c too */
void c32to24(word32 in, word24 out)
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] =  in & 0xff;
}


#ifdef CYASSL_DTLS

static INLINE void c32to48(word32 in, byte out[6])
{
    out[0] = 0;
    out[1] = 0;
    out[2] = (in >> 24) & 0xff;
    out[3] = (in >> 16) & 0xff;
    out[4] = (in >>  8) & 0xff;
    out[5] =  in & 0xff;
}

#endif /* CYASSL_DTLS */


/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}


#if !defined(NO_OLD_TLS) || defined(HAVE_CHACHA) || defined(HAVE_AESCCM) \
    || defined(HAVE_AESGCM)
/* convert 32 bit integer to opaque */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}
#endif


/* convert a 24 bit integer into a 32 bit one */
static INLINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


/* convert opaque to 16 bit integer */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (word16) ((c[0] << 8) | (c[1]));
}


#if defined(CYASSL_DTLS) || defined(HAVE_SESSION_TICKET)

/* convert opaque to 32 bit integer */
static INLINE void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

#endif /* CYASSL_DTLS */


#ifdef HAVE_LIBZ

    /* alloc user allocs to work with zlib */
    static void* myAlloc(void* opaque, unsigned int item, unsigned int size)
    {
        (void)opaque;
        return XMALLOC(item * size, opaque, DYNAMIC_TYPE_LIBZ);
    }


    static void myFree(void* opaque, void* memory)
    {
        (void)opaque;
        XFREE(memory, opaque, DYNAMIC_TYPE_LIBZ);
    }


    /* init zlib comp/decomp streams, 0 on success */
    static int InitStreams(CYASSL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  = (free_func)myFree;
        ssl->c_stream.opaque = (voidpf)ssl->heap;

        if (deflateInit(&ssl->c_stream, Z_DEFAULT_COMPRESSION) != Z_OK)
            return ZLIB_INIT_ERROR;

        ssl->didStreamInit = 1;

        ssl->d_stream.zalloc = (alloc_func)myAlloc;
        ssl->d_stream.zfree  = (free_func)myFree;
        ssl->d_stream.opaque = (voidpf)ssl->heap;

        if (inflateInit(&ssl->d_stream) != Z_OK) return ZLIB_INIT_ERROR;

        return 0;
    }


    static void FreeStreams(CYASSL* ssl)
    {
        if (ssl->didStreamInit) {
            deflateEnd(&ssl->c_stream);
            inflateEnd(&ssl->d_stream);
        }
    }


    /* compress in to out, return out size or error */
    static int myCompress(CYASSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->c_stream.total_out;

        ssl->c_stream.next_in   = in;
        ssl->c_stream.avail_in  = inSz;
        ssl->c_stream.next_out  = out;
        ssl->c_stream.avail_out = outSz;

        err = deflate(&ssl->c_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_COMPRESS_ERROR;

        return (int)ssl->c_stream.total_out - currTotal;
    }


    /* decompress in to out, returnn out size or error */
    static int myDeCompress(CYASSL* ssl, byte* in,int inSz, byte* out,int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->d_stream.total_out;

        ssl->d_stream.next_in   = in;
        ssl->d_stream.avail_in  = inSz;
        ssl->d_stream.next_out  = out;
        ssl->d_stream.avail_out = outSz;

        err = inflate(&ssl->d_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_DECOMPRESS_ERROR;

        return (int)ssl->d_stream.total_out - currTotal;
    }

#endif /* HAVE_LIBZ */


void InitSSL_Method(CYASSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = CYASSL_CLIENT_END;
    method->downgrade  = 0;
}


/* Initialze SSL context, return 0 on success */
int InitSSL_Ctx(CYASSL_CTX* ctx, CYASSL_METHOD* method)
{
    ctx->method = method;
    ctx->refCount = 1;          /* so either CTX_free or SSL_free can release */
#ifndef NO_CERTS
    ctx->certificate.buffer = 0;
    ctx->certChain.buffer   = 0;
    ctx->privateKey.buffer  = 0;
    ctx->serverDH_P.buffer  = 0;
    ctx->serverDH_G.buffer  = 0;
#endif
    ctx->haveDH             = 0;
    ctx->haveNTRU           = 0;    /* start off */
    ctx->haveECDSAsig       = 0;    /* start off */
    ctx->haveStaticECC      = 0;    /* start off */
    ctx->heap               = ctx;  /* defaults to self */
#ifndef NO_PSK
    ctx->havePSK            = 0;
    ctx->server_hint[0]     = 0;
    ctx->client_psk_cb      = 0;
    ctx->server_psk_cb      = 0;
#endif /* NO_PSK */
#ifdef HAVE_ANON
    ctx->haveAnon           = 0;
#endif /* HAVE_ANON */
#ifdef HAVE_ECC
    ctx->eccTempKeySz       = ECDHE_SIZE;
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    ctx->passwd_cb   = 0;
    ctx->userdata    = 0;
#endif /* OPENSSL_EXTRA */

    ctx->timeout = CYASSL_SESSION_TIMEOUT;

#ifndef CYASSL_USER_IO
    ctx->CBIORecv = EmbedReceive;
    ctx->CBIOSend = EmbedSend;
    #ifdef CYASSL_DTLS
        if (method->version.major == DTLS_MAJOR) {
            ctx->CBIORecv   = EmbedReceiveFrom;
            ctx->CBIOSend   = EmbedSendTo;
            ctx->CBIOCookie = EmbedGenerateCookie;
        }
    #endif
#else
    /* user will set */
    ctx->CBIORecv   = NULL;
    ctx->CBIOSend   = NULL;
    #ifdef CYASSL_DTLS
        ctx->CBIOCookie = NULL;
    #endif
#endif /* CYASSL_USER_IO */
#ifdef HAVE_NETX
    ctx->CBIORecv = NetX_Receive;
    ctx->CBIOSend = NetX_Send;
#endif
    ctx->partialWrite   = 0;
    ctx->verifyCallback = 0;

#ifndef NO_CERTS
    ctx->cm = CyaSSL_CertManagerNew();
#endif
#ifdef HAVE_NTRU
    if (method->side == CYASSL_CLIENT_END)
        ctx->haveNTRU = 1;           /* always on cliet side */
                                     /* server can turn on by loading key */
#endif
#ifdef HAVE_ECC
    if (method->side == CYASSL_CLIENT_END) {
        ctx->haveECDSAsig  = 1;        /* always on cliet side */
        ctx->haveStaticECC = 1;        /* server can turn on by loading key */
    }
#endif
    ctx->suites.setSuites = 0;  /* user hasn't set yet */
    /* remove DH later if server didn't set, add psk later */
    InitSuites(&ctx->suites, method->version, TRUE, FALSE, TRUE, ctx->haveNTRU,
               ctx->haveECDSAsig, ctx->haveStaticECC, method->side);
    ctx->verifyPeer = 0;
    ctx->verifyNone = 0;
    ctx->failNoCert = 0;
    ctx->sessionCacheOff      = 0;  /* initially on */
    ctx->sessionCacheFlushOff = 0;  /* initially on */
    ctx->sendVerify = 0;
    ctx->quietShutdown = 0;
    ctx->groupMessages = 0;
#ifdef HAVE_CAVIUM
    ctx->devId = NO_CAVIUM_DEVICE;
#endif
#ifdef HAVE_TLS_EXTENSIONS
    ctx->extensions = NULL;
#endif
#ifdef ATOMIC_USER
    ctx->MacEncryptCb    = NULL;
    ctx->DecryptVerifyCb = NULL;
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        ctx->EccSignCb   = NULL;
        ctx->EccVerifyCb = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        ctx->RsaSignCb   = NULL;
        ctx->RsaVerifyCb = NULL;
        ctx->RsaEncCb    = NULL;
        ctx->RsaDecCb    = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

    if (InitMutex(&ctx->countMutex) < 0) {
        CYASSL_MSG("Mutex error on CTX init");
        return BAD_MUTEX_E;
    }
#ifndef NO_CERTS
    if (ctx->cm == NULL) {
        CYASSL_MSG("Bad Cert Manager New");
        return BAD_CERT_MANAGER_ERROR;
    }
#endif
    return 0;
}

/* In case contexts are held in array and don't want to free actual ctx */
void SSL_CtxResourceFree(CYASSL_CTX* ctx)
{
    XFREE(ctx->method, ctx->heap, DYNAMIC_TYPE_METHOD);

#ifndef NO_CERTS
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);
    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
    XFREE(ctx->privateKey.buffer, ctx->heap, DYNAMIC_TYPE_KEY);
    XFREE(ctx->certificate.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
    XFREE(ctx->certChain.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
    CyaSSL_CertManagerFree(ctx->cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(ctx->extensions);
#endif
}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    int doFree = 0;

    if (LockMutex(&ctx->countMutex) != 0) {
        CYASSL_MSG("Couldn't lock count mutex");
        return;
    }
    ctx->refCount--;
    if (ctx->refCount == 0)
        doFree = 1;
    UnLockMutex(&ctx->countMutex);

    if (doFree) {
        CYASSL_MSG("CTX ref count down to 0, doing full free");
        SSL_CtxResourceFree(ctx);
        FreeMutex(&ctx->countMutex);
        XFREE(ctx, ctx->heap, DYNAMIC_TYPE_CTX);
    }
    else {
        (void)ctx;
        CYASSL_MSG("CTX ref count not 0 yet, no free");
    }
}


/* Set cipher pointers to null */
void InitCiphers(CYASSL* ssl)
{
#ifdef BUILD_ARC4
    ssl->encrypt.arc4 = NULL;
    ssl->decrypt.arc4 = NULL;
#endif
#ifdef BUILD_DES3
    ssl->encrypt.des3 = NULL;
    ssl->decrypt.des3 = NULL;
#endif
#ifdef BUILD_AES
    ssl->encrypt.aes = NULL;
    ssl->decrypt.aes = NULL;
#endif
#ifdef HAVE_CAMELLIA
    ssl->encrypt.cam = NULL;
    ssl->decrypt.cam = NULL;
#endif
#ifdef HAVE_HC128
    ssl->encrypt.hc128 = NULL;
    ssl->decrypt.hc128 = NULL;
#endif
#ifdef BUILD_RABBIT
    ssl->encrypt.rabbit = NULL;
    ssl->decrypt.rabbit = NULL;
#endif
#ifdef HAVE_CHACHA
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
#endif
#ifdef HAVE_POLY1305
    ssl->auth.poly1305 = NULL;
#endif
    ssl->encrypt.setup = 0;
    ssl->decrypt.setup = 0;
#ifdef HAVE_ONE_TIME_AUTH
    ssl->auth.setup    = 0;
#endif
}


/* Free ciphers */
void FreeCiphers(CYASSL* ssl)
{
    (void)ssl;
#ifdef BUILD_ARC4
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        Arc4FreeCavium(ssl->encrypt.arc4);
        Arc4FreeCavium(ssl->decrypt.arc4);
    }
    #endif
    XFREE(ssl->encrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_DES3
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        Des3_FreeCavium(ssl->encrypt.des3);
        Des3_FreeCavium(ssl->decrypt.des3);
    }
    #endif
    XFREE(ssl->encrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_AES
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        AesFreeCavium(ssl->encrypt.aes);
        AesFreeCavium(ssl->decrypt.aes);
    }
    #endif
    XFREE(ssl->encrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CAMELLIA
    XFREE(ssl->encrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_HC128
    XFREE(ssl->encrypt.hc128, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.hc128, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_RABBIT
    XFREE(ssl->encrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CHACHA
    XFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_POLY1305
    XFREE(ssl->auth.poly1305, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
}


void InitCipherSpecs(CipherSpecs* cs)
{
    cs->bulk_cipher_algorithm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea                   = INVALID_BYTE;
    cs->sig_algo              = INVALID_BYTE;

    cs->hash_size   = 0;
    cs->static_ecdh = 0;
    cs->key_size    = 0;
    cs->iv_size     = 0;
    cs->block_size  = 0;
}

static void InitSuitesHashSigAlgo(Suites* suites, int haveECDSAsig,
                                                  int haveRSAsig, int haveAnon)
{
    int idx = 0;

    if (haveECDSAsig) {
        #ifdef CYASSL_SHA384
            suites->hashSigAlgo[idx++] = sha384_mac;
            suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
        #endif
        #ifndef NO_SHA256
            suites->hashSigAlgo[idx++] = sha256_mac;
            suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
        #endif
        #ifndef NO_SHA
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
        #endif
    }

    if (haveRSAsig) {
        #ifdef CYASSL_SHA384
            suites->hashSigAlgo[idx++] = sha384_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
        #ifndef NO_SHA256
            suites->hashSigAlgo[idx++] = sha256_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
        #ifndef NO_SHA
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #ifdef HAVE_ANON
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = anonymous_sa_algo;
        #endif
    }

    suites->hashSigAlgoSz = (word16)idx;
}

void InitSuites(Suites* suites, ProtocolVersion pv, byte haveRSA, byte havePSK,
                byte haveDH, byte haveNTRU, byte haveECDSAsig,
                byte haveStaticECC, int side)
{
    word16 idx = 0;
    int    tls    = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
    int    haveRSAsig = 1;

    (void)tls;  /* shut up compiler */
    (void)tls1_2;
    (void)haveDH;
    (void)havePSK;
    (void)haveNTRU;
    (void)haveStaticECC;

    if (suites == NULL) {
        CYASSL_MSG("InitSuites pointer error");
        return;
    }

    if (suites->setSuites)
        return;      /* trust user settings, don't override */

    if (side == CYASSL_SERVER_END && haveStaticECC) {
        haveRSA = 0;   /* can't do RSA with ECDSA key */
        (void)haveRSA; /* some builds won't read */
    }

    if (side == CYASSL_SERVER_END && haveECDSAsig) {
        haveRSAsig = 0;     /* can't have RSA sig if signed by ECDSA */
        (void)haveRSAsig;   /* non ecc builds won't read */
    }

#ifdef CYASSL_DTLS
    if (pv.major == DTLS_MAJOR) {
        tls    = 1;
        tls1_2 = pv.minor <= DTLSv1_2_MINOR;
    }
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    if (side == CYASSL_CLIENT_END) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_MD5;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    if (haveRSA ) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_MD5
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_B2B256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_B2B256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_RABBIT_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_RABBIT_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_WITH_RSA_CAMELLIA_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

    suites->suiteSz = idx;

    InitSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig, 0);
}


#ifndef NO_CERTS


void InitX509Name(CYASSL_X509_NAME* name, int dynamicFlag)
{
    (void)dynamicFlag;

    if (name != NULL) {
        name->name        = name->staticName;
        name->dynamicName = 0;
#ifdef OPENSSL_EXTRA
        XMEMSET(&name->fullName, 0, sizeof(DecodedName));
#endif /* OPENSSL_EXTRA */
    }
}


void FreeX509Name(CYASSL_X509_NAME* name)
{
    if (name != NULL) {
        if (name->dynamicName)
            XFREE(name->name, NULL, DYNAMIC_TYPE_SUBJECT_CN);
#ifdef OPENSSL_EXTRA
        if (name->fullName.fullName != NULL)
            XFREE(name->fullName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
    }
}


/* Initialize CyaSSL X509 type */
void InitX509(CYASSL_X509* x509, int dynamicFlag)
{
    InitX509Name(&x509->issuer, 0);
    InitX509Name(&x509->subject, 0);
    x509->version        = 0;
    x509->pubKey.buffer  = NULL;
    x509->sig.buffer     = NULL;
    x509->derCert.buffer = NULL;
    x509->altNames       = NULL;
    x509->altNamesNext   = NULL;
    x509->dynamicMemory  = (byte)dynamicFlag;
    x509->isCa           = 0;
#ifdef HAVE_ECC
    x509->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef OPENSSL_EXTRA
    x509->pathLength     = 0;
    x509->basicConstSet  = 0;
    x509->basicConstCrit = 0;
    x509->basicConstPlSet = 0;
    x509->subjAltNameSet = 0;
    x509->subjAltNameCrit = 0;
    x509->authKeyIdSet   = 0;
    x509->authKeyIdCrit  = 0;
    x509->authKeyId      = NULL;
    x509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = NULL;
    x509->subjKeyIdSz    = 0;
    x509->keyUsageSet    = 0;
    x509->keyUsageCrit   = 0;
    x509->keyUsage       = 0;
    #ifdef CYASSL_SEP
        x509->certPolicySet  = 0;
        x509->certPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif /* OPENSSL_EXTRA */
}


/* Free CyaSSL X509 type */
void FreeX509(CYASSL_X509* x509)
{
    if (x509 == NULL)
        return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&x509->subject);
    if (x509->pubKey.buffer)
        XFREE(x509->pubKey.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(x509->derCert.buffer, NULL, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #ifdef OPENSSL_EXTRA
        XFREE(x509->authKeyId, NULL, 0);
        XFREE(x509->subjKeyId, NULL, 0);
    #endif /* OPENSSL_EXTRA */
    if (x509->altNames)
        FreeAltNames(x509->altNames, NULL);
    if (x509->dynamicMemory)
        XFREE(x509, NULL, DYNAMIC_TYPE_X509);
}

#endif /* NO_CERTS */


/* init everything to 0, NULL, default values before calling anything that may
   fail so that desctructor has a "good" state to cleanup */
int InitSSL(CYASSL* ssl, CYASSL_CTX* ctx)
{
    int  ret;
    byte haveRSA = 0;
    byte havePSK = 0;
    byte haveAnon = 0;

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    ssl->version = ctx->method->version;
    ssl->suites  = NULL;

#ifdef HAVE_LIBZ
    ssl->didStreamInit = 0;
#endif
#ifndef NO_RSA
    haveRSA = 1;
#endif

#ifndef NO_CERTS
    ssl->buffers.certificate.buffer   = 0;
    ssl->buffers.key.buffer           = 0;
    ssl->buffers.certChain.buffer     = 0;
#endif
    ssl->buffers.inputBuffer.length   = 0;
    ssl->buffers.inputBuffer.idx      = 0;
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset   = 0;
    ssl->buffers.outputBuffer.length  = 0;
    ssl->buffers.outputBuffer.idx     = 0;
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
    ssl->buffers.domainName.buffer    = 0;
#ifndef NO_CERTS
    ssl->buffers.serverDH_P.buffer    = 0;
    ssl->buffers.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.buffer  = 0;
    ssl->buffers.serverDH_Priv.buffer = 0;
#endif
    ssl->buffers.clearOutputBuffer.buffer  = 0;
    ssl->buffers.clearOutputBuffer.length  = 0;
    ssl->buffers.prevSent                  = 0;
    ssl->buffers.plainSz                   = 0;
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        ssl->buffers.peerEccDsaKey.buffer = 0;
        ssl->buffers.peerEccDsaKey.length = 0;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        ssl->buffers.peerRsaKey.buffer = 0;
        ssl->buffers.peerRsaKey.length = 0;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

#ifdef KEEP_PEER_CERT
    InitX509(&ssl->peerCert, 0);
#endif

#ifdef HAVE_ECC
    ssl->eccTempKeySz = ctx->eccTempKeySz;
    ssl->pkCurveOID = ctx->pkCurveOID;
    ssl->peerEccKeyPresent = 0;
    ssl->peerEccDsaKeyPresent = 0;
    ssl->eccDsaKeyPresent = 0;
    ssl->eccTempKeyPresent = 0;
    ssl->peerEccKey = NULL;
    ssl->peerEccDsaKey = NULL;
    ssl->eccDsaKey = NULL;
    ssl->eccTempKey = NULL;
#endif

    ssl->timeout = ctx->timeout;
    ssl->rfd = -1;   /* set to invalid descriptor */
    ssl->wfd = -1;
    ssl->rflags = 0;    /* no user flags yet */
    ssl->wflags = 0;    /* no user flags yet */
    ssl->biord = 0;
    ssl->biowr = 0;

    ssl->IOCB_ReadCtx  = &ssl->rfd;  /* prevent invalid pointer access if not */
    ssl->IOCB_WriteCtx = &ssl->wfd;  /* correctly set */
#ifdef HAVE_NETX
    ssl->nxCtx.nxSocket = NULL;
    ssl->nxCtx.nxPacket = NULL;
    ssl->nxCtx.nxOffset = 0;
    ssl->nxCtx.nxWait   = 0;
    ssl->IOCB_ReadCtx  = &ssl->nxCtx;  /* default NetX IO ctx, same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and write */
#endif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;      /* we don't use for default cb */
    ssl->dtls_expected_rx = MAX_MTU;
    ssl->keys.dtls_state.window = 0;
    ssl->keys.dtls_state.nextEpoch = 0;
    ssl->keys.dtls_state.nextSeq = 0;
#endif

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

#ifndef NO_RSA
    ssl->peerRsaKey = NULL;
    ssl->peerRsaKeyPresent = 0;
#endif
    ssl->verifyCallback    = ctx->verifyCallback;
    ssl->verifyCbCtx       = NULL;
    ssl->options.side      = ctx->method->side;
    ssl->options.downgrade    = ctx->method->downgrade;
    ssl->options.minDowngrade = TLSv1_MINOR;     /* current default */
    ssl->error = 0;
    ssl->options.connReset = 0;
    ssl->options.isClosed  = 0;
    ssl->options.closeNotify  = 0;
    ssl->options.sentNotify   = 0;
    ssl->options.usingCompression = 0;
    if (ssl->options.side == CYASSL_SERVER_END)
        ssl->options.haveDH = ctx->haveDH;
    else
        ssl->options.haveDH = 0;
    ssl->options.haveNTRU      = ctx->haveNTRU;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsig;
    ssl->options.haveStaticECC = ctx->haveStaticECC;
    ssl->options.havePeerCert    = 0;
    ssl->options.havePeerVerify  = 0;
    ssl->options.usingPSK_cipher = 0;
    ssl->options.usingAnon_cipher = 0;
    ssl->options.sendAlertState = 0;
#ifndef NO_PSK
    havePSK = ctx->havePSK;
    ssl->options.havePSK   = ctx->havePSK;
    ssl->options.client_psk_cb = ctx->client_psk_cb;
    ssl->options.server_psk_cb = ctx->server_psk_cb;
#endif /* NO_PSK */
#ifdef HAVE_ANON
    haveAnon = ctx->haveAnon;
    ssl->options.haveAnon = ctx->haveAnon;
#endif

    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN;
    ssl->options.handShakeState  = NULL_STATE;
    ssl->options.handShakeDone   = 0;
    ssl->options.processReply = doProcessInit;

#ifdef CYASSL_DTLS
    ssl->keys.dtls_sequence_number      = 0;
    ssl->keys.dtls_state.curSeq         = 0;
    ssl->keys.dtls_state.nextSeq        = 0;
    ssl->keys.dtls_handshake_number     = 0;
    ssl->keys.dtls_expected_peer_handshake_number = 0;
    ssl->keys.dtls_epoch                = 0;
    ssl->keys.dtls_state.curEpoch       = 0;
    ssl->keys.dtls_state.nextEpoch      = 0;
    ssl->dtls_timeout_init              = DTLS_TIMEOUT_INIT;
    ssl->dtls_timeout_max               = DTLS_TIMEOUT_MAX;
    ssl->dtls_timeout                   = ssl->dtls_timeout_init;
    ssl->dtls_pool                      = NULL;
    ssl->dtls_msg_list                  = NULL;
#endif
    ssl->keys.encryptSz    = 0;
    ssl->keys.padSz        = 0;
    ssl->keys.encryptionOn = 0;     /* initially off */
    ssl->keys.decryptedCur = 0;     /* initially off */
    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;

    ssl->options.verifyPeer = ctx->verifyPeer;
    ssl->options.verifyNone = ctx->verifyNone;
    ssl->options.failNoCert = ctx->failNoCert;
    ssl->options.sendVerify = ctx->sendVerify;

    ssl->options.resuming = 0;
    ssl->options.haveSessionId = 0;
    #ifndef NO_OLD_TLS
        ssl->hmac = SSL_hmac; /* default to SSLv3 */
    #else
        ssl->hmac = TLS_hmac;
    #endif
    ssl->heap = ctx->heap;    /* defaults to self */
    ssl->options.tls    = 0;
    ssl->options.tls1_1 = 0;
    ssl->options.dtls = ssl->version.major == DTLS_MAJOR;
    ssl->options.partialWrite  = ctx->partialWrite;
    ssl->options.quietShutdown = ctx->quietShutdown;
    ssl->options.certOnly = 0;
    ssl->options.groupMessages = ctx->groupMessages;
    ssl->options.usingNonblock = 0;
    ssl->options.saveArrays = 0;
#ifdef HAVE_POLY1305
    ssl->options.oldPoly = 0;
#endif

#ifndef NO_CERTS
    /* ctx still owns certificate, certChain, key, dh, and cm */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.certChain = ctx->certChain;
    ssl->buffers.key = ctx->privateKey;
    if (ssl->options.side == CYASSL_SERVER_END) {
        ssl->buffers.serverDH_P = ctx->serverDH_P;
        ssl->buffers.serverDH_G = ctx->serverDH_G;
    }
#endif
    ssl->buffers.weOwnCert      = 0;
    ssl->buffers.weOwnCertChain = 0;
    ssl->buffers.weOwnKey       = 0;
    ssl->buffers.weOwnDH        = 0;

#ifdef CYASSL_DTLS
    ssl->buffers.dtlsCtx.fd = -1;
    ssl->buffers.dtlsCtx.peer.sa = NULL;
    ssl->buffers.dtlsCtx.peer.sz = 0;
#endif

#ifdef KEEP_PEER_CERT
    ssl->peerCert.issuer.sz    = 0;
    ssl->peerCert.subject.sz   = 0;
#endif

#ifdef SESSION_CERTS
    ssl->session.chain.count = 0;
#endif

#ifndef NO_CLIENT_CACHE
    ssl->session.idLen = 0;
#endif

#ifdef HAVE_SESSION_TICKET
    ssl->session.ticketLen = 0;
#endif

    ssl->cipher.ssl = ssl;

#ifdef FORTRESS
    ssl->ex_data[0] = 0;
    ssl->ex_data[1] = 0;
    ssl->ex_data[2] = 0;
#endif

#ifdef CYASSL_CALLBACKS
    ssl->hsInfoOn = 0;
    ssl->toInfoOn = 0;
#endif

#ifdef HAVE_CAVIUM
    ssl->devId = ctx->devId;
#endif

#ifdef HAVE_TLS_EXTENSIONS
    ssl->extensions = NULL;
#ifdef HAVE_MAX_FRAGMENT
    ssl->max_fragment = MAX_RECORD_SIZE;
#endif
#ifdef HAVE_TRUNCATED_HMAC
    ssl->truncated_hmac = 0;
#endif
#ifdef HAVE_SECURE_RENEGOTIATION
    ssl->secure_renegotiation = NULL;
#endif
#if !defined(NO_CYASSL_CLIENT) && defined(HAVE_SESSION_TICKET)
    ssl->session_ticket_cb = NULL;
    ssl->session_ticket_ctx = NULL;
    ssl->expect_session_ticket = 0;
#endif
#endif

    ssl->rng    = NULL;
    ssl->arrays = NULL;

    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_history.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;

    InitCiphers(ssl);
    InitCipherSpecs(&ssl->specs);
#ifdef ATOMIC_USER
    ssl->MacEncryptCtx    = NULL;
    ssl->DecryptVerifyCtx = NULL;
#endif
#ifdef HAVE_FUZZER
    ssl->fuzzerCb         = NULL;
    ssl->fuzzerCtx        = NULL;
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        ssl->EccSignCtx   = NULL;
        ssl->EccVerifyCtx = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        ssl->RsaSignCtx   = NULL;
        ssl->RsaVerifyCtx = NULL;
        ssl->RsaEncCtx    = NULL;
        ssl->RsaDecCtx    = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

#ifdef __MORPHOS__
    ssl->socketbase = NULL;
#endif

    /* all done with init, now can return errors, call other stuff */

#ifndef NO_OLD_TLS
#ifndef NO_MD5
    InitMd5(&ssl->hashMd5);
#endif
#ifndef NO_SHA
    ret = InitSha(&ssl->hashSha);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#ifndef NO_SHA256
    ret = InitSha256(&ssl->hashSha256);
    if (ret != 0) {
        return ret;
    }
#endif
#ifdef CYASSL_SHA384
    ret = InitSha384(&ssl->hashSha384);
    if (ret != 0) {
        return ret;
    }
#endif

    /* increment CTX reference count */
    if (LockMutex(&ctx->countMutex) != 0) {
        CYASSL_MSG("Couldn't lock CTX count mutex");
        return BAD_MUTEX_E;
    }
    ctx->refCount++;
    UnLockMutex(&ctx->countMutex);

    /* arrays */
    ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
    if (ssl->arrays == NULL) {
        CYASSL_MSG("Arrays Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->arrays, 0, sizeof(Arrays));

#ifndef NO_PSK
    ssl->arrays->client_identity[0] = 0;
    if (ctx->server_hint[0]) {   /* set in CTX */
        XSTRNCPY(ssl->arrays->server_hint, ctx->server_hint, MAX_PSK_ID_LEN);
        ssl->arrays->server_hint[MAX_PSK_ID_LEN - 1] = '\0';
    }
    else
        ssl->arrays->server_hint[0] = 0;
#endif /* NO_PSK */

#ifdef CYASSL_DTLS
    ssl->arrays->cookieSz = 0;
#endif

    /* RNG */
    ssl->rng = (RNG*)XMALLOC(sizeof(RNG), ssl->heap, DYNAMIC_TYPE_RNG);
    if (ssl->rng == NULL) {
        CYASSL_MSG("RNG Memory error");
        return MEMORY_E;
    }

    if ( (ret = InitRng(ssl->rng)) != 0) {
        CYASSL_MSG("RNG Init error");
        return ret;
    }

    /* suites */
    ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                   DYNAMIC_TYPE_SUITES);
    if (ssl->suites == NULL) {
        CYASSL_MSG("Suites Memory error");
        return MEMORY_E;
    }
    *ssl->suites = ctx->suites;

    /* peer key */
#ifndef NO_RSA
    ssl->peerRsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey), ssl->heap,
                                       DYNAMIC_TYPE_RSA);
    if (ssl->peerRsaKey == NULL) {
        CYASSL_MSG("PeerRsaKey Memory error");
        return MEMORY_E;
    }
    ret = InitRsaKey(ssl->peerRsaKey, ctx->heap);
    if (ret != 0) return ret;
#endif
#ifndef NO_CERTS
    /* make sure server has cert and key unless using PSK or Anon */
    if (ssl->options.side == CYASSL_SERVER_END && !havePSK && !haveAnon)
        if (!ssl->buffers.certificate.buffer || !ssl->buffers.key.buffer) {
            CYASSL_MSG("Server missing certificate and/or private key");
            return NO_PRIVATE_KEY;
        }
#endif
#ifdef HAVE_ECC
    ssl->peerEccKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->peerEccKey == NULL) {
        CYASSL_MSG("PeerEccKey Memory error");
        return MEMORY_E;
    }
    ssl->peerEccDsaKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->peerEccDsaKey == NULL) {
        CYASSL_MSG("PeerEccDsaKey Memory error");
        return MEMORY_E;
    }
    ssl->eccDsaKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccDsaKey == NULL) {
        CYASSL_MSG("EccDsaKey Memory error");
        return MEMORY_E;
    }
    ssl->eccTempKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccTempKey == NULL) {
        CYASSL_MSG("EccTempKey Memory error");
        return MEMORY_E;
    }
    ecc_init(ssl->peerEccKey);
    ecc_init(ssl->peerEccDsaKey);
    ecc_init(ssl->eccDsaKey);
    ecc_init(ssl->eccTempKey);
#endif
#ifdef HAVE_SECRET_CALLBACK
    ssl->sessionSecretCb  = NULL;
    ssl->sessionSecretCtx = NULL;
#endif

    /* make sure server has DH parms, and add PSK if there, add NTRU too */
    if (ssl->options.side == CYASSL_SERVER_END)
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    else
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, TRUE,
                   ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                   ssl->options.haveStaticECC, ssl->options.side);

    return 0;
}

#ifdef __MORPHOS__
void SSL_set_socketbase(CYASSL* ssl, struct Library *socketbase)
{
    ssl->socketbase = socketbase;
}
#endif

/* free use of temporary arrays */
void FreeArrays(CYASSL* ssl, int keep)
{
    if (ssl->arrays && keep) {
        /* keeps session id for user retrieval */
        XMEMCPY(ssl->session.sessionID, ssl->arrays->sessionID, ID_LEN);
        ssl->session.sessionIDSz = ssl->arrays->sessionIDSz;
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}


/* In case holding SSL object in array and don't want to free actual ssl */
void SSL_ResourceFree(CYASSL* ssl)
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which may optionally be kept for the whole session. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    FreeCiphers(ssl);
    FreeArrays(ssl, 0);
#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    FreeRng(ssl->rng);
#endif
    XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

#ifndef NO_CERTS
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH || ssl->options.side == CYASSL_CLIENT_END) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_DH);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    }

    if (ssl->buffers.weOwnCert)
        XFREE(ssl->buffers.certificate.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnCertChain)
        XFREE(ssl->buffers.certChain.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnKey)
        XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
#endif
#ifndef NO_RSA
    if (ssl->peerRsaKey) {
        FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
    }
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
#ifdef CYASSL_DTLS
    if (ssl->dtls_pool != NULL) {
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_NONE);
    }
    if (ssl->dtls_msg_list != NULL) {
        DtlsMsgListDelete(ssl->dtls_msg_list, ssl->heap);
        ssl->dtls_msg_list = NULL;
    }
    XFREE(ssl->buffers.dtlsCtx.peer.sa, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    ssl->buffers.dtlsCtx.peer.sa = NULL;
#endif
#if defined(KEEP_PEER_CERT) || defined(GOAHEAD_WS)
    FreeX509(&ssl->peerCert);
#endif
#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
    CyaSSL_BIO_free(ssl->biord);
    if (ssl->biord != ssl->biowr)        /* in case same as write */
        CyaSSL_BIO_free(ssl->biowr);
#endif
#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif
#ifdef HAVE_ECC
    if (ssl->peerEccKey) {
        if (ssl->peerEccKeyPresent)
            ecc_free(ssl->peerEccKey);
        XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->peerEccDsaKey) {
        if (ssl->peerEccDsaKeyPresent)
            ecc_free(ssl->peerEccDsaKey);
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->eccTempKey) {
        if (ssl->eccTempKeyPresent)
            ecc_free(ssl->eccTempKey);
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->eccDsaKey) {
        if (ssl->eccDsaKeyPresent)
            ecc_free(ssl->eccDsaKey);
        XFREE(ssl->eccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(ssl->extensions);
#endif
#ifdef HAVE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPacket);
#endif
#ifdef __MORPHOS__
	 ssl->socketbase = NULL;
#endif
}


/* Free any handshake resources no longer needed */
void FreeHandshakeResources(CYASSL* ssl)
{

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        CYASSL_MSG("Secure Renegotiation needs to retain handshake resources");
        return;
    }
#endif

    /* input buffer */
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    /* suites */
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    ssl->suites = NULL;

    /* RNG */
    if (ssl->specs.cipher_type == stream || ssl->options.tls1_1 == 0) {
#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
        FreeRng(ssl->rng);
#endif
        XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
        ssl->rng = NULL;
    }

#ifdef CYASSL_DTLS
    /* DTLS_POOL */
    if (ssl->options.dtls && ssl->dtls_pool != NULL) {
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        ssl->dtls_pool = NULL;
    }
#endif

    /* arrays */
    if (ssl->options.saveArrays)
        FreeArrays(ssl, 1);

#ifndef NO_RSA
    /* peerRsaKey */
    if (ssl->peerRsaKey) {
        FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->peerRsaKey = NULL;
    }
#endif

#ifdef HAVE_ECC
    if (ssl->peerEccKey)
    {
        if (ssl->peerEccKeyPresent) {
            ecc_free(ssl->peerEccKey);
            ssl->peerEccKeyPresent = 0;
        }
        XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->peerEccKey = NULL;
    }
    if (ssl->peerEccDsaKey)
    {
        if (ssl->peerEccDsaKeyPresent) {
            ecc_free(ssl->peerEccDsaKey);
            ssl->peerEccDsaKeyPresent = 0;
        }
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->peerEccDsaKey = NULL;
    }
    if (ssl->eccTempKey)
    {
        if (ssl->eccTempKeyPresent) {
            ecc_free(ssl->eccTempKey);
            ssl->eccTempKeyPresent = 0;
        }
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->eccTempKey = NULL;
    }
    if (ssl->eccDsaKey)
    {
        if (ssl->eccDsaKeyPresent) {
            ecc_free(ssl->eccDsaKey);
            ssl->eccDsaKeyPresent = 0;
        }
        XFREE(ssl->eccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->eccDsaKey = NULL;
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->buffers.peerEccDsaKey.buffer = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->buffers.peerRsaKey.buffer = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
}


void FreeSSL(CYASSL* ssl)
{
    FreeSSL_Ctx(ssl->ctx);  /* will decrement and free underyling CTX if 0 */
    SSL_ResourceFree(ssl);
    XFREE(ssl, ssl->heap, DYNAMIC_TYPE_SSL);
}


#ifdef CYASSL_DTLS

int DtlsPoolInit(CYASSL* ssl)
{
    if (ssl->dtls_pool == NULL) {
        DtlsPool *pool = (DtlsPool*)XMALLOC(sizeof(DtlsPool),
                                             ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        if (pool == NULL) {
            CYASSL_MSG("DTLS Buffer Pool Memory error");
            return MEMORY_E;
        }
        else {
            int i;

            for (i = 0; i < DTLS_POOL_SZ; i++) {
                pool->buf[i].length = 0;
                pool->buf[i].buffer = NULL;
            }
            pool->used = 0;
            ssl->dtls_pool = pool;
        }
    }
    return 0;
}


int DtlsPoolSave(CYASSL* ssl, const byte *src, int sz)
{
    DtlsPool *pool = ssl->dtls_pool;
    if (pool != NULL && pool->used < DTLS_POOL_SZ) {
        buffer *pBuf = &pool->buf[pool->used];
        pBuf->buffer = (byte*)XMALLOC(sz, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        if (pBuf->buffer == NULL) {
            CYASSL_MSG("DTLS Buffer Memory error");
            return MEMORY_ERROR;
        }
        XMEMCPY(pBuf->buffer, src, sz);
        pBuf->length = (word32)sz;
        pool->used++;
    }
    return 0;
}


void DtlsPoolReset(CYASSL* ssl)
{
    DtlsPool *pool = ssl->dtls_pool;
    if (pool != NULL) {
        buffer *pBuf;
        int i, used;

        used = pool->used;
        for (i = 0, pBuf = &pool->buf[0]; i < used; i++, pBuf++) {
            XFREE(pBuf->buffer, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
            pBuf->buffer = NULL;
            pBuf->length = 0;
        }
        pool->used = 0;
    }
    ssl->dtls_timeout = ssl->dtls_timeout_init;
}


int DtlsPoolTimeout(CYASSL* ssl)
{
    int result = -1;
    if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
        ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
        result = 0;
    }
    return result;
}


int DtlsPoolSend(CYASSL* ssl)
{
    int ret;
    DtlsPool *pool = ssl->dtls_pool;

    if (pool != NULL && pool->used > 0) {
        int i;
        for (i = 0; i < pool->used; i++) {
            int sendResult;
            buffer* buf = &pool->buf[i];

            DtlsRecordLayerHeader* dtls = (DtlsRecordLayerHeader*)buf->buffer;

            word16 message_epoch;
            ato16(dtls->epoch, &message_epoch);
            if (message_epoch == ssl->keys.dtls_epoch) {
                /* Increment record sequence number on retransmitted handshake
                 * messages */
                c32to48(ssl->keys.dtls_sequence_number, dtls->sequence_number);
                ssl->keys.dtls_sequence_number++;
            }
            else {
                /* The Finished message is sent with the next epoch, keep its
                 * sequence number */
            }

            if ((ret = CheckAvailableSize(ssl, buf->length)) != 0)
                return ret;

            XMEMCPY(ssl->buffers.outputBuffer.buffer, buf->buffer, buf->length);
            ssl->buffers.outputBuffer.idx = 0;
            ssl->buffers.outputBuffer.length = buf->length;

            sendResult = SendBuffered(ssl);
            if (sendResult < 0) {
                return sendResult;
            }
        }
    }
    return 0;
}


/* functions for managing DTLS datagram reordering */

/* Need to allocate space for the handshake message header. The hashing
 * routines assume the message pointer is still within the buffer that
 * has the headers, and will include those headers in the hash. The store
 * routines need to take that into account as well. New will allocate
 * extra space for the headers. */
DtlsMsg* DtlsMsgNew(word32 sz, void* heap)
{
    DtlsMsg* msg = NULL;

    msg = (DtlsMsg*)XMALLOC(sizeof(DtlsMsg), heap, DYNAMIC_TYPE_DTLS_MSG);

    if (msg != NULL) {
        msg->buf = (byte*)XMALLOC(sz + DTLS_HANDSHAKE_HEADER_SZ,
                                                     heap, DYNAMIC_TYPE_NONE);
        if (msg->buf != NULL) {
            msg->next = NULL;
            msg->seq = 0;
            msg->sz = sz;
            msg->fragSz = 0;
            msg->msg = msg->buf + DTLS_HANDSHAKE_HEADER_SZ;
        }
        else {
            XFREE(msg, heap, DYNAMIC_TYPE_DTLS_MSG);
            msg = NULL;
        }
    }

    return msg;
}

void DtlsMsgDelete(DtlsMsg* item, void* heap)
{
    (void)heap;

    if (item != NULL) {
        if (item->buf != NULL)
            XFREE(item->buf, heap, DYNAMIC_TYPE_NONE);
        XFREE(item, heap, DYNAMIC_TYPE_DTLS_MSG);
    }
}


void DtlsMsgListDelete(DtlsMsg* head, void* heap)
{
    DtlsMsg* next;
    while (head) {
        next = head->next;
        DtlsMsgDelete(head, heap);
        head = next;
    }
}


void DtlsMsgSet(DtlsMsg* msg, word32 seq, const byte* data, byte type,
                                              word32 fragOffset, word32 fragSz)
{
    if (msg != NULL && data != NULL && msg->fragSz <= msg->sz &&
                     fragOffset < msg->sz && (fragOffset + fragSz) <= msg->sz) {

        msg->seq = seq;
        msg->type = type;
        msg->fragSz += fragSz;
        /* If fragOffset is zero, this is either a full message that is out
         * of order, or the first fragment of a fragmented message. Copy the
         * handshake message header as well as the message data. */
        if (fragOffset == 0)
            XMEMCPY(msg->buf, data - DTLS_HANDSHAKE_HEADER_SZ,
                                            fragSz + DTLS_HANDSHAKE_HEADER_SZ);
        else {
            /* If fragOffet is non-zero, this is an additional fragment that
             * needs to be copied to its location in the message buffer. Also
             * copy the total size of the message over the fragment size. The
             * hash routines look at a defragmented message if it had actually
             * come across as a single handshake message. */
            XMEMCPY(msg->msg + fragOffset, data, fragSz);
            c32to24(msg->sz, msg->msg - DTLS_HANDSHAKE_FRAG_SZ);
        }
    }
}


DtlsMsg* DtlsMsgFind(DtlsMsg* head, word32 seq)
{
    while (head != NULL && head->seq != seq) {
        head = head->next;
    }
    return head;
}


DtlsMsg* DtlsMsgStore(DtlsMsg* head, word32 seq, const byte* data,
        word32 dataSz, byte type, word32 fragOffset, word32 fragSz, void* heap)
{

    /* See if seq exists in the list. If it isn't in the list, make
     * a new item of size dataSz, copy fragSz bytes from data to msg->msg
     * starting at offset fragOffset, and add fragSz to msg->fragSz. If
     * the seq is in the list and it isn't full, copy fragSz bytes from
     * data to msg->msg starting at offset fragOffset, and add fragSz to
     * msg->fragSz. The new item should be inserted into the list in its
     * proper position.
     *
     * 1. Find seq in list, or where seq should go in list. If seq not in
     *    list, create new item and insert into list. Either case, keep
     *    pointer to item.
     * 2. If msg->fragSz + fragSz < sz, copy data to msg->msg at offset
     *    fragOffset. Add fragSz to msg->fragSz.
     */

    if (head != NULL) {
        DtlsMsg* cur = DtlsMsgFind(head, seq);
        if (cur == NULL) {
            cur = DtlsMsgNew(dataSz, heap);
            if (cur != NULL) {
                DtlsMsgSet(cur, seq, data, type, fragOffset, fragSz);
                head = DtlsMsgInsert(head, cur);
            }
        }
        else {
            DtlsMsgSet(cur, seq, data, type, fragOffset, fragSz);
        }
    }
    else {
        head = DtlsMsgNew(dataSz, heap);
        DtlsMsgSet(head, seq, data, type, fragOffset, fragSz);
    }

    return head;
}


/* DtlsMsgInsert() is an in-order insert. */
DtlsMsg* DtlsMsgInsert(DtlsMsg* head, DtlsMsg* item)
{
    if (head == NULL || item->seq < head->seq) {
        item->next = head;
        head = item;
    }
    else if (head->next == NULL) {
        head->next = item;
    }
    else {
        DtlsMsg* cur = head->next;
        DtlsMsg* prev = head;
        while (cur) {
            if (item->seq < cur->seq) {
                item->next = cur;
                prev->next = item;
                break;
            }
            prev = cur;
            cur = cur->next;
        }
        if (cur == NULL) {
            prev->next = item;
        }
    }

    return head;
}

#endif /* CYASSL_DTLS */

#ifndef NO_OLD_TLS

ProtocolVersion MakeSSLv3(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = SSLv3_MINOR;

    return pv;
}

#endif /* NO_OLD_TLS */


#ifdef CYASSL_DTLS

ProtocolVersion MakeDTLSv1(void)
{
    ProtocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor = DTLS_MINOR;

    return pv;
}

ProtocolVersion MakeDTLSv1_2(void)
{
    ProtocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_2_MINOR;

    return pv;
}

#endif /* CYASSL_DTLS */




#ifdef USE_WINDOWS_API

    word32 LowResTimer(void)
    {
        static int           init = 0;
        static LARGE_INTEGER freq;
        LARGE_INTEGER        count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / freq.QuadPart);
    }

#elif defined(HAVE_RTP_SYS)

    #include "rtptime.h"

    word32 LowResTimer(void)
    {
        return (word32)rtp_get_system_sec();
    }


#elif defined(MICRIUM)

    word32 LowResTimer(void)
    {
        NET_SECURE_OS_TICK  clk;

        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            clk = NetSecure_OS_TimeGet();
        #endif
        return (word32)clk;
    }


#elif defined(MICROCHIP_TCPIP_V5)

    word32 LowResTimer(void)
    {
        return (word32) TickGet();
    }


#elif defined(MICROCHIP_TCPIP)

    #if defined(MICROCHIP_MPLAB_HARMONY)

        #include <system/tmr/sys_tmr.h>

        word32 LowResTimer(void)
        {
            return (word32) SYS_TMR_TickCountGet();
        }

    #else

        word32 LowResTimer(void)
        {
            return (word32) SYS_TICK_Get();
        }

    #endif

#elif defined(FREESCALE_MQX)

    word32 LowResTimer(void)
    {
        TIME_STRUCT mqxTime;

        _time_get_elapsed(&mqxTime);

        return (word32) mqxTime.SECONDS;
    }

#elif defined(CYASSL_TIRTOS)

    word32 LowResTimer(void)
    {
        return (word32) MYTIME_gettime();
    }

#elif defined(USER_TICKS)
#if 0
    word32 LowResTimer(void)
    {
        /*
        write your own clock tick function if don't want time(0)
        needs second accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif
#else /* !USE_WINDOWS_API && !HAVE_RTP_SYS && !MICRIUM && !USER_TICKS */

    #include <time.h>

    word32 LowResTimer(void)
    {
        return (word32)time(0);
    }


#endif /* USE_WINDOWS_API */


/* add output to md5 and sha handshake hashes, exclude record header */
static int HashOutput(CYASSL* ssl, const byte* output, int sz, int ivSz)
{
    const byte* adj = output + RECORD_HEADER_SZ + ivSz;
    sz -= RECORD_HEADER_SZ;

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, output, sz, FUZZ_HASH, ssl->fuzzerCtx);
#endif
#ifdef CYASSL_DTLS
    if (ssl->options.dtls) {
        adj += DTLS_RECORD_EXTRA;
        sz  -= DTLS_RECORD_EXTRA;
    }
#endif
#ifndef NO_OLD_TLS
#ifndef NO_SHA
    ShaUpdate(&ssl->hashSha, adj, sz);
#endif
#ifndef NO_MD5
    Md5Update(&ssl->hashMd5, adj, sz);
#endif
#endif

    if (IsAtLeastTLSv1_2(ssl)) {
        int ret;

#ifndef NO_SHA256
        ret = Sha256Update(&ssl->hashSha256, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef CYASSL_SHA384
        ret = Sha384Update(&ssl->hashSha384, adj, sz);
        if (ret != 0)
            return ret;
#endif
    }

    return 0;
}


/* add input to md5 and sha handshake hashes, include handshake header */
static int HashInput(CYASSL* ssl, const byte* input, int sz)
{
    const byte* adj = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

#ifdef CYASSL_DTLS
    if (ssl->options.dtls) {
        adj -= DTLS_HANDSHAKE_EXTRA;
        sz  += DTLS_HANDSHAKE_EXTRA;
    }
#endif

#ifndef NO_OLD_TLS
#ifndef NO_SHA
    ShaUpdate(&ssl->hashSha, adj, sz);
#endif
#ifndef NO_MD5
    Md5Update(&ssl->hashMd5, adj, sz);
#endif
#endif

    if (IsAtLeastTLSv1_2(ssl)) {
        int ret;

#ifndef NO_SHA256
        ret = Sha256Update(&ssl->hashSha256, adj, sz);
        if (ret != 0)
            return ret;
#endif
#ifdef CYASSL_SHA384
        ret = Sha384Update(&ssl->hashSha384, adj, sz);
        if (ret != 0)
            return ret;
#endif
    }

    return 0;
}


/* add record layer header for message */
static void AddRecordHeader(byte* output, word32 length, byte type, CYASSL* ssl)
{
    RecordLayerHeader* rl;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    rl->type    = type;
    rl->pvMajor = ssl->version.major;       /* type and version same in each */
    rl->pvMinor = ssl->version.minor;

    if (!ssl->options.dtls)
        c16toa((word16)length, rl->length);
    else {
#ifdef CYASSL_DTLS
        DtlsRecordLayerHeader* dtls;

        /* dtls record layer header extensions */
        dtls = (DtlsRecordLayerHeader*)output;
        c16toa(ssl->keys.dtls_epoch, dtls->epoch);
        c32to48(ssl->keys.dtls_sequence_number++, dtls->sequence_number);
        c16toa((word16)length, dtls->length);
#endif
    }
}


/* add handshake header for message */
static void AddHandShakeHeader(byte* output, word32 length, byte type,
                               CYASSL* ssl)
{
    HandShakeHeader* hs;
    (void)ssl;

    /* handshake header */
    hs = (HandShakeHeader*)output;
    hs->type = type;
    c32to24(length, hs->length);         /* type and length same for each */
#ifdef CYASSL_DTLS
    if (ssl->options.dtls) {
        DtlsHandShakeHeader* dtls;

        /* dtls handshake header extensions */
        dtls = (DtlsHandShakeHeader*)output;
        c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq);
        c32to24(0, dtls->fragment_offset);
        c32to24(length, dtls->fragment_length);
    }
#endif
}


/* add both headers for handshake message */
static void AddHeaders(byte* output, word32 length, byte type, CYASSL* ssl)
{
    if (!ssl->options.dtls) {
        AddRecordHeader(output, length + HANDSHAKE_HEADER_SZ, handshake, ssl);
        AddHandShakeHeader(output + RECORD_HEADER_SZ, length, type, ssl);
    }
#ifdef CYASSL_DTLS
    else  {
        AddRecordHeader(output, length+DTLS_HANDSHAKE_HEADER_SZ, handshake,ssl);
        AddHandShakeHeader(output + DTLS_RECORD_HEADER_SZ, length, type, ssl);
    }
#endif
}


/* return bytes received, -1 on error */
static int Receive(CYASSL* ssl, byte* buf, word32 sz)
{
    int recvd;

    if (ssl->ctx->CBIORecv == NULL) {
        CYASSL_MSG("Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssl->ctx->CBIORecv(ssl, (char *)buf, (int)sz, ssl->IOCB_ReadCtx);
    if (recvd < 0)
        switch (recvd) {
            case CYASSL_CBIO_ERR_GENERAL:        /* general/unknown error */
                return -1;

            case CYASSL_CBIO_ERR_WANT_READ:      /* want read, would block */
                return WANT_READ;

            case CYASSL_CBIO_ERR_CONN_RST:       /* connection reset */
                #ifdef USE_WINDOWS_API
                if (ssl->options.dtls) {
                    goto retry;
                }
                #endif
                ssl->options.connReset = 1;
                return -1;

            case CYASSL_CBIO_ERR_ISR:            /* interrupt */
                /* see if we got our timeout */
                #ifdef CYASSL_CALLBACKS
                    if (ssl->toInfoOn) {
                        struct itimerval timeout;
                        getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                            XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                    "recv() timeout", MAX_TIMEOUT_NAME_SZ);
                            CYASSL_MSG("Got our timeout");
                            return WANT_READ;
                        }
                    }
                #endif
                goto retry;

            case CYASSL_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssl->options.isClosed = 1;
                return -1;

            case CYASSL_CBIO_ERR_TIMEOUT:
#ifdef CYASSL_DTLS
                if (DtlsPoolTimeout(ssl) == 0 && DtlsPoolSend(ssl) == 0)
                    goto retry;
                else
#endif
                    return -1;

            default:
                return recvd;
        }

    return recvd;
}


/* Switch dynamic output buffer back to static, buffer is assumed clear */
void ShrinkOutputBuffer(CYASSL* ssl)
{
    CYASSL_MSG("Shrinking output buffer\n");
    XFREE(ssl->buffers.outputBuffer.buffer - ssl->buffers.outputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
}


/* Switch dynamic input buffer back to static, keep any remaining input */
/* forced free means cleaning up */
void ShrinkInputBuffer(CYASSL* ssl, int forcedFree)
{
    int usedLength = ssl->buffers.inputBuffer.length -
                     ssl->buffers.inputBuffer.idx;
    if (!forcedFree && usedLength > STATIC_BUFFER_LEN)
        return;

    CYASSL_MSG("Shrinking input buffer\n");

    if (!forcedFree && usedLength)
        XMEMCPY(ssl->buffers.inputBuffer.staticBuffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
               usedLength);

    XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset      = 0;
    ssl->buffers.inputBuffer.idx = 0;
    ssl->buffers.inputBuffer.length = usedLength;
}


int SendBuffered(CYASSL* ssl)
{
	CYASSL_ENTER("send buffered");
    if (ssl->ctx->CBIOSend == NULL) {
        CYASSL_MSG("Your IO Send callback is null, please set");
        return SOCKET_ERROR_E;
    }

    while (ssl->buffers.outputBuffer.length > 0) {
    		int sent = ssl->ctx->CBIOSend(ssl,
                                      (char*)ssl->buffers.outputBuffer.buffer +
                                      ssl->buffers.outputBuffer.idx,
                                      (int)ssl->buffers.outputBuffer.length,
                                      ssl->IOCB_WriteCtx);
        
        if (sent < 0) {
            switch (sent) {

                case CYASSL_CBIO_ERR_WANT_WRITE:        /* would block */
                    return WANT_WRITE;

                case CYASSL_CBIO_ERR_CONN_RST:          /* connection reset */
                    ssl->options.connReset = 1;
                    break;

                case CYASSL_CBIO_ERR_ISR:               /* interrupt */
                    /* see if we got our timeout */
                    #ifdef CYASSL_CALLBACKS
                        if (ssl->toInfoOn) {
                            struct itimerval timeout;
                            getitimer(ITIMER_REAL, &timeout);
                            if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                                XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                        "send() timeout", MAX_TIMEOUT_NAME_SZ);
                                CYASSL_MSG("Got our timeout");
                                return WANT_WRITE;
                            }
                        }
                    #endif
                    continue;

                case CYASSL_CBIO_ERR_CONN_CLOSE: /* epipe / conn closed */
                    ssl->options.connReset = 1;  /* treat same as reset */
                    break;

                default:
                    return SOCKET_ERROR_E;
            }

            return SOCKET_ERROR_E;
        }

        if (sent > (int)ssl->buffers.outputBuffer.length) {
            CYASSL_MSG("SendBuffered() out of bounds read");
            return SEND_OOB_READ_E;
        }

        ssl->buffers.outputBuffer.idx += sent;
        ssl->buffers.outputBuffer.length -= sent;
    }

    ssl->buffers.outputBuffer.idx = 0;

    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);

    return 0;
}


/* Grow the output buffer */
static INLINE int GrowOutputBuffer(CYASSL* ssl, int size)
{
    byte* tmp;
    byte  hdrSz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ :
                                      RECORD_HEADER_SZ;
    byte  align = CYASSL_GENERAL_ALIGNMENT;
    /* the encrypted data will be offset from the front of the buffer by
       the header, if the user wants encrypted alignment they need
       to define their alignment requirement */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }

    tmp = (byte*) XMALLOC(size + ssl->buffers.outputBuffer.length + align,
                          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    CYASSL_MSG("growing output buffer\n");

    if (!tmp) return MEMORY_E;
    
    if (align)
        tmp += align - hdrSz;

    if (ssl->buffers.outputBuffer.length)
        XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
               ssl->buffers.outputBuffer.length);

    if (ssl->buffers.outputBuffer.dynamicFlag)
        XFREE(ssl->buffers.outputBuffer.buffer -
              ssl->buffers.outputBuffer.offset, ssl->heap,
              DYNAMIC_TYPE_OUT_BUFER);

    ssl->buffers.outputBuffer.dynamicFlag = 1;

    if (align)
        ssl->buffers.outputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.outputBuffer.offset = 0;

    ssl->buffers.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffer.bufferSize = size +
                                           ssl->buffers.outputBuffer.length;
    return 0;
}


/* Grow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(CYASSL* ssl, int size, int usedLength)
{
    byte* tmp;
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;
    byte  align = ssl->options.dtls ? CYASSL_GENERAL_ALIGNMENT : 0;
    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
    tmp = (byte*) XMALLOC(size + usedLength + align, ssl->heap,
                          DYNAMIC_TYPE_IN_BUFFER);
    CYASSL_MSG("growing input buffer\n");

    if (!tmp) return MEMORY_E;
    if (align)
        tmp += align - hdrSz;

    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag)
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap,DYNAMIC_TYPE_IN_BUFFER);

    ssl->buffers.inputBuffer.dynamicFlag = 1;
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.inputBuffer.offset = 0;
    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    return 0;
}


/* check available size into output buffer, make room if needed */
int CheckAvailableSize(CYASSL *ssl, int size)
{

    if (size < 0) {
        CYASSL_MSG("CheckAvailableSize() called with negative number");
        return BAD_FUNC_ARG;
    }

    if (ssl->buffers.outputBuffer.bufferSize - ssl->buffers.outputBuffer.length
                                             < (word32)size) {
        if (GrowOutputBuffer(ssl, size) < 0)
            return MEMORY_E;
    }

    return 0;
}


/* do all verify and sanity checks on record header */
static int GetRecordHeader(CYASSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    if (!ssl->options.dtls) {
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx, RECORD_HEADER_SZ, FUZZ_HEAD,
                    ssl->fuzzerCtx);
#endif
        XMEMCPY(rh, input + *inOutIdx, RECORD_HEADER_SZ);
        *inOutIdx += RECORD_HEADER_SZ;
        ato16(rh->length, size);
    }
    else {
#ifdef CYASSL_DTLS
        /* type and version in same sport */
        XMEMCPY(rh, input + *inOutIdx, ENUM_LEN + VERSION_SZ);
        *inOutIdx += ENUM_LEN + VERSION_SZ;
        ato16(input + *inOutIdx, &ssl->keys.dtls_state.curEpoch);
        *inOutIdx += 4; /* advance past epoch, skip first 2 seq bytes for now */
        ato32(input + *inOutIdx, &ssl->keys.dtls_state.curSeq);
        *inOutIdx += 4;  /* advance past rest of seq */
        ato16(input + *inOutIdx, size);
        *inOutIdx += LENGTH_SZ;
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx - LENGTH_SZ - 8 - ENUM_LEN -
                           VERSION_SZ, ENUM_LEN + VERSION_SZ + 8 + LENGTH_SZ,
                           FUZZ_HEAD, ssl->fuzzerCtx);
#endif
#endif
    }

    /* catch version mismatch */
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor){
        if (ssl->options.side == CYASSL_SERVER_END &&
            ssl->options.acceptState == ACCEPT_BEGIN)
            CYASSL_MSG("Client attempting to connect with different version");
        else if (ssl->options.side == CYASSL_CLIENT_END &&
                                 ssl->options.downgrade &&
                                 ssl->options.connectState < FIRST_REPLY_DONE)
            CYASSL_MSG("Server attempting to accept with different version");
        else {
            CYASSL_MSG("SSL version error");
            return VERSION_ERROR;              /* only use requested version */
        }
    }

#ifdef CYASSL_DTLS
    if (ssl->options.dtls) {
        if (DtlsCheckWindow(&ssl->keys.dtls_state) != 1)
            return SEQUENCE_ERROR;
    }
#endif

    /* record layer length check */
#ifdef HAVE_MAX_FRAGMENT
    if (*size > (ssl->max_fragment + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        SendAlert(ssl, alert_fatal, record_overflow);
        return LENGTH_ERROR;
    }
#else
    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA))
        return LENGTH_ERROR;
#endif

    /* verify record type here as well */
    switch (rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
            break;
        case no_type:
        default:
            CYASSL_MSG("Unknown Record Type");
            return UNKNOWN_RECORD_TYPE;
    }

    /* haven't decrypted this record yet */
    ssl->keys.decryptedCur = 0;

    return 0;
}


static int GetHandShakeHeader(CYASSL* ssl, const byte* input, word32* inOutIdx,
                              byte *type, word32 *size, word32 totalSz)
{
    const byte *ptr = input + *inOutIdx;
    (void)ssl;

    *inOutIdx += HANDSHAKE_HEADER_SZ;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = ptr[0];
    c24to32(&ptr[1], size);

    return 0;
}


#ifdef CYASSL_DTLS
static int GetDtlsHandShakeHeader(CYASSL* ssl, const byte* input,
                                  word32* inOutIdx, byte *type, word32 *size,
                                  word32 *fragOffset, word32 *fragSz,
                                  word32 totalSz)
{
    word32 idx = *inOutIdx;

    *inOutIdx += HANDSHAKE_HEADER_SZ + DTLS_HANDSHAKE_EXTRA;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = input[idx++];
    c24to32(input + idx, size);
    idx += BYTE3_LEN;

    ato16(input + idx, &ssl->keys.dtls_peer_handshake_number);
    idx += DTLS_HANDSHAKE_SEQ_SZ;

    c24to32(input + idx, fragOffset);
    idx += DTLS_HANDSHAKE_FRAG_SZ;
    c24to32(input + idx, fragSz);

    return 0;
}
#endif


#ifndef NO_OLD_TLS
/* fill with MD5 pad size since biggest required */
static const byte PAD1[PAD_MD5] =
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
static const byte PAD2[PAD_MD5] =
                              { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };

/* calculate MD5 hash for finished */
static void BuildMD5(CYASSL* ssl, Hashes* hashes, const byte* sender)
{
    byte md5_result[MD5_DIGEST_SIZE];

    /* make md5 inner */
    Md5Update(&ssl->hashMd5, sender, SIZEOF_SENDER);
    Md5Update(&ssl->hashMd5, ssl->arrays->masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD1, PAD_MD5);
    Md5Final(&ssl->hashMd5, md5_result);

    /* make md5 outer */
    Md5Update(&ssl->hashMd5, ssl->arrays->masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD2, PAD_MD5);
    Md5Update(&ssl->hashMd5, md5_result, MD5_DIGEST_SIZE);

    Md5Final(&ssl->hashMd5, hashes->md5);
}


/* calculate SHA hash for finished */
static void BuildSHA(CYASSL* ssl, Hashes* hashes, const byte* sender)
{
    byte sha_result[SHA_DIGEST_SIZE];

    /* make sha inner */
    ShaUpdate(&ssl->hashSha, sender, SIZEOF_SENDER);
    ShaUpdate(&ssl->hashSha, ssl->arrays->masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD1, PAD_SHA);
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    ShaUpdate(&ssl->hashSha, ssl->arrays->masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD2, PAD_SHA);
    ShaUpdate(&ssl->hashSha, sha_result, SHA_DIGEST_SIZE);

    ShaFinal(&ssl->hashSha, hashes->sha);
}
#endif


static int BuildFinished(CYASSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;
#ifdef CYASSL_SMALL_STACK
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        Md5* md5 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifndef NO_SHA
        Sha* sha = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #endif
    #ifndef NO_SHA256
        Sha256* sha256 = (Sha256*)XMALLOC(sizeof(Sha256), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifdef CYASSL_SHA384
        Sha384* sha384 = (Sha384*)XMALLOC(sizeof(Sha384), NULL,                                                                        DYNAMIC_TYPE_TMP_BUFFER);
    #endif
#else
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        Md5 md5[1];
    #endif
    #ifndef NO_SHA
        Sha sha[1];
    #endif
    #endif
    #ifndef NO_SHA256
        Sha256 sha256[1];
    #endif
    #ifdef CYASSL_SHA384
        Sha384 sha384[1];
    #endif
#endif

#ifdef CYASSL_SMALL_STACK
    if (ssl == NULL
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        || md5 == NULL
    #endif
    #ifndef NO_SHA
        || sha == NULL
    #endif
    #endif
    #ifndef NO_SHA256
        || sha256 == NULL
    #endif
    #ifdef CYASSL_SHA384
        || sha384 == NULL
    #endif
        ) {
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifndef NO_SHA
        XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #endif
    #ifndef NO_SHA256
        XFREE(sha256, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifdef CYASSL_SHA384
        XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return MEMORY_E;
    }
#endif

    /* store current states, building requires get_digest which resets state */
#ifndef NO_OLD_TLS
#ifndef NO_MD5
    md5[0] = ssl->hashMd5;
#endif
#ifndef NO_SHA
    sha[0] = ssl->hashSha;
    #endif
#endif
#ifndef NO_SHA256
    sha256[0] = ssl->hashSha256;
#endif
#ifdef CYASSL_SHA384
    sha384[0] = ssl->hashSha384;
#endif

#ifndef NO_TLS
    if (ssl->options.tls) {
        ret = BuildTlsFinished(ssl, hashes, sender);
    }
#endif
#ifndef NO_OLD_TLS
    if (!ssl->options.tls) {
        BuildMD5(ssl, hashes, sender);
        BuildSHA(ssl, hashes, sender);
    }
#endif

    /* restore */
#ifndef NO_OLD_TLS
    #ifndef NO_MD5
        ssl->hashMd5 = md5[0];
    #endif
    #ifndef NO_SHA
    ssl->hashSha = sha[0];
    #endif
#endif
    if (IsAtLeastTLSv1_2(ssl)) {
    #ifndef NO_SHA256
        ssl->hashSha256 = sha256[0];
    #endif
    #ifdef CYASSL_SHA384
        ssl->hashSha384 = sha384[0];
    #endif
    }

#ifdef CYASSL_SMALL_STACK
#ifndef NO_OLD_TLS
#ifndef NO_MD5
    XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#ifndef NO_SHA
    XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif
#ifndef NO_SHA256
    XFREE(sha256, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#ifdef CYASSL_SHA384
    XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif

    return ret;
}


    /* cipher requirements */
    enum {
        REQUIRES_RSA,
        REQUIRES_DHE,
        REQUIRES_ECC_DSA,
        REQUIRES_ECC_STATIC,
        REQUIRES_PSK,
        REQUIRES_NTRU,
        REQUIRES_RSA_SIG
    };



    /* Does this cipher suite (first, second) have the requirement
       an ephemeral key exchange will still require the key for signing
       the key exchange so ECHDE_RSA requires an rsa key thus rsa_kea */
    static int CipherRequires(byte first, byte second, int requirement)
    {

        if (first == CHACHA_BYTE) {

        switch (second) {

        case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;
            }
        }

        /* ECC extensions */
        if (first == ECC_BYTE) {

        switch (second) {

#ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

#ifndef NO_DES3
        case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
#endif

#ifndef NO_RC4
        case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
#endif
#endif /* NO_RSA */

#ifndef NO_DES3
        case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
#endif
#ifndef NO_RC4
        case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
#endif
#ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
#endif

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

#ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_CCM_8 :
        case TLS_RSA_WITH_AES_256_CCM_8 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
#endif

        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :
        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

 ernal.ccase TLS_ECDHpyriSA_WITH_AES_128_CBC_SHA256 :ternal.c
 *
 * Copyright (C) 2006-2014256lfSSL In384 *
 * This ; yoif (requirement == REQUIREopyrC_DSA)software; youhe treturn 1;software; you can redistribute it and/or modiSTATIC * it under the terms of the GNU Generalbr/* internal.c
 *
 * CopPSK 2006-2014 wolfCM*
 * This file is p (at your opt CyaSany later version.
 *
 * CyaSSL ision) an_8y later version.
 *
 * CyaSSL is distril,
 * but WI you can redistribute it and/or PSK Free Software Foundation; either version 2 of the License, or
 *DHE* (at your option) any later version.
 *ic License for mo distributed in tied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  Se can redistribute it and/or DHE Free Software Foundation; either version 2 of the Licendefaultof the GNU GenCYASSL_MSG("Unsupported cipher suite, C<confRredists ECC")he GNU Generalrms of 0he GNU Gen}   /* switch */>

#include <cyaifU Genernal.h>
#i canfirst != <cy_BYTE) {e <cyanormalig.h>
sl/error-ssl.ssl/int(second) {

#ifndef NO_RSAternal.c
 *
 *CONFRC) 2006-RC4be usSHAe software; you can redistribute it and/or Ry
 * it under the terms of the GNU Generaln 2 of the License, or
 *NTRU #include "ntru_crypto.h"
#endif

#if defined(DEBUG_CYASSL) || dLE_Mned(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FRE    #include "ntru_crMD5o.h"
#endif

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FRE    #include 3Dor mDElfSSL Ino.h"
#endif

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCALE_MQX
       FERS)
    #error \
CYASSL_CALLBACKS needs LARGE_STATIC_BUFF
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endi Cop#include 2014 wolfSSL Ino.h"
#endif

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCA
static int BuildMessagec.
 *
 * This 

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCALE_MQX
       nt BuildMessage(CYASSL* ssl, byte* output, int outSz,
    ot use both secure-renegotiation and renegotiation-indication
#endif

static int B CyaSSL is (CYASSL* ssl, byte* output, int outSz,
                        const byte* input, int inSz, int type);

#ifndef NO_CYASSL_CL CyaSSL is atic int DoHelloVerifyRequest(CYASSL* ssl, const byte* input, word32*,
                                           #include NULLrypto.h"
#endif                          atic int DoHelloVerifyRequest(CYASSL* ssl, const byte* input, word32*,
                                                             ASSL* ssl, const byte* input, word32*,
               
    #endif
#endif

#ifdef __sun
    #include <sys/#endif the License, or
 * (at your option)GCML Inc.
 *
 * This file is pave received a cot byte*free software;se, or
 * (at your option) SSL Inc.
 *
 * This file is pave received a copSL is free software;CYASSL* ssl, byte* input, word32*ord32);
    #if !defined(NO_RSA) || defined(ord32);
    #if !defined(NO_R        HAVE_ECC)
        static int DoC #endif
    #ifdef HAVE int DtlsCheckWindow(Dtlsc int DoHelloVerifyRequest(CYASSL* ssl, conTY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more dt byte* input, word32*, word32ld have received a co DoClientKeyExchange(CYASSL* sic License for more deSSL Inc.
 *
 * This file is pld have received a copfined(HAVE_ECC)
        statiic License fo_DTLS
    static INLINE int Dtlsz,
                 atic int DoHelloVerifyRequest(CYASSL* ssl, connc., 51 Franklin Street, Fifth Floor, BostotlsState* state);
#endif


typedef enum {
    doProcessInit = 0,
#ifndef NO_CYAh"
#endif

#ifdef HAVE_NTRU
 verify) NO_CYASSL_CLIENT
    static int DoHelloVerifyRequest(CYASSL* ssl, const byte* input, word32*,
                  ee Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301oSz);

#ifndef min

    stCERTS
        static int DoCertificateRequest(CYASSL* ssl, const byte* input, word32*,
             */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINORuildMessage(CYASSL* ssl, byte* output, int outSz,
                        const byte* input, int */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        rssl->version.minor <= DTLSv1_2_MINOR)
        return 1;

    return 0;
}


#ifdef HAVE_NTRU

static byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    /* TODO: add locking? */
    sta#include HC    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif


#if defined(CYASSL_CALLBACKS) && !defined(LAR= 0) ? 1 : 0;

    il, const byte* input, word32*,
                                                                        word32);
    #ifndef

    iB2B256CYASSL* ssl, byte* output, int outSz,
                        const byte* input, int inSz, int type);

#ifndef NO_CYASSL_CLIENT
    out[2] =  in & rd32);
    #ifndef NO_CERTS
   out[2] =  in & 0xff;
}


#ifdef CYASSL_DTLS

static INLINE void c32to48(word32 in, byte out[6])
{
    out[0] = 0;
    out[1]RABBIT

/* used by ssl.c too */
void c32to24(word32 in, word24 out)
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xientHello,
#endif
    getRecordLayerHe>=TLSv1_MINOR)
   DoClientKeyExchange(

#if defined(DEBUG_CYASSL) || defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifdef FREESCAfndef min

    statico,
#endif
    getRecordLayerHeader || defined(HAVE_AESCCM) \
    || defined(HAVE_AESGCM)
/* convert 32 bit integer to opaque */
static INLINE void rn 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;CAMELLIALS_MAJOR && ssl->versio24[0] << 16) | (u24[1] << 8rd32);
    #endif
#endif


#ifd16) | (u24[1] << 8) | u24[2];|| defined(HAVE_CHACHA) || definbit integer */
statiatic int DoHelloVerifyRequest(CYASSL* ssl, const byte* input, word32*,
                                            >> 16) & 0xf4[1] << 8) | u24[2];
}


/* convert opaqto32(const byte* c, word32);
    #endif
#endif


#ifdto32(const byte* c, word32* u32)
& 0xff;
    c[1] = (u32 >> 16) & 0xf) | (c[1]));
}


#if defined(CYASSL_DTLS) || defined(HAVE_SESSION_TICKET)

/* convert opaque to 32 bit integef defined(DEBUG_CYASSL) || defi_SIGth this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 0static #ifendiHAVE_ANON| c[3];
}

#endif /*_anonatic int BuildMessage(CYASSL* ssl, byte* output, int outSz,
    ee(void* opaque, void* memory)
    {
        (void)opaque2110-1301, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#includeassl/ctaocrypt/settings.h>

#include cyassl/internal.h>
#inclde <cyECC / Nsn.h>

#ifdefelsel/erternal.c
ettings.h>

#i}
igAlgo, word3CERTS


/* Ma/intnames with wildcards, eac ZLIB_INIT can represibuta single    rterncomponibutor fragributbut not mulitp 1;

  s, i.e.,tern*.z.com m    es yl->d_st = (allox.ee  = (ssl->rms of t on succesef HAstatic int      DomainName(const char* pattern,idpf)len,     if (inflstr)
{terna (in p, sinterna canateInitte i     ||OK) turn 0;
    len <= 0 * it undeettings.h>ternawhile (void> 0zlib.ernal.c
p = ( (in)XTOLOWER(*ateInit++ssl/ctaocry
    te ieeStreams(CAEAD_TEST)
    #ifde_stream);'*'zlib          in {
    --    if  &&treamnit) {
            deflateE)am);
   * it under the teinternal.c
l->d_strvoidm);
            inStreamIn'\0'ess(CYASSL* ssl {
     (sout, return out sizK) r)de <nt o      }
    }


l->d_strs in,pstatic int myComprAEAD_TEST)
nt)ssl->c_stream.total_ou'. static int myComprpt/settings.h>

#incluVE_LIBZ
 tr++xt_in   = in;
}>

#includt_in   = eInit    }
    }


_strea! err;
        int    cu* it under the terms of .h>

#includnd(&ssl->d_str    rrTotal =t_in   = in;
xt_out d(&ssl->d_str    if (t_in   = in;
len--EFAULT_COms(CYASSL* rr !=l->ct out_COM/* try to find an alt
   tream.  /*deap;
,    ssl->d_stream.opaque = (voidpf)CheckAss in s(DecodedCert*  ssl,,f (inflturnn return Zdpf)t outSzo out,=       iDNS_entry*ress in trn 0;
_COMPREVE_CONFIG_H
myDeCing ompress(asslROR;

    ssl,    return
        i ssl,->ess in _ERROR;
 {
    ess in       }
    VE_CONFIG_H
 out,idividualtream.to cyDeCal_out;

;

     ssl->heap;

    ess in ->   r,(int)XSTRLEN= outSz;

    ),inSz, by)    }
    }



    {
 ned(CHACHA_AEAD_TEST)
   if (err != Z_OK 
        i outSz;

 ext->c_stream.total_outream.;
    #if1, Uined(KEEP_PEER!= Z_)    am.totalSESSION!= Z_O)  }

Copy parts X509 needs from YASSL*  ce* in0d_stream.opaqueint mopyYASSL* ToitSS(VE_CONFitSS* x509,ASSL_METssl, byte* yte* out,intret{
    ROR;

   = pvturn 0;
    thod-turn 0;
eStreams(CYASSL* BAD_FUNC_ARGT_END;
= pv->version_in   = inss */
in+ (er= Z_Sr = NCPY meth->issuer.     n   = inOD* me, ASN_NAME_MAXssl/ctaL_METHOD* method)[d = method;
 - 1], int out ctx->refCount = szout,  err = inflL_METHOD* method))ASSL_C;
     OPENCONFEXTRfdef H        sctx->met
   .fullt  = !
}


/*out = outSzXMEMYASS&L_METHOD* met  = 0;
     sffer  = 0;
    ctx->serverDH_G.buffe&>certChain.buffer, sizeofCYASSL* vail_ssl/ctaocry0;
    ctx->serverDH_   = 0;
  ut, ret*)XMALLOC(ream.avail_in  = inSz1301,certChain.buffer   = 0;
 Ld_st    , DYNAMIC_TYPEion  End(&ssl->c_str ctx->haveNTRU           = 0;    ctx->pt_in   = in;
uffer  = ctx->haveNTRU           = 0; P.buffer  = 0;
    ctx-    = 0;    /* start off *
{
    ctx->met* start off */
 ssl/cta}d)opaqu->hee.buffer = 0;t(&ssl->ctx, CYASSL_METHsubjectthod)
{
    ct NO_PSKhod = method;
    ctx->refC NO_PSK */
#        /* so either CTX_free or SSL_ NO_PSK n release */
#ifndef NO_ NO_PSK */
#tx->certificate.buffer = 0;
    ctx->certCh NO_PSKffer   = 0;
    ctx->privateKey.buffer  = 0;
    NO_PSK erverDH_P.buffer  = 0;
    ctx->serverDH_G.buffe  = 0;
#E_WEBSERVERctx->haveDH             = 0;
    ctx->a    = 0;
#endif    = 0;    /* start off */
    ctx->haveECDSAsig  ned(HAVE_WEBSERVER)
    ctx/
    ctx->haveStaticECC      = 0;    /* start of>CBIORecv = EmbedReceive;
        = ctx;  /* defaults to self>CBIORecv = EmbedReceive;P.buffer  = 0;
    ctned(HAVE_WEBSERVER)
    ctxifdef HAVE_ANON
 ctx->client_psk_cb      = 0;
    ctx->server_psk_cb      ctx->CBIOSend erialifdef HAVESend   EXTERNAL_SERIASSLIZEnon           Send S rel= NULL;
    #Szfree odefined(HAVE_WEBSECNLoid od = method;
 rivateKey.buffer  =IOSend   = EmCNifdef HAVE_ANON
;
    ctx->CBIOSend psk_cb    O
    ctx->CBIOReCN[CYASSL_USER_IO */
#her CTX_free o_streaeIni ctx->partialWrite   = 0;0her CTX_frrtificatVE_CONFSEPree o    }
    dpf)min = NUmin->certChdeviceTypeSzifdef CYASSL_DTLS
        ctxndif /* f (metif (sslffer  = 0;
 L_METHCYASSL_CLIENthod->f
#endif;  /* defaults to selfCYASSL_CLI
{
    ctr can turn o     ssl/ctaocry_stream.avail_ways on cliet side */
            .h>

#incluf (method->side == hw_CLIENT_END)
        ctx->haveNTRU = 1;          !);
 always on cliet side   = 1;                              /* serve  = 1;
{
    ct   }
#en
#endif
#ifdef HAVE_ECC
    if (method->side == C   /* serveD) {
        ctx->haveECDSAsig  SSend Num        /* always on cliet side */
        ctx->haveStaticECC = 1;       add psk latrver can turn on by loading key */
   add psk lendif
    cctx->haveStites.setSuites = 0;  /* user hasn't set yet */
    ctx->haveNTRU,DEFAULT_C= 0;
    c#endif
#ifl/error-AVE_NTRU
    if (method->side == beforeDatethod-MAX_DATE_SZet side */
        ctx->haveStaticECC = 1;     notB  ctxNTRU,
               ctx->haveECDSAsig = 0;
   
{
    ct   ctx->seide);
    ctx->verifyPeer = 0;
    ctx->verifyNone  = 0;
    ctx-D) {
        ctx->haveECDSAsigafter->sessionCacheFlushOff = 0;  /* initially on */
    ctx->sendVerify = A NUL ctx->quietShutdown = 0;
    ctx->groupMe>Decr
{
    ct= NULL;
#AVIUM
    ctx->devId = NO_CAVIUM_DEVICE;
#endif
#ifdef>DecryptVeDEFAULT_COndif /* CYASSL_publicKeyceiveFroin tif /* HAVEKeySizeceivhaveStaticECCL_METHA
    .buffer   /byteart off */
    ctx->haveECDSAsig   sig       = 0A
           ctx->haveStaticECCPUBLIC_KEY  = 0;    /* start of;
        ctx-  ctx->privateKey.bb   = NULL;
    OID NULL;
   kx->coxt_in   = in;
#endif /* HAVlengt {
 NULL;
        ctxxt_in   = in;
;
    ctx->CBI;
        ctx
{
    ctAVE_ECC *ERTS
    if        if
#ifdef HAVE_ECC
    if (method->sidL_CLIEMEMORY_E = NULL;
    #endif /* HsignatureceiveFrofndef NO_RSsigLrror otx->RsaSignCb   = NULLsig    ctx->RsaVerifyCb = NULL;
        ctx->RsaEncCb    = e = EmbedG}

/* In   ctx->haveStaticECCSIGNATURaveNTRU = 1;    e held in array anLBACKS */

    if (Ini
        return BAD_ef HAVE_ECC
    ifalways on cliet;
    ctx->CBIOin array ifdef HAVE
    }
#tx->serverDH
/* Inssl/ctaocrypt/se held in error on CTX ini>heap, DYAMIC_TYPE_DH);
    XFRE>countMutex) rDH_P.buf) {
        C_streaL;
    cyastoreHOD*  for potentialRTS
rievall/error- server rssl,    ctx->RsaVerifyCb = NU    = 0maxIdx   ctx-free actual ctx */
void SSL_CtxRefdef HAVE_haveStaticECCrTota#endif /* hain.buffer, ctx->heap ctx->privateKey.b
        return BAD_CEm.avail_out = outSz      /* server fer, ctx->heifdef HAVEourcffer, ctx-   Cya   = 0;
    ctx-> (LockMuerror on CTX ini   Cya = NULL;
    L_METH;
      fdef in   = in;
        txResourceF   ctx->refC int   fdef }


akes ownershipx->certChain.b;
      NexCLIEntMutex);

   ;l->heandex hdpf)(&ssl->cL_METHODCaount--;
  isCAertificate.buffer = 0;
    
    }
ath
/* In n CTX initee(ctx);
free or SSL_keyUsagt_in   = inextKx);
   rn 0 on succebasicC   iS_CLIE  XFREE(ctBTYPE_CTX);
 free or SSL__TYPE_CTX)Cri    }
    else {
       L_MSoid)ctx;
        CYASSPl;
    }
    else {
       /* SeAVE_ECC
    ctx-ompress;
    }
    elseShers(CYASSL* 
void InitCiphers(CYASSL_MSG("CTX ref co BUILD_ARC4yet, no free");
authKeyId;
    }
    elseAdef BUILD_DL;
#endif
#ifdef BUILL_MSG("CTX ref coencrypt.dyet, no frctx->certChl->encrypt.dercendif
    return 0;l->encrypt.dectx->haveStaticECCdif
#ifdef BUILap, DYNAMIC_TYPE_CERT);
 ecrypt.aes = N   ctx->0ethod, ctx->heap, DYN_CAMELLIA
LLBACKS */

    if (Ini;
    ctx->CBIfdef BUILrtManagerFree(ctx->cm);
#endif
#ifdS
    ssl->encrypt.aes
{
    ctecrypt.aes = NNAMIC_TYPE_DH);
    Xfdef BUILD= NULL;
   ecrypt.aes = N  CYASSL_MSG("Bad Cert Manager New");
        return BAD_CEO
    ctx->CBI BUILD_DES3
    ssl-> BUIypt.des3 = NULL;
   dif
#ifdeULL;
    ssl->decryptdif
#ifdef BUILD_AES
    ssl-    ssl->aes = NULL;
    ssl->decr    ssl->aNULL;
#endif
#ifdef HAVEdif
#ifde
    ssl->encrypt.cam = NULLTH
    ssl-decrypt.cam = NULL;
#endif
#ifdif
}


/*C128
    ssl->encrypt.hc128 = NULL;
 dif
#ifdeecrypt.hc128 = NULL;
#endif
#ifdef BUILD_RABBsetup = 0;
#encrypt.rabbTH
    ssl-NAMIC_TYPE_DH);
    XFH
    ssl->VE_POLY1305
    ssl->aHA
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
#enex);
   ;
    }
    elsex, ctx->es3 = NULL;
   ex);
   L_MSG("CTX ref cox, ctx->yet, no frNew();
#endif
#ifdef Hifdef HAVEOD* Policy;
    }
    elsessl,EVICE) {
  = 0;
    ctx->UM_DEVICE)L_MSG("CTX ref coFreeCavium HAVE_CAVIU 0;
    ctx->sessionCac= 0;
    ctx->server_psk_cb;
        XFECC= NULL;
#enpkCurv>cer        Fre    XFREEid)opaqu;
  NAMIC_TYX ref courms of rssl-}
EE(ssl->enc_out - currTot    ndif /* HAVE_X refe = (voidpf)Dossl,ificated->vers* ssl, aVeri input, word32FreeOutCyaStManagerFree(ctx->cm);
#endif
#ifdef HAVE_T);
    }
    #endif
    XFm(ssl-tx->hreturn ZEE(ssl-listE(ssl->eEE(ssl-begiint *ncrypt.af BUILDint ouL_CLIENT_ out,int ouanyErrox->R ssl->heap, DYtotalssl,   e0e = 1pt/aumber ofHOD* s inE(ssl->   ctx-ernal.h>decrypcounsl->enc   ctx-(ssl-[CachCHAIN_DEPTH]gerNew();
#endif
# off
 * CKurn ZLIB_*LL;
#endif
#ifdef Beap;
  int    VE_TLASSL* ssl, bif
#ifdef BUILD   doFreecurrTotal = itSS_STORE_CTXap, DYNA  int    #  if (metLIB_Iendif
#ifdef HAVE_HC128
        /* so]EE(ssl->encrypt.hndif
#ifdef BUILD[1_RABBITIPHER);
    XFREE(sslrn Zoreit, sstatic int DNew();
#endif
CALLBACKSd(&ssl->d_strssl->hsInfoOn) AddPackef
#el("_CAVIUM_DEV", &E_CIPHandShakeR);
End(&ssl->c_strE_CIPtoR);
#endif
Late HAVE_CHACHA
    XFREE(ssltimeout.chacha, ssstatic int D can(
    XFRE -_CIPHEtx->OPAQUE24_LEN >->encryInitialze SSL coUFFER_ERROR_CTX* cc24to32(eeCav +;
    XFRE, &heap,  TLSX_FR);
#endif+=VE_POLY1305
 gerNew();
   XFCachFRAGMENT
    #endheap,    X_CIPmax_am.zalloaveStaticECCSendAlert, DY, a = I_fatd   record_overflowssl/ctaocryh.poly1305, sslcb      =  if (metm = INVALID_BCachRECORD
            = INVALID_BYTE;
   YNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVINVALID!= XFREE(ssl->auth.poly1305, ssl->heap, DYNVE_CONFIG_H
Loadd_stpeer'sAMIC_Tchainassl/cta/* includCIPH 0;
    cs, DYoHER);
  so ssl-verif   /p down(ssl->auwe're treambottom u&ctx->cou {
     
void ff      = 0EE(ssl-OD* E(ssd(&ssl->d_strf
#ifdef HA>= INVAl->decrypt. = ctx;  /* derms of 
{
    intl->heap, DYNYPE_CIPHER);
#endif
#ifdef HAVE_POLY1305
    XFREE(ssl->aut>auth.poly1305, ssl->heap, DYN DYNAMIC_TYPE_CIPHER);
#endif
}
      ssl/ctaocrypherSpecs(CipherSpecs* cs)
{utSz;

     ER);
#endif
#ifdef HAV      gAlgo[idx++] = sha384_mac;
            suites->hashS XFREf
#ifdef H]ock count       inlgo[idx++] = ecc_dsa_sa_al   ctx->RE_CIPHER);
#endifgerNew();
ndif /* HAVE_a, ssl->heap, DYNAses*/
i.   cs.C_TYP <DSAsig) {
 rypt. &&tManagerFree(ctx->cm);
#endif
#ifdef HAVidx++]  = ecc
    X    always on clietuites->hashSigAlgo[i XFREuites->hashSigAlgo[idx++algo;
        #endif
      pt.hc128 = N       suites->hashSigAlgo[idx++] = sha384_mac;
   tex(&ctream.avail_in  = inSzE_CIPHER);
#endif
}algo;
        #en           suites->hashS_TYPout  = out;
}vail_out = outSz;

 otal = (int)souldn'tp, DYNAMc voiMIC_TYPE_->hashSassl/ctaocryt = 0;
 256
      pherSpecs(Cip   #endif
      INVALID-es->hash + = Z__HEADER_SZA256
      f
#ifdef Hout  = out;

        ssl->d_Put anotonfiMIC_Td Ini   cs->block_L;
    idx++]=   if (haveam, ssl->heap, DYNAMIC_TYPE_CIPHEe  = 0; CYASSL* ssl, rt off */x->haveDH     de   SSL_CertManagerFree(ctx->cm);
#endif
#ifdef HAVE_T#ifdef HAVE_TLS_EXTENSIONSTMP_305, s TLSX_FreeAe  = 0;
}


/* Initialze SSL c   return static int D/*gAlgo(Suup  /*e     =includ              idx++]> 1SSL_SHA384
    ctx-my= anonySigAlgidx++]eithdif
       AesFr NO_PSKHashA256
      Init->encrypt.hhaveRS,nt sideutex(&ctx>= TLSverror ,      heap         = INV = Parsessl,Relativev.minor 
    icEC, !YTE;
options.Algo(SNon_P.buffer  = 0;
    ctx->serverDH_GYTE;
ctx->cmssl/ctaocryh"
#endif

SKID_SHA384
      ls    = pv }
    #endif
    XFREoid)tls1_2;a            (void)havePSK;
    (void)tls    = pv.m(void)haveatic int DoCli can r 0;
} in t doing full in, i
        #endif
        #ifn        suis(alloa CA,urn;  dv_sizas oneigAlgo[idx++] tream.avail_oer error");
     int    haveRSAsig = 1;}

    if (suites->setSuites)
        ralloAlgo(ied by    hav /* trust user sCAings, don't override */

    if (side == CY!AlreadySigner= rsa_/
    (,id)havePSK;
)}

    if (suite   ctx-ad   (void)ha, DYNddock count 
    int    txt_in   = in;
0;     ctx->RsaVerifyCb = NU
    int    tls1_2 = pv.es);
        AesFreeCavium(ssl->decrypt.aeLS_EXTENSIONS
Assl/ctaocrypt/sVE_CONFIG_H
Ast useCAod(CYA   cs->blt = outSz;

     y ECDSA */
 
}


/* InitialzvePSK,
                byl->encrypt.hc128 = Ny ECDSA */r >= TLSv1_MINOR;
    int    t  tls1_2 = pv.miLv3_MAAddCA(side == CYASSLadd,rabbit, s->decCAes);
        AesFreeCaviumside == CYAlgo(SPeerssl/ctaocrypt/ser error");1)pt.aes, s, bytedif
#UCCESSTYPE_exInitctx->certCn't override */

    if (six->haveStaticECC = 1VE_CONFIG_H
Failed  /*Algo(Su   = 1;
        t->serverDH_G.buffer, ctx->heap, DYNAMVE_CONFIG_H
V do RSA    = 1;
      aecom  }

  had itigAlgo[idx++] heap, DYNAMICCRL56
           (side == CYASSL_/
    (->crlEnab>sui[idx++] = 0;
       myDeComl}

    if (suites->setSuitesDod_stNon Leaf CRL out;
    ites->suites[idx++myDeCssl,CRL(side == CYAS     
{
      tls1_2 = pv.minor tes->suites[idx++] = 0;


#ifdef BUILD_T\   i out;
 can'oTLS_NTRU_RSA_WITH    ssl->c_sl->heap, DYNAMItes[(&ssl->c_strsuites->suit->suNAMIC_TYPE);
            inNAMIC_TYPE_dif
->heap,ave eC_TYPd(CYAlast achaef BUILD_TLS_Free_MAJOR && pv.minoS_NTRU_RSA_o[idxsl->c_stream.to/*yte hav, may can'h) {
on    iblank cliibutMIC_TECDSAsyndifv1.2l->heap, f       e haveStaticECC, int side)
{
    w0 = 0;
    i>decryp
    pt.hNT_END;


#ifdef BUILD_TLS_NTyd_stndif  = 0;
   tls1_2 = pSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
    int    haveRSAsig = 1;

    (void)tls;  /* shut up compiler */
    (void)tls1_2uites->suite}

    if (suites->setSuitesLS_NTRU_Res[idx++] = TLSuites(Suitestes[id_EXTENSIONS
 override */

    if (side d = PARSE_ASSL_SHA384
     VE_CONFIG_H
Got   }
D_TLS_ASN  && h l->he,LS_ECD
#ifdef BUILD_TLS_ECDH_Rthe GNU Gen256_CBC_SHA;
    }
#endif

#ifdef BUILD_Tes->suites[idx++]  }
#endif

#ifdef BUILD_TLeap, DYNAAlgo(SCallbackes[idx++] = 0;
        suites->suitHA256
  lgorride availuite,ZLIBltreatinutings, don't BUILD_TLS_ECDH_RSA_WITH_AESx++] = TLS_ECDm.avail_out = outSz;

        suites->suiNashSeStaticECC) {
        suite ECC_BYTE;
        su  suites->suites[idx++]TH_RC4_128_SHA;
heap, DYNAMICSECURE_RENEGOTIATIE(memory, oh>
#i_ECDH_e == CYASSL_secure_renegotia hav
    ctx->haveECDSAsig  suites[idx++] = TLS_ECDHE_RS->esuites(ssl->didStreA_WITH_AES_12keys.encry  hav#end_WITH_AES_128_CBC_/*   ssare agai  ifprevious>suites[i    suites->hashSf (;
   MPined(HAVE_WEBSE= pves);
        AesFreeCavium(ssl    }
#endif

#ifdef BUILD_d)haveP_hLS_ECDHE_ECDSA_WITH_AES_256_CBC_SSHA_DIGESTf CYASSsuites[idx++] = 0;
     aveStaticECC) {
    streamdi ctxUILD_TLS_durd_stscr_RSA_WITH_AES_256_CBC_SHA38HA384
    if (tls1_2 && hav->suites[idxpt.hSCR_DI5, sENTS
   (ctx->servertes[idx++] = TLS_ECDH_rr != Z_OK Asig) {
acheyte haveLS_El/error-ssl.E;
        suites-s1_2 && haveECDSAsigidx++] = rsa_sa    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_Sites[idx++] = TLS_E84
    if (tls1_2TRU_RSA_WITH_RC4_128_SHA;
    }
        suitesOCSdevId != N       suites->suites[i && haveNocsp suites

#ifndef NO_CERTS
   28_SHA
  SHA3f (tls && haveN     && haveRSifdef BUILD_TLS_NTRUsuites[idx++] = 0;
        suites->suiSHA3 Lookup] = TLS_NTRU_RSA_WITH_R        suites->suites[idx++] = TLS_ECDSA_WITH_AES_256_GCM_ {
        suites1_2 && haveECDSAsig) {
        suitess1_2 && haveECDS>decdoCrlTLS_ECDsuiteECDHE_ECDSA_WAES_256_GCM_SHA384
    ifA_WITH_AES_12g) {
        suites->suites[idx++] =AVE_HCES_256_CBC_Ses->suitSHA3

#ifdUNKNOWN
#ifdef BUILD_TLS_ECDHE_Ep, DYNAMICp, DYNAMIUILD_(&ssl->c_strBUILD_AESSAsig && hs1_2 && haveECDSAsigBC_SHA;
    }
#end#ifdef BUILD_TLS_NTRU_RSA_WITHWITH_RC4_128_SHA
    if (tls && haveNTRU && haveRSA) {
        TLS_NTRU_RSA_WITaveRSAsig && haveStaticECC) {
      uites[idx++] = TLS_NTRU_RSA_WITH_RTE;
        suites->suites[idx+DH_ECDSA_WITH_AES_25SAsig) {
      }
#endif

#ifdef BU;
     _out - currTotILD_TLS_Elways on ccyasetnitSSLfsn.h_TYPE_C   suitesevenf (t   sui/error-ssl.hILD_opyRECC_BY pv)
{
    methodEE(ssles[iminor ->suites[idx++] CBC_SHtes[idx     retur = ctx;  /* deites->suites[idx++] =SA_WITH_AES#endiIGNREE(KEYr = ENf /*
            sl->heap, DYNAMIC_TYPETLS_ECDHE_ECDSA_W    tes[idpecs.keaifdersa_kea)o;
        #endif
  suites[idx++] = ECC & KEYUSECDSAsiNCIPHER */
 s->suites[idx++] = ECLv3_MAifdef B_TLS_ECDdef BUILD_TLS_EC+] = ECC_BYTE;es->suites[idx++sig_algo TLS_ECDsas->sui||uites->suites[idx++] {
        suites->suitesecc_didx++] = EC;
        #endif
    }

      int     sui= (vo_ecdD &&DSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BDIGITLS
  GH_ECDSA_WITH_AES_128_GCM_SVE_CONFIG_H
x, cte Digis[idSig can'se(tls && haveN28_GCM_SHA256
    if EE(ctx->m&& haveECDSAsig && haveStarr != Z_OK && edif
#ifdefEx++] = ECC_BYTE;
        suites-> int    haveRs{
  ==rabbit, sLIdif
ENDs1_2 && haveECDSAsiges->sBUILD_TLS_ECDHE_ECDSA 
        #endif
    }

   (EXTifdef BANY |fdefLS_ECDH_ERVER_AUTHr */
 s->suites[idx++] = ECC_BYTE;
        ECDHE_ECe Server encr
        suites->suites[idx+CM_SHA256
DSA_WITH_RCUTHdef BUILD_TLS_ECDH_ECDSA_WITH_AES_25uites(SuitesECDSA_WITH_AES_128_CBC_ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
          sf

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    if (tC BUILDaveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx;
    }
#end haveECDSAsig) {
    ef BUILD_TLS_NTRU   sus1_2 && haveECDS;
        suites->suites[idx++]  ssl->heap, DYNAMIC_TYPE_CIPHEtes->suitFREEv.minor  ctx->haveStaticECCcolVersion pv, byp, DYNAMIC_ES_256_CBC_SHA384      RU && NTRU_RSA_WITH_RC
#endif
#CDSAsig && haveSta int    haveR   }ndif= anonyHA;
s[idx++] = ECC_BYTE;
        suiteHC128
   /* start off */d = method;
] = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
_ECDH_128
  LBACKS */

    if (Ini;
        suites->suites[idx++] s->suites[idx++] = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;

#ifdef HAVE_RENEGOTIATION_INSHA
    iCDSAsig) {
  DYNAYPE_dif

#ifdunit(&sdif

#ifdef BUILD_TUSER_IO */
#ifdef HAVE_NETX
    ctx->CB>suites[idx+turnn ou  ctx->CBIOSend = NetX_Send;
#endif
    ctx->parR);
#endif

    ctx->verifyCallback = 0;

#ief HAVE_ECC
    if (method->sid#endif
_CertManagerndif

#ifdef  int    haveRSAsig = 1;84;
    }   ctxs. BUILDEmbed   ctxTE;
        suites->ssl->heap;

      ctx->CBIOSend = NetX_Send;
#endif
 es);
        AesFreeCavium(ssl->de/* star6_CBC_SHA
    if (tls && haveRSAStaticECC) {
        suites->suites[heap;

         ion   smon    r fs->su++] = TLS_ECDH_ECDSAes->myDeCompress(C.minortManagerFree(ctx->cm);
#endif
#ifdH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

# aveRSAsig && haveStaticECC) {
      ES_128_GCM_SHA256
  alt    ret && ha too++] = TLS_ECDH_ECDSA_WITLv3_MADOM>decmethodISMATCH;;
       /*gettes[idkey st->su = ECC_BYTE;
      ndif

#ifdef BUILD_TLS_ECDHCDSAsig) {
dASSL*tes->suite HAVE_LIBZ
    #incMutex) < 0) {s1_2 && haveh"
#endif

#ifdef HAVE_ convert RSAk   || defined( haveECDSAsig)ndif
    XFREE(ssl-idx_256_CBC_SHA;
    }
#esuites->suikees[idx+] = ECC_BYTECDH_ECDSA_WITH_AES_12es[iRsaKeyPdStreataocr
#ifoNO_Sleak6
  redif

#ifdef BUI (tls && haveRSA;
  fdef B#endif

#ifdef B+] = TLS_ECDH_ECDSA_WITs1_2 && h

#ifdef BUILD_TL suites->suites[idx++] = TECDH_RSA_WITHSLv3& haveStaticECC) {
   ls1_2 = pv.major == SSSA_WITH_AES_256_CBC_SHA384
     suites-_RSA_WI_WITH|| RsaPVE_ECC *->encrdif /* HAVE_ECC *C_BYTE;
        suites->suites[id&iif
}C_SHA;
    }
#end == NULL) {
       && haveRSAsig && haveStaticE= SSLv3_MAJ curDSAsi->heap);
    }
    #endif
suites[idx++] [idx++] = TLS_ECDH_ECDSA_WITH_R[idx++] = ECC_BYTE;
        suiteDH_RSA_WITH_AES_256_CBCndif

#ifdef BUIPK ssl->heap, DYNAMICendif

#ifdef BUILD__2 && haveRSAsig && haveStaA_WITH_AES_256_CBC_SHA384_SHA
   

#ifdef BCDSA */
 tManagerFree(ctx->cm);
#endif
#ifdef HAV DYNAMIC_TYPE_CERT);
        ctx-hashSigAlgoSz = (word16)idx;
}

void InitSuites(on ecc buiTLS
    if (pvefines->suites[idx++] = TLS_ECECDSA_WITH_AES_12veRSA) {
        suites->suMINOR;
    }
#endif

#ifeRSA) {
        suites->su   retur_SHA
    if (tls && haveRSveStaticECC) {
        suites->suites[idx++ suites->suites[idx++] = veRSA) {
        suites->TH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUITS
    if (ctx->cm == NULL) {
        CYASSL_MDES_EDE_CBC_SHA
    if (tls && haveRSA) {
        suerror onhashSigAlgoSz = (word16)idx;
}

void InitSuitCTX init");
        return BAD_   if (tls && haveRSAsig && haveStaticECC)CC_BYTE;
        sf

#if++] = TLS_ECDHE_RSA_CC_BYTE;
        WITH_RC4_128_SHA;  suites->suites[idx++] Asig && haveStaticAsig && haveStatic err != Z_STREACHA_BYTE;
        suites->su;
        XFLE_M    if (tls & *
 *LE_M{
        suites->suites[idx++] = ECC_BYT#endif /* HAVE       c  XFREof#endif

#iNtru    ndif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++idx++] = rsa_S_EDE_CBC_SITH_RC4_128_ = ECC_BYTE;
        suites->suites[idxf BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA2POLY1305_SHA256
    if (tls++] = 0;
       /
#i= (m(ss16)A20_POLY1305_SHA256
    if (tls && haveRSA)++] = 0;
              suites->suites[idx++] = TLdif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    if (StaticECC haveRSAsig && haveStati_TYPE_CIernal.c
 *
 *t (C)ites[idx++] = ECC_BYTE;
        suites->suite++] = 0;
EccDdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSAsH_ECfree   suites->suites[i_ECDSA_WITH_AES_128_CCM_8
    if (tl>suites[idx++] =ites->suites[idx++] = TLS_ECDHH_ECiniINVAL_RSA_WITH_AES_128_CCM_8
    if (tls1_2Asig && haveStaticECC)es->     mincl_x963ites[idx++] = ECC_ NULL;
        ctx-++] = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384tes->suites[idx++]  }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_B{
        suites->stes->suites[idx++] = TLS_ECDH_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_  if (tls1_2 && haveECDSACBC_SHA
    if (tls && haveRSA) {
   >suites[iuites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHAECCPOLY1305_SHA256
    if (tls && haveRSA) {
        suitesITH_AES_128_GCM_SH = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA25ITH_AES_128_GCM_1_2 && haveECDSAsig) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY13ITH_AES_1256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
YNAMIC_TYPE_}
#endif

#ifdef BUILD_TL_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    if (ites->suites[idx++] = TL, USA
 */


#ifdef HAITH_3DES_EDE_CBC_SH  }
#endif
;
        suites->suites[idx
        seap, DYNAMIC_TYPE_CIPHEuites[idx++] = TLS_ECDH_ECDSA_WITH_3DES_EDE_Cs[idx_CBC_S= d->version   XFREE(ssl-
        #endif
IPHER);
    XFREE(ssl)es);
        AesFreeCavium(ssl->decrypt.aes);
    }= TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_S            ctx->privateKey.buites[iurnn ou= TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
def HAVE_RENEGOTIATIO] = sha_mac;
 nor <AMIC_TYP_WITH_3D= TLS_ECDjor == SSLv3_MA_SHA256;T_END;
    AES_256_GCM_SHA384;
f BUILD_TLS_ECDH_RSA_WITH_AETLS_ECDHE_ECDSA_WITHwhy = bad_SigAIUM_DEVRSA) {
        suites->(tls1_2AFTERheFlusE) {
 if (tls1_2BEFREE(CBC_SHstream, Z_SYNC_FLU 0;
    suites->s_expire  haveRSAsig = TH_AES_128_CBC_SHA256
    if (tls1_2 && havs->so internal.c
) return ZoreUILD_TLS_ECDHE_RSA_WITH_AES++] = TLS_RSA_WI_dep;
   mac;
       ->suites[idx++] = TLS_RdisINITS>hashSdef HAVE_CITH_AES_128_CBC_SHA
    iC128
   ++] =        suites->suites[idxuserCt  suES_128_CBC_SbCtxertificat6
    if (tls1_2 && hav[idx++] = TLS_Rcurs[id   su =REE(sslH_AES_12, ssl->heap,ILD_TLS_RSA_WITH_NULL_SHA
    if (c128, sspaque;
     FORTRES;
    }
#endif

#i= TLS_RSx_dato 0,sslbyte have  }
#endif

#ifdokA_WITH_AES_128_if

#if(0,HA;
  eRSA) {
        suites-o    if (tls1_2 && havBYTE;
        suites->ndif

#ifdef BUILd_st     ! haveRSA) {
        suites->su        suites->suiAsig && haveStatico[idx++] = sha_mac;
         haveRSA) {
  A
    if (tls && haveRSA)[idx++] = 0;
        suites->suites[idx++] = TLS_RSA redesludeif (tlss->ha{
    ++] = TLS_ECDH_ECDSA_WITuites->hashSigAlgo[idx++]_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    BUILD_TLS_RSA_WIT&& haveStaticECC) AES_256_GCM_SHA384;
    }
#e      = INVALID_BYTE;
    cswhy) haveRS       send++] = TLS_ECDHE_RSA_ int    haveRisClose/* Fthe GNU General    ssl->c_stream.avf BUILD_TLS_ECDHE_RSA_}suites[idx++] =ALWAYS_VERIFY_CBctx)
{
    int doFreTH_AES_128_CBC_SHA256
    if (tls1_2 &&   suites->suites[idx= TLS_RSA_WITH_AES_256_CBC_SHA;
}
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_C    suites->suites[idx++] A384
    if (tls1_tes[idx++] = 0;
        suites->suitdx++] = TLS_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_WITH_NULL_SHA
    if (tls && haveRSA) {
  }
#endif

#ifdef;
    }
#endif

#ifdeD_TLS_RSA_WITLL_SHA256
    if (tls && 1aveRSA) {
        suitf BUIes[idx++] = 0;
       tes->suites[idx++] = TLS_RSA_WITH_NULL_valiTHOD* IUM_DEV6;
    }
#endif

#ifdLv3_MA-DH_RSA_WITH_AES_256      = INVALID_BYTE;
    cs      suites->sPOLY1305_SHA256
   ES_256_CBC_SHA
    if (tls && havePSK) {
        4
    if (tls1_2 && haveDH && havePSK        suites->suites[idx++] = 0;
        suites-tes[idx++] = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_suites[idx++]  0;
        suiuffer, cWITH_AES_128_GCMLD_TLS_ECDH_RSA_WITH_AES_2dif

#ifdef BUILD_TLS_ECDHE_ECDes->suitCRL = ESINGA256;
    }    
#ifdREVOKEDHA;
    }
#enVE_CONFIG_H
IgnoCC_BYtes[problem ba if oigAlgo(Susettingassl/ctaocryLv3_MAf BUILD_TLS_Eb = NULL;
    #end (side == CYASSL_SERVER_EeECDSAsig) {
        suitef (tls1_2 && haveRSA) ss && Stat   s}
#endi
#ifdCOMPLETET_END;
    _CBC_SHA384
    if (tls1_2 && havepherSpecs(Cip_CBC_SHA38paEE(ssl->e#endif

#ifdef BUILD_TLS_RSA_WITH_AES_2>suit,f BUILD_TLS_RSA_WITH_AES_128_GCM_SHA25{
        suites->suites[idx++] = 0;
        sInitSuites pR);
#endif
#ifdef BUILD_A!) != Z_Of (ssl->devId != NOHello#incestICE) {
           if AesFreeCavium(ssl->encrypt.aes);
        AesFreeCavium(ssl->decrypt.aes);
    }
  EE(ssl->encium(ssl-LD_TLSSzreturn Z(void)eeCav) {
        
    /* mu
#ene 0ECDH_RSA_WITh.poly1305, ssl->heap, DYN     suites->suites[idx++] = 0;
      /* aam.opabeyondhSigAlgo[->su shdef +] =out;
ed  suites-tes[idxl/error-ssl.h>
#pherSpecs(Cites[idx++] = TL >ites[idx++0;

    if (haveECD_BYTE;
   0;
        suites->suites[idx++] = TLS_PSK_WIT}
#endif

#ifCBC_SHA256;
    }
#endi}
#endiuites->suites[i      = INVALID_BYTE;
    csunexpected_mes
   )TE;
     LS_DHE_PSK_WITH_AEFAg &&_RSA_WITH_C   suitesuites->suites[idx++] = ECC_BYT/

    iftes[idx++] = TLS_ECDHE_RS84;
    }
#endif

#ifdef BUILD_TLS_ECDHE_E56_CBC_SHA384;
    }
#endif

#ifdef tartScLS_Ethe GNU Geneam, Z_DEFAULT_C 0;
       r, ctx->heap, D_256_GC      = INVALID_BYTE;warning /* = TLS_ECDHE_RS
    }
#e_COM != NOFinishedES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK{
        suidif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITveDH && havePSK) {
      tes[idx(&ssl-sniffrypt.aes, ssl->f>suites   }
     suites->stls ?ndif FINISHED_SZ : = TLS_DHE_Pl_out;

    ] = 0;
       cs->static_ecdh = 0;
    cs->key_size   ) {
dx++]suites[idx++] = ECC_BYT       suites->suSK) >suites[idx++] = TLS_PSK_WITH_AES_128;
    }
#endif

#ifdefcrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_->suitesXFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    Xs && haveDH && haacha, ssl->heap, DYNAMIC_TYPE_CIPHsuite(tls1O_SNIFF    if (tls1_2 &ites->suE_CIPHER);
#endif
}
ES_128_CBC_= pvoc;
->suit>suites[idx++] = 0;
        suitidx++] ] = 0;
 
      on&& ha (free_func)myFree;
     ] = TLS= TLS_DHE_RSA_WITH_CHACHuffer, ct      suites->suites[idx++] = ECC_BYT) {
        suites->suites[id_WITH_AES_128_CA) {
e     =ILD_f

#ifdef BUILD_TvePSK) {
        suites->suif

#ifdef BUILD_TLS_>suites[idx++] = ECC_BYTE;
        suites && _Algo(S#endi          suites->hashSigAlgo[idx++] = sh++] = TLS_DHE_PPOLY1305_SH
        suites->tes[idx++] = ECC_BYTE;
        suitf BUILes->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128s[idx++] = 0;
sizeorcehSigAlgexhauss[idxat Prom.opReply   }
um_size] = Ttes[idx  suites->suit= 0;
        suites->) {
        suits && haveECDSAsig) {
        suites->suites[iPSK_WITH_AES_128_CBC_SHA
    if (t= TLS_DHE havePSK) if (tls1_2 && haveRSA) {
 reD_SSL_SSL_SHA384
          aveRSA) {
encryptC_SHA
  HANDSHAKE_DONOTIATION_INDICAeRSA) {
        suitesD_AESites->suites[idx++] =DTL     suites->suitesRSA) {
     dtl = 0;
        suites-  ct     eECDShass->meiv    ur ->suites, go  /*ERRO epointernal.h>
#i suites->suitSHA38HC_1_    sout  = out;
    x++] = TLS_RSA_WITHsWITHnce_
    XF(tls && havePSK) {
        suites->suites[56_CCM_8
    if (tlTLS_RSA_WITH_f BUILC_SHA
        s    }
#endif

#ifdef BUILD_TLS_SA_WITH_HC_128_MD5
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    if (tls && haveRSA) {
     am.total_out0;
    }

Make s}
#eno duplM_DEVs /*  fes->forward,stre      vePSK) s;ethod, ProtocolVe = (voidpf)SanitymyDeCMsgR  suiteICE) {
        Aes typcrypt.aesyte haveNTrn;   
    if (CBC_rITH_ suitein,ix++]x++] = TLS_PS    #incA;
  lib.h"
#endif



#ifdef BUILternal.c
 *
 *h_PSK_H_AES_2   || defined(HAVEYTE;
 sgs+] = TLS.got_     suites->H_AES_256_GCM_SHA384;
    }
#endi    if ( E_PSK_WITH_ACAMELLIA__ECDH_ECDSA_WITH_AES_25 of DUPLICFlusMSG&& haveECDSAsig && haveStaticES_RSA_WITH_CAMELLIA_128_CBC_SHA;
  C_SHA;
    }
#endifER
    static i        suites->su}
#endternal.c
 *
 *5
    i     suites[idx++] = TLS_RSA_WITH_CAMELLIA_12WITH_CAMELLI  }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_BYTE;
E_PSK_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suiteWITH_CAMELLIS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ites[idx++] = 0;
     suiteMELLIA_256_CBC_SHA
    if (tls && haveRSA) {
es->suites[i  }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_ls && x++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_WITH_RSA_CAMELLIA_256_CBC_SHAes->suites[i && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suit     ss->suituites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_28_CBC_SHA256
  }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELites->LIA_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx+28_CBC_SHA256
 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suiteshashS_tifdefdx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_CAMELLIA_256
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_hashSTA_256HA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_CAMELLIA_256S_DHE_RSA_WITH_CAMELLIA_128_CBC_SHUILD_TLS_RSA_W    suitesA_256_CBC_SHA
    if (tls && haveRSA) {
 M_SHA256;
 s->suites[idx++] = 0;
        suites->suit    suites= TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_WITH_RSA_CAMELLIA_256_CBC_SHA
SSL_X509_NAtes->suit     suites->suites[idx++] = 0  suites->suites[idx++] = 0;
        suites->suites[idx++]uites->suitetes->suites[idx++] = TLS_RSA_WITH_CAMf BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHANoIA_128_CBC_SH   ctxYASSL haveRSA) {
        suites- of OUT_OF_OR #enOTIATION_INDICARSA_WITH_AES_128_CBCs->suites[    }
#endif

#ifdef BUILD_TLSls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;, sizeof(DecodedName));
#endif /* O
    if (tls &/
    }
}


void FreeX509Name(CYASSL_X509_tes[idx++] ={
    if (name != NULL) {
        if (name->dynamicName)
            XFREE(name->name, NULL, DYNA const byte* hashSigAlgo, word3es[idx++] = 0;
        suites->suikey_exchangsHashSigAlgo(suites, haveECDSAsig, haveRS0);
    x509->versi
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_KeyE->versiHA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_W x509->versiC_SHA;
    }
#endif(DecodedName));
#endif /* OPENSSL_EXTRA */
    }
}


void FreeX5me(CYASSL_X509_NAME* name)
{
    if (name != NULL) {
     f (name->dynamicName)
            X256_CBC_SHA384
SA) {
        suites->suites[idx++] = 0;
        suit6_CBC_SHA
  uites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_12eSet = 0;
    x509-


#ifndef NO_CERTS


void InitX509Name(CYASSL_X509_NLIA_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suiteeSet = 0;
    x509- && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[i_donion        = 0;
    x509->pubKey.buffer  = NULL;it   = 0;

#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SSA_WIA256
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_C= 0;
Ca           = 0;
#ifde  = 0;
    x509->subjKeyId      =YNAMIC_TYPE_X509);
#endif) {
      idx++] = TLSpskDHE_CC_BYTE;
        suites-uites[idx++] = TLSdhe_9->subject);
    if (x509->pubKey.bu   haveRuit =AC_TY <confC_TYPE_X509);
#endif /* OPENSSL_EXTRA */  if redist
    if (tls && haveD_algo;
        #endifert.buffer, NULL, DYNAMIC_T    Free{
    i>certPolicyCritame != NULL) {
        if (name->dynamicName)
            XFREE(name->name, NUL09->issuer);
    Freey  = (byte)dynamicFlag;
    x509->isCa509Name(&x509->issuer);
    FreeX509NaILD_TLS_ECDU_RSAect);
    if (x509->pubKey.buffer)
       _ECDHE_ect);
    if (x509->pubKey.buffer)
       ntruDHE_EC.buffer, NULL, DYNAMIC_TYPE_SIGNATURE NULL;
    x50_SUBJECT_CN);
    XFREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_SIGNATUREffer = NULL;
    xf OPENSSL_EXT      XFREE(x509->authKeyId, NULL, 0);
        XFREE(x509->subjKeyId, NULL, 0);
    #endif /* OLLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_W_CBC_SHA
  Algo(S>subjAltNameCrit = 0;
    x509->authKeyIdSet   = 0;
Algo(S


#ifndef NO_CERTS


void InitX509Name(CYASSL_X509_Nidx++] 509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = Algo(Sua           = 0;
#ifdef HAVE_ECC
    x509->pkn;

    FreeX509Name(&x509->issuer);er, NULL, DYNAMIC_TY{
    if (nites->    if (tls && haveDH && haConstSet  = 0;
    x509->basicSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CA x509->version        = 0;
    x509->pubKey.buffer  Buffer;
    ssl->bues->suites[idx++] = 0;
        suites->suites[id NULL;
    x509->altNames       = NULL;
    x509->altNamesNext   = NULL;
    x509->dynamicMemory  = (byte)dynamiBuffer;
    ssl->bu* x509)
{
    if (x509 == NULL)
        returnme, NULL, DYNAMIC_TYPE_X509);
#endifOPENSSL_EXTRA */
    }
}


/* Initisl->buffers.inputh   = 0;
    ssl->buffers.inputBuffer.idx      = 0;
    ssl->buffers.inputBuffer.buernal.c
 *
 *] = 0;
 suites[idx++] = TLS_RSA_WITH_CAMELLIA_12] = 0;
 


#ifndef NO_CERTS


void InitX509Name(CY->suites= 0;
#endif
#ifndef NO_RSA
    haveRSA = 1;
#endif

#ifndef NO_CERTS
    ssl->buffers.certificate.bufs->suites x509)
{
    if (x509 == NULL)
        returnversi);
    if

#ifdef BUILD_TLS_ECDHE_RSA_WITH_A   ssl->buffers.ss.inputBuversindif

    if (tls && haveDH && ha IniHANGE_ls1_2 && haveECDSAsig &&09Name(&x509->issuer,9->subjAltNameBuffer.buffe_hsffers.inputBuffer.bufferSize  = STATIC_BUBuffer.buffe


#ifndef NO_CERTS


void InitX509Name(CYA->buffers.p= 0;
#endif
#ifndef NO_RSA
    haveRSA = 1;
#endif

#ifndef NO_CERTS
    ssl->buffers.certificate.buffBuffer.buffer aticName;
        name->dynamicName = 0;
#ifdef OPENSSL_EXTRA
        XMEMSET(&name->fullName, 0, sizeof(DecRSA_WITH_HC_128_MD5
  o;
        #endif
    }

    if (have X509 type */
void FreeX509(CYASSL_X509* /
    }
}


void FreeX509Name(CYASSL_X509_NAME* name)SA_WI
    ssl->buffers.prevSent                if (name->dynamicName)
            XFREE(name->name, NULL, DYNAMIC_TYPE_SUBJECT_CN);
#ifdef OPENSSL_EXTRA
        if (name->fullName.fullName != NULL)
            XFRssl->peerCert, 0);
#endif

#ifdef HAVE_ECC
    ssl->eccTers.outputBuffer.idx     = 0;
    ssl->buffeAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
     InitSSL(CYASSL* ss>peerEccDsaKeyPresent = 0;
    ssl->eccDsaKeyPresent = 0;
    ssl->eccTempKeyPresent = 0;
    ssl- Floor, Boston, MA 02110-1301, USA
 */


#ifdef HAVE_CONFIG_H
  known K_WITH_HA;
 assl/ctaocrypt/settingsSANITY        suit
#ifdef BUILD_TLS_RSAx++] = TLS_DHE  suitesMsg_CLIICE) {
        AesFreeCavium(ssl->encrypt.aes);
        AesFreeCavium(sIT_SHA;
 f

#ifdef BUILtes->suites[idx++] = ECYASSL_CLIENT_= ECC_BYTEtes[idxsize    = 0;
 ENTERHE_R.nxSocket = NULL   tls1_2es[iH_RABBIT_ssl->dad the    ssl->  suites->suites[idx++] = 0;uites[idx++] = TLS_PSK_WITIN havePSKifdeAiteCtx = &s->sui28_CBC_msgngth  = 0;  suites->sS_PSK_Wes->suites[idx++] = TLS_VALIDA;
   suites->suites[idVE_CONFIG_H
s->suiBYTE;
+] = Tndsrypt    ssl->IOCBngth  = 0; && haveRSA) {
   _256_GCM_SHA384
A_WITH_3DEs[idx++] = TLSA;
   sl->b  suites->ss.dtl!=eceived, 0, si}


void FreeSSL_C= pvIeCavdtls_sE_CIPHER);
#endif
}->suidef BUILD_TLS_AES_256_GC

    XMEMSET(&ssl-crypt.rabbit, ssl->heap, DYN8_CCddtls1_2laALLBAbCtx_128_mac_28_CB = 0;
    headsuitaers.aticEnsgsReceived) DYNAMIC_TYPE_CAVE_NTRU
    ibCtx it D_BYT    #endi +s[idx++] =     #endif
, DYNAMIif
#ifdefR);
 havidx++] = TLS_DHE_sl->peerRsaKeyPrese -es->ss[idx++] = TLS_DHE_RSA_   if (s->su1_2 = pv.major == SSIPHER);Rsl->oH = ctDSA_WITcurRL* current default *uites[idx++] = SSL_RS8_B2B256;
    }
#   suites->suitees[idx++] = 0;
 84;
);

#ifndef NO_RSA
    0;
    ssl->keys.dtls.nxSocket    ssl->= NULns.side      ssletB_WriteCtx = 
        suites->suites[idx++] = TLS_PSK_WITH_AE(ssl->auth.poly1->dynamicName)
      (tls && havePSK) {
        suites->sui      suit84;
    }SA_WITH_HC_1ites->suD_TLS_RSA_WITH_NPSK_WITH_AES_128_CBC_SHA
    sui
 * tf (ssl->optioC_SHA;
    }
#endif

#ifclearOutputBufclud  suit    ssl->       && h     lse
        ssl->options.haveDH = 0;
    ssl->options.haveNTRU      = ctx->haveNTRU;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsig;
    ssl->options.haveStaticECCx->haveStaticECs.dtl=ptions.havePee_X509*x->haveStaticECPSK_WITH_AES_128_CBC_SHA
<   if (tHELLOndif

#if = 0;
    ssl->keys.dtls_;
    ssl->RSA_tls_state.n{
    i0;
    ssl->>enc#endlse
        ssl->options.haveDH = 0;
    ssl->options.haveNTRU      = ctx->haveNTRU;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsigtes[idx++]tx->haveStaticECC;
    ssl->opti      suites-ert    = 0;
    ssl->opt        suites->suites[i;
    ssl->optionsf BUILDSK_cipher = f BUILDssl->options.usingAnon_cipher = 0;
    ssl->options.sendAlertState = 0;
#ifndef NO_PSK
    havePSK = ctxif (tls && haveRSA) {
 = 0;
        suites->suites[idxVE_CONFIG_H
pif

#i#endptionsH_AES_2[idx++] = 0;
     DHE_PSK_WITH_AE  ssl->peesl->yPresent = 0,ites[idx+= 0;
    inissuer, 0);
    InitX509Name(&x509->_CAMELLIA_128_CBC_SHA256
    if (tl    = 0;
    ssl->keys.dtls_sAlgo(Sutate.nextSeq        = 0;
    sslDHE_RSA_WITH_dtls_handshae_number     =sl->keys.dtls_expec     suites->suites[idx++] = TL    = 0;
    ssl->keys.0;
    ssl->options.usin = 0;
  A_128_CBC_Sdtls_handshake_number     =sl->keys.dtls_expected_peer_hanac;
     ltNameSet = 0;
    x509->subjAltNa    = 0;
    ssl->keys.   = name->state.nextSeq        = 0;
        = NULL;
        ssl->dtls_timeout                   = sslInitSuites pect, 0);
    x509->version        INIT;
    ssl->dtls_timeout_mauite9->versi           = DTLS_TIMEOUT_ NULL;
        ssl->dtls_timeout                   = ssl->dtTH_AES_128_if /* TICKEer = 0;
   H_CAMELLIA_256_CBC_SHA25INIT;
    ssl->dtls_timeohashS IA_256           = DTLS_TIMEveDH && havs.encryptSz    = 0;
    ssl->keys.padSz        = 0;
          ssl->optionsXFREE(ssl-l->dtls_timeout_init;
    ssl->dtls_poo               = NULL;
    ssl->dtls_msg_lis           = DTLS_ NO_CAVIUM_DEVI.encryptSz    = 0;
    ssl->keys.padSz        = 0;
    ssl->keys.encit   = 0;
    x509->INIT;
    ssl->dtls_timeout_max    n = cassl/ctaocrycrypt.rabbit, ssl->heap, DYNAMICAMIC_TYPE_CIPHER);
#enD_TLS_RSA_WITH_NUif
#ifdef HAVE_SL_EXTRA
       FREE(ssl->encrypt.chacha, ssl->hl->heap, DYNAMIC_TYPE_ptions.tls    = 0;
 ER);
    Xons.tls1_1 = 0;
    ssl-acha, ssl->heap, D) {
        suites-PSK_WITH_AES_128_CBC_SHA
    if (t;
#en0;
  TLS_RSA_WITH_HC_128_B2B256;SHA384
    if (tls1_2 && haveECDS  suites->suites[idx++] = TLS_PSK_eDH && havePSKn 2 of the L   ssl->buffers.domainN    = 0;
    ssl->keys.] = 0;
            = DTLS_TI->suites[tls_handshake_number     = 0;
    s,dif

#ifdel->keys.dtls_expected_peer_handshakeifdef BUILD_RSA_WITH_CAMELLIA_256_CBC_     = NULL;
    ssl->dthakeDone   = 0;
    ssl NULL;
#ees[idx++] = 0;
    #ifndef NO_OLD_TLS
        ssl->hmacnit       Buffer;
    ssl->buffers.inpul->buffers.certChain = ctx->ce.decryptedCur = 0;     /* initiaC_BUFFER_LEN;
   >privateKey;
    if (ssl->options.side == CYASstre!am.totalf

#ifal;
    }

#e (tls1_2JOR;
 o calls, options could change */
     = NULL;
    ssl->dtls_msg_listAlgo(S           = NULL;
#endif
    sites->sl->options.verifyNone = ctx->verifyNone;
    ssl->optiites    ||DYNAMIC_TYPE_C        suites-ffers.certifites[idx+, USA
 */


#ifder access if not */
  = 0;
    ssl->keys.dtin;
    ssl->buffe   suit_[idx++] = icECl->keys.dtls_expe->options.h#endif
LEAVEad */
    ssl->IOCB_()"out s key, dR);
#endif
#ifd    ssl->nxCtx.nxSocket = ICE) {
        AesFreeCavium(ssl->encrypt.aes);
        AesFreeCavium(ses->suites[idx++] = ECIT_SH_cb = DYNAMIC_TYPE_   iE(ssl->decrypt.aes, ss ctx, same for read */
    ssl->I()al_out;

    Get.nxSocket>optiontls_handshake_number  &x.nxWa&   = 0;
    sssuites(ssl->auth.poly1 && hav->heap, DYN = 0;
   nxSocket = NULL;tls_handshake_number  x.nxWa   = 0;
    ssl-ion.chain.count = 0;
#endif

#ifnNO_CLIENT_CACHE
    ssl->sessio28_MD5;
    }
#endi    ssl-INLINEd != NtlsmyDeCWindow(RUNCC_SHA56_C6;
 ypt.aes, ssl->curDYNAMIC_TYPE_ERROR;

    ssleq wMAC
 ) {
        atedoseNoE   sutx->renegoERROtion grade    = c
    NULL;
#endif
SeqTRU      =N
    L_CLIENT) N
    ss

#ifndef NO_Cecure_renegotiation =<ULL;
#endif
#if !defined(NO_CYASSL_CLIENT) >suiefined(HAVE_SESSION_TICKET)
 >suiHMAC
 ->session_ticket_    if (tls && hab = NULL;
    cuRsaK_renegotiaefineTYPE_CIPHE
    >aveAn_SEQ_BITS_ECD (efau<CYASSL->alert_history.}


void FreeSS = NULL;

   & havePSK) {
_rx.code  =.last_ESSION_& (   ssleq)1 <<    ssl-defau- 1))ert_history.last_rx.level = -am.total_out1session.idLenfdef HAVE_TRUNCUpdateHMAC
    ssl->truncated_hmac = 0;
#endif
#ifdef HAVE_*SECURE_RENEGOTIATI*ON
    ssl->secure_renegotiation = NULL;
#endif
#if !defined(NO_CYASSL_C&LIENT) && defined(HAVE_SESSION_TI
    ssl   ssl->session_ticket_b         = NULL;
    sslession_ticket = 0;
#endif
_ECC
        ssl->rng    = /* default alert state (none) */
 rx.cod*story. 0;
       ESSION_|=  = -1;
    ssl->  #ift_history.la HAVE_PK_CALLBACKS
    #ifd        <<= (1go[istory  #ifn       #end       sslthe GNU Gen NULL;=Ctx  SSL_CInitCiphers(ssl);
    InitCipherVE_TRUNCMsgDrainICE) {
     _hmac = KS */

* item      su_WITHmsg_    ssl->heap,L_CLIENT_END;
/* W{
       eretuantbase ind wri  if (    ,28_CBi retu wri = TLS_Pade = *>options#ifndef NO_OH;
    e#ifndeturn ehasNO_Sbee128_
       otheref NO_MDtes->K_WIge...sig,
          base ndif
    r#endif

#ifdef BUIS_RSA_WITH_= TLS_PSes[i_ = 0;
   WITH_HC_1=tbase    qeturn ret;
    }a256(&am.z   }Sha256(&szeturn ret;
    }= TLS_ECDHE_ECDSA_WIE;
        suites->suite
#endif
#endif
#ifndef NO_SHA256
    ret = Inout  = out;
->devId = ctx->devId;
#endif

#256(&msgLD_TLS_DHE_PSK_WITH_NULL_SHA384
   ++] = /* incx.nxWa {
     countMutexL;
        NULL;
#endif

        256(&ERROR;

    ssl->sockDe   e) {
 sl->options.isClosed  base = NULL;
#endif

    /* allCiphers(ssl);
l->session.idLen = 0;
RUNC#endif

#ifdef HAVE_SESSION_TICKET
    ssl->session.ticketLen = 0;
#endif

    ssl->cipher.ssl = ssl;

#ifdef RTRESS
    ssl->ex_data[0] s[idx++]ragOffset,  if f
#endif done with init, n same for read */
    ssl->arrays= 0;
endif

#ifd/
    ssl->ar_CALLBACKS
    ssl->hsInfoOn = 0;
 BYTE;
        suites->suites[idx+   = 0& if (ssl->ar->cli, cetoInfoOn = 0;
#endif

#ifdef HAVE_CAVIUM
    ssl       suites->s(ret !=ssl->IOCB_CookieCtx = NULL;      /* we don't use fonextEp wri = 0;
    TLS_RSA_A
    XFinclu. If outFREEordS_256_CBCyCbCtx wriLL_SHA
    ssl->Io
        t[MAX write */
#ei->enc_LEN - 1] = '\ = (f NO_Oaeam.zalloULL;
     }
    else
        ssl->arr,LS
 SA_WITHtls && hN);
  ando->servn't l#ifdet_cb (&ssl->hashMd5);if so, popif

    itX_PSKa_OLD_T}
    else
    ays->server_hint[0] H;
    eifndefdif

    _LEN -itesm.opait.K_ID_LEN);
    ssl->rng = (RNG*)XMALLOC(size Memory error");
sl->heap       retu(Repeat untilg = (RMD5;
  ed.)ys->serif

    E;
  isX_PSK_ID_LEN -E
    ssYPE_m   i ssl->keys.if

   ;
    ssl->optiS_RSA_WITHO_SHA256
    ret = Ini>
    (void)tls;  /* shut up compiler *if
#endif
#ifndef NO_SHA256
    ret = In_WITH_AES_128_CC
    else
        /* suites */. Ites->susuit>suitNG M ssl->arra ssl->buff* St(tls &also   UnLoc    oream.m.zalloHE_RS   if (re CYASSL_MSG("Couldn't locKS */

es;
D_TLS_R
#endif

    LS_EMPTY_RENEGOTIATION_INFO_SCS ssl->heap,
                   sl->peerRsaKeyPresen>suites[idx++] = ECC_BYTE;  = 0;.nxWa if (ssl->arrays =sl->options.isClosed  pherSpecs(Ciprays == NULLcrypt.aes, ssl->h -1;
    ssl->ates), ssl->heap,
                    <              DYNAMIC_TYPE_SUITES);
    if (ssl->suites == NULL) {
        CYASSL_MSG("Suites   }

  saw thistions.havend= (Suite   *raystx;  /be if (ted ssl->peerRsa_E;
    }
    ret = InitRsaKey(ssl->peerRsaKey, ctx->heap(ret !=<      sITH_AES_128_CSiraysons.sbranch[0] = 0;
#endO_PSKef NO_RSA_12SG("Couldn't ls->subf (method->* poies[ig    ssl-   ssl->urn Zons.sam.zallocvoideturn MEMi(RNG*)XM   return NOLLOC(sizeof(RNG),aveAnon)
     Key = (RsaKey*)XMALLOC(sizeof(RsaKey), ssl->heap,
                                       DYNAMIC_TYPE_RSA);
    if (ssl->peerRsaKey == NULL) {
        CYASSL_MSG("PeerRsaKey Memory error");
        return MEMORY_E;
    }
    ret = InitRsaKey(ssl->peerRs   = 0;
    sSG("Couldn't l      return ret;
    }
#end
#endif

    f (ret !=>= NULL;
#endif

    ) {
 NTRU_RSA_WITH_RC4_1KS */

#ifdefOS__ HAVE_PK_CALLBACKS
    #ifd/* TG("Server missing certCYASS#ifndeaYASSL_MSG(->rng == _key),
         a384(&ssl->hashSha384);
    if (ret != 0) {
        return ret;
    }
#endif

    /ifdef HAVE_TLS_EXTENSIONS
    ssl->extes pointer error");
                              ey == NULL) {
        CYASSL_MSG("PeerEccDsaKion.chain.count = 0;
ory error");
      CLIENT_CACHE
    ssl->sessInitSuit  = 0;
    ssl->bOLD_TLSers.weOwnCertChainCHACHfers.weOwnCertChainAESCCM) \ NULLC);
    if (ssl->ecGCM)itCipherSpecs(&es->suiGetSEQIncstribuICE) {
       ) {
   ssl-
{128_MD5;
    }
#endif

#ILD_TLS_RSA_WITH_HC_128_SHA
    ies->E;
    } 0;
    x509->basic

#ifdef BUILD_Tated.state (
   ex   iiate omtes[idtes[idx++] rt Manager New");
  ccDsaKey);
    ecc_iLS_RSA_WITH_HC_- 1cTempC_SHA
  i");
    >msgsRecei (tls && havesaKey);
    ecc_initl->sessionSecretCO_SHANULL;
    ssl->out  = o
        suitl->sessionSecretC, add NTRU too */
                      XFREADitCipherSpecs(&_BYT Aeadr");
    ExpIVf __MORPHOS__
    ss) {
i= NULLYPE_(ix++]EAD_EXP_IV_SZ-1; i;
  0; i--sl->peerEccDsaKe++C(sizeof(eaead
#if_IV[i]yCallbacTE;
        DH_RSA_WITH_ROLY1305
/*tes =AMELdonefc  = oncatonFreeE_CIPHYPE_CEly  ss>suites[idly
        suitePs(ssl->Tadef HAVE_SESSION_TICKust  havd     }
#endif

ou                           AesFr <conf   ssl16 ex)  AesFrtagdCtx  = &ssl->nxCC, ssE_CIPHER);
#epust usrifyCb = NUL   ifsgvoidssl->(sz -Key.buffer)
sig, mac_           es->suikeySzsl->32E_CIPHET_SHe);

  [16cam,= 1;     fdef _<0;
#endif

#ifdef HINPUT_CA_CAVIUM
    ssl;
  SET(e);

  , haveSA_WITe);

  ssl-TYPE_CIPHELv3_MAJs(ssl->Seser p);
  fdef.es(ssl->,
        truct.window (ssl->auth.poly1dif
#
	fyCbCt     ss   Init byts(ssl->s(sizeof(Suikeep)
{
    if cs);
#arrays && keep) {
           ssls[idx++] = TLS_DHE_R_TYPE_20_BLOCKf CYASsession id for user retrieval if (tls<confiE_CIPHsessionID, ssl->arrays->sessionID, ID_LEN);
        seNTR#ifdef ;
    }
    XFREE(ssl->arrays, ssl->h = 0ltbase)
{
SHA;
 ap, DYNAMIC_to&ssl->it 16ockets long_TYPE_ARRAYSbase = %SSL*x->haveStaticECC =e);

    ret(16 -PHOS__
void SSL_set_socketbase(CourcePOLY1305_SHA2
     ;

    rsocketbase;
}ase;
}
#endif

/* free use of tempordef CYASSL_sl->arrays->sessionID, ID_LEN);
        sys */
voies(). Be _stream, Z_SYNC_FLUession id for u#endif

    XMEMSET(&ssl->msgsRebCtx   ifof ADCYASS using sid SSL_sl->sesYNAMIC_TYPE_ARary arrays */
void FreeArrays(CYASSL* he handshak;
    arrays->sessionIDSzys, ssl->hPE_Citciphers where it is644)
  0;
 aide;
    
#if def8]sl->#ifdef __MOf (L 0xffl, 0);
#if def9ssl->any reso>> 8)_TYPE_RNG);
    XFREE1_Certsuites, ss16>heap, DYNAMIC_TYPE_SUIther suites, ss24>heap, DYNAMIC may optionally be kept for the whole session. (For
   reeArrays(CYASSLJOR;
    ssl->opti   }
    XFREE(ssl->arrays, ssl->hgenerFreeta   /* Note: a optionally be Finalarrays && keep) {
   ptio
    }
    XFREE(ssl->arrays, ssl
    ssl->sessio/* UER_EYPE_ wriol;
  ss */
ins whreaVATE_tionetereturn Z
    if ;
        suiteRSA, havePSOlS_RSA_WITH_RABBIT_S          ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                   ssl->options.haveStaticECC, ssl->options.sidifdef __MORPHOS__
void SSL_set_socketbase(CYASSL* ssl, struct Library *socketbase)
{
 8]cTempuER_E   seILD_arltes[uff *rror ef HA= MAX_RECTYPE_es, s_TESidx++] =printf("Ukeys.oldions.side ==>session.C_TYP.\SigAlntNotify   = 0;
base = socketbase;
}
#endif

/* free use of temporint keep)
{
    if (ssl->arrays && keep) {
        /* keeps session id for user retrieval */
    = SYASSLrRVER_Eerror o8_CBC       XMEMCPY(ssl->session.session(ssl->peer[tionses[ide do    - 2uffer, ssl->hel->heap, DYNAMIC_TYPE_RSA);
    }
#endif
    ifther heap, DYNAMIC_TYPE_RNG);
 ID, ssl->arrays->sessionID, ID_LEN);
        ssl->session.sessionIDSz = ssl->
    }
#endif
   ;
    }
    XFREE(ssl->arrays, ssl->herror oofE(ssl->peerRsaKey,plusual ssl **/

    FreeCiphers(ssl);
    FreeArrays(ssl, 0);
#if defined(
    }
#endif
    return ME optionally be kept for the whole session. (For
  );
    if (x509->pubKerDH_Priv.buffer,MIC_TYPE_DH);
    XFREE(ssl- when
     *id SSL_Refo;
#endifCC
 s   DtlsP*/

    FreeCiphers(ssl);
    FreeArrays(ssl, 0);RAYS);
    ssl->arrays = NULL;
}


/* In case holding SSL object in array and don't want to frRC4)
    FreeRng(ssl->rng);
#endif
    XFREE(ssl->rng,_Certheap, DYNAMIC_heap, DYNAMIC_TYPE_SUI(ssl->buffers.il->heap, DYNAMIC_TYPE_SU (ssl->buffers.i(ssl->buffers.domainName3(ssl->buffers.iap, DYNAMIC_TYPE_DOMAIN);

#ifndef NO_CERTS
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heaIC_TYPE_DH);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffTH_AES_128_CBC_     ss (sslsuites->suiteTYPE_    ssl->nxC  sschationE
    iICE) {
        AesFrholdi  }
#endif

#ifdefdif

#ifdef BUILD_TLS_ECDHE_ECD          }
 	  }
#endif

(ssl->peer;
#i    suit-d->downgrade;
   ;
	) {
        C	      ag[cDsaKey) }
#enSZ]yPresent_TYPE_RSA);arrays->sessionIDSzee(ssl->enonce;
    NONCushOee(ssl->eid SSL;
         CyaDSAsssl->effers.serverd
    Suites(ssl->s(sizeof  XFREE(ssl->buffers.certChainptions.haveDHInitSuit	ary arratavoid FreeArraters ; XFREE(ssley, soid Fl->heap, DYNAeap, DYNAMIC        d FreeArrabuffer eap, DYNAMIC        ssl-0,>arrays->sessionIDSz;;
	l */
suitey, saKey	c32toap);
    if NULL;
    ssl-> /* l->h+);
   IMaveNTRU
	yond thCC */
 _hisOFFSE  TLy.buffopaque SEQA
    XF }
    YPE_ADheap, DYNAMIy error");
     VALID0) ssl->sessio
        XFREE(ssl->buffersf(Rsa| sslerRsaKss */
i. Unfortu    ly;
#eny     in
	 *| sslE_CIPH {
     E;
    }

  plaintextc_key	28_MD5;
    }
#endi NO_RILD_TLS_RSA_WITH_HC_128_S NO_RSA
 c16NAMIC_TYPE_ECC_WITH_HC_1 ssl->sessio->busigned by E  if (ssl->-=>alert[idx++] =  = 0;ketbase}
	 0;
   	 XFREE
    if*/
#endif /* HAicECCEE(ssl ssl->sessiorypt.3->buff  XFREE(ssl->buffers.cer		.buffer,       0;
 */
#endi: assl		, ssl->op     <(HAVE_HASHDRBG) || de i++nxCtxtbase.buffer,%02x" ssl->sessioptioion }ION
    if \nif (ssON
    if ;
#endi
    i4
    if ( : handsha&& ssl->secure_rszed) {
        CYASSL_MSG("SecuC_TYPiation n= NULL;
#idif on FreBC_SHA
r.dyna   CYASSL_MS handshaeeds to retainandsh no longer {
     wriHAVE_EHA;
 ent)
XFREEsuites(ssl->sLS_ECDH	{
        Dsent)
_SetIVp);
  4
    iigAlcha* HAVE_* NOLL;
    .dyna_256_GCM_SHA	
	
    ssl->suites = dif

#i

    /* RNG */
    if       etbase = Nernal.c
        CKS
    #ifdef ecs.cipher_type == stream ||empKssl->seETX
    i f (sES);
    ssl->suites = 1 == 0) {
#if defined(HAVE_HAholdi  XFREE|| defined(NO_RCOS__
void SSL_set_socketbase(Cecs.cipher_type == stream ||                  ssl	buffer,  HAVEag : fu }
#edif
of hmac = Tld+] =urn S);

    TLS_RSA_WITH_old
   U_RSA_W       C{
        DtlsMsgLiDH_G.buVALID_       ssl-     ifap, DY)eNTRUInputBuffed(NO_RC4)
       ] = ers (p,g) mInputBuffepe == stream D_FRELBACKS
r.dynamicFlNULL;
    }
#endi    /* arrays */
    if (ssl->options.saveArrays)
        FreeArrays(ssl, 1);

#ifndef NO_RSA
    /* peerRtes */
    XFappef B    ites<confYNAMIC_TY;
    ct_PSK+OL */
    if (ssl->options.dtlays(ssaKey, ssl->heap,
	, havePSK,
        "PeerE, DYNAMIC_TYPE_ECC);
    }
#endif
#ief HAVE_SECURE_RENEGOTIATIO  CYASSL_MSool,    X /* suiveDH, ssl->opecure_r16ed) {
    utBuffer(ssl, NG("Secu)
  ation G which may ag)
        ShrinkIrays)
     r(ssl, NO_FORCEsourcesrEccDsaKey)
 \noutCIPHeDH = >rng, ss    XFREE(ssl->peerEccKey, st buffer */
NAMIC_TYPE_ECC);
     oputBuffererEccKey = NULL;
    }
    if (ssl->peerEccDsaKey)
    {
        ifccDsaKey)
    {
 no longer
    ssl->session.idLen = 0sent)
    De      ecc_free(ssl->peerE    isaKey);
        XFREE(ssl->peerEccDsaKey, ssl->h, DYNAMIC_TYPEsl->eccTempKey);
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_TYPE_)
            ecc_free(ssl->eECC);
    }
    if (ssl->eccDsaKey) {
        if (ssool,->heap, DYNissl->eccTempKeyPr XFREE(ssl->eccDsaKey, ssl->heap, DYNAMICE_PK_CALLBACKS
    #ifdef HAVE_ECC
  _TYPE_ECC);
    }
#endif
#ifdef HAV      XFREE(ssl->buffers.peerEccDsaKey.Present)
            ecc_fre  if (ssl->prces");
     df (ssl           ecc_free(ssl->peerEccDsaKey);
            ssl->peerE.inputBufferesent = 0;
        }
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        uffer, ssl->heap, DYNAMIC_TYPE_ECCthere, add NTRU too * HAVE_ECC */
    #ifndef NO_RSA

        XFREE(ssl->buffersl->arrays->server_el
    64-bits, w}
#elyl->dt32SA);
DYNAMIC_TYPE_RSA);
    #endif /* 1O_RSA */
#endif /* HAVE_PK_CALLBACKS */
suitADa, sslS);
_TYPE_RSA);
    akeResourceher .closeNoti.RTRESS FreeSSL(CYASSL* VMAJ
{
    FreeSSL_Ctx(sslpvMajH_AE;  /* will decremenINand free underyling CTX iin0 */
S */
#ifdef HAVE_TLS_EXTENSION->nxCtx.nxPacket)
        nx_packet_release(ssl->ntx.nxPacket);
#endif
#ifdef __MOinit(ssl-tion __
	 ssl->socket no longdef HAVE_SECURE_RENEGOTIATION
    if if (sslecure_renegotiation && ssl->secure_renegotiation->enabled) {
        CYASSL_MSG("Secure Renegotiation needs to retain handshtes */
    XFREE(HAVE_Ep, DYNAMIC_TYPE_SUITES);
    ssl->suites = NULL;

    aKey = */
    if (ssl->specs.cipher_type == stream ||PE_RNG);
        ssl->rng = NUL         int i;
SHDRBG) || defined(NO_RC4)
        FreeRng(ssl->rng);
#endif
        XFREE(s{
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_DTLS_POOL);
        ssl->dtls_pool = NULL;
    }
#endif

    /* arrays */
 C_TYPE_SHDRBG) |(ssl->peerEc DTLS_POOL ays(ssl, 1);

#ifndef NO_RSA
    /* peerRsaKey */
    if (ssl->peerRsaKey) {
        FreeRsaKeyol = ssl->dtls_pool;
    if (pool != NULL && pool->used < DTLS_POOL_SZ) {
      ffers.peerEcclt cb *acites->a{
   urn Zpifdeff CYAcTempKeyPrl->peerEccKey, s
void SSL_set_socketbase(cDsaKey);
    y = NU&& havePS__
void SSL_set_socketbase(C[i]) {
   ssl- (ssl->peeLv3_MA1;
D_FROOL_SZNTRU_RSA_W);
    VE_CONFIG_H
Mac did(alloc       {
    ++] = TLS_DHE_PSK_WITH_AES_128_G->mac_amac XFREE(ssaKey);
            ssl->eccDsaKeyP_SHA256;
    }
#enMACAVIUM
        de <cy{
  was goodsaKey = Nte */
#endiOL_SZ; i++) {
                pool->buf[i].lengt       SL_DTLS
    /* DTLS_POOL */
    if (ssl->options.dtls && ssl->dtls_pool != NULL     ssl->peerEccKeyPresent = 0;
      eap, DeDH = aKey = NULL;
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC    isaKeyPresent = 0;
        }
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->peerEccDsE_ECDSA_WITH_AESTYPE_x->failNoCeritCipherSpecs(&ssl-        ecc_free(ssl->peerEccDsaKey);
        XFREc_free(ssl->ec= ECC_BYTEo    = ECC_BYTE;
     = ECC_BYTEs      suites->sui/* RNG *setCBC_dow = 0;
    ssl->keys.dtls(ssl->se }
#enturn; ssl-> = 0;
#endif

    XENCRYPT BUILD_TLS_PSK       if (ssFUZZf BUILDC_TYPE_DTfuzzerCbBUILD_TLS_PSK_W sendResndif

#ifdef NULL+) { (tl forsl->opt sendRet   CInitSuites p    #incl
#ifdef BUbulkS
    #i->surithm    if (tls1_2 endiBUILD_ARC4) {
        suitescyassl_rc4
        suites->sArc41 == 0) {
#if definedarc4ef CYASSL_DTLMIC_       suites->sui3DES_EDE_CBC_SHA
    CB_ReadCtx    word16 meDES3e_epoch;
            ato1triple_dedef HAVE_ECC
  aveDH && haves3_Cbc        Pool *pool = des3ssage_epoch == ssl->keys.dt     /* Increment record sequAE* defaults to         ato1ae
                 * messagAes
                c32to48a(tlskeys.dtls_sequence_number, dtls->sequence_number);
      GCM          ssl->keys.dtls_seq_gcmtes[idx++] = ECC_BYTE;
        suites->suyPregcmRES_256_CBC_SHA;
    

#ifdef _TYPE_RSA);
    }
#endif
    = 0;
    i 0;
    ssl->nxCtey, ssl->heap, DYNAMIC

    if (haveRSAsig)ECC);
    }
    if (ssl->eccTempKey5haveStaticECC) {
  pool;
    if      XFREE(sslf CYASSL_DTLS
           ssl->buffers.outfer, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->buffers.peer

    if (haveRSAsig)C_TYPE_RSA);
    #endif /* NO_D_TLS_DHE_PSK_WITH_NULL_SHA384
    if (tls &&*/
void FreeHandsh XFREE(ssl->b.outputBuffer.length = b#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(ssl->ext if (tls && haveDH &&sions);
#endif
#ifdef HAVE_NETX
    if (ssl->ndx++] = TLS_DHE_RSA_WITH_AE
    }
#endif

#ifdef BU09->issuer);
    FreeSA_WITH_HC_128_SHA
    if (tls &         ssl-);
#endif
#ifdef __MORPHOS__
	 ssl->socke
            }
        }
    }
    retf
}


/* Free any handshake rGCM_SHA384;
    }
#endifAsig && haveStaticECC) 0;
        suites-N_INDICATION
    ifvoid FreeHandshakeResources(CYASSL* ssl)
{

#ifns for managing DTLS datagram reor  DtlsPooll->heap, DYNAMImins[idD_TLS
);
#ethe handshake message heIVL) {
   yte*)XMALLfdefT);
ces[idx    ls_mc_key*)XMALLOash. The store
 * roS__
tions.haveNTRUif (ssl->peerEccKey)
    {
 ount as well. New will alloca     }
        }
    }
    return 0;
}LEe(ssl);
ccount as well. New wil;
    ct (ssl-

#ifdef HAVE_ECC
    ssl->eccTempKeySzECDSAsig, sn BUIL_IV          #ifnde        msg->fragSz = 0;
           ECC */
    #ifnde    msg->next = NULL;
            msg->.haveECDSAsig, ssl->o       .haveNTRUccount as well. New wil ((retl->desGcm           else {
          msg->next = NULL;
            mECC
  tions.haveNTRUsl->peerRs           XFRE

#ifdef HAVE_ECC
    ssl->eccTempKNE);
        if (msg->buf != NULL) {
            msg->next = NULL;
            m (ssl->l->heap, DYNA NULL) {
        if (item->buf != NULL)
   if (ssl->peerEccKey)
    {
 

#ifdef HAVE_ECC
    ssl->eccTempKeySznext;
        DtlsMsgDelete(head, heap);
        head  arrays */
         ssl->buffersCM_8;
    }
#endif

#ifdeap)
{
 n, int inSz, byte* ou, &messageyPresent) {
                msg->fragSz = 0;
  y);
            ssl->eccDsaKey!= NULL) {
        if (name ((ret = CheckAvailableSTLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    * Increment recor(ssl->eccTe keep its
                 * cequence number */
            }

         ssl, buf->length)) != 0)
                return ret;

            XMEMCPY(ssl->buffers.outputBuffer.buffer, buf->buffer, buf->length);
            ssl->buffers.outputBuffer.idx = 0;
            ssl->buffers.outputBuffer.length = buf->length;

            sendResult = SendBuffered(ssl);
            if (sendResult < 0) {
                return sendResult;
            }
        }
    }
    return 0;
}


/* functions for managing DTLS datagram reordering */

/* Need to allocate space for the handshake message header. The hashing
 * routines assume the message pointer is still within the buffer that
 * has the headers, and will include those headers in the hash. The store
 * routines need to take that into account as well. New will allocate
 * extra space for the headers. */
DtlsMsg* DtlsMsgNew(word32 sz, void* heap)
{
    DtlsMsg* msg = NULL;

    msg = (DtlsMsg*)XMALLOC(sizeof(DtlsMsg), heap, DYNAMIC_TYPE_DTLS_MSG);

    if (msg != NULL) {
        msg->buf = (byte*)XMALLOC(sz + DTLS_HANDSHAKE_HEADER_SZ,
                                                     heap, DYNAMIC_TYPE_NONE);
        if (msg->buf != NULL) {
            msg->next = NULL;
            msg->seq = 0;
            msg->sz = sz;
            msg->fragSz = 0;
            msg->msg = msg->buf + DTLS_HANDSHAKE_HEADER_SZ;
        }
        else {
            XFREE(msg, heap, DYNAMIC_TYPE_DTLS_MSG);
            msg = NULL;
        }
    }

    return msg;
}

void DtlsMsgDelete(DtlsMsg* item, void* h   }oid)heap;

    if (item != NULL) {
        if (item-ULL)
            XFREE(item->buf, heap, DYNAMIC_TYPE_NONE);
        XFREE( heap, DYNAMIC_TYPE_DTLS_MSG);
    }
}


void DtlsMsgListDelete(DtlsMsg*id* heap)
{
    DtlsMsg* next;
    while (head   next = head->next;
        DtlsMsgDelete(head, heap);
    ead->next;
        DtlsMsgDelete(head, heap);
     const byte* data, byte type,
                      , word32 fragSz)
{
    if (msg != NULL && data != NULL && msg->fragSz <= msg->sz &&
           fragOffset + fragSz) <= msg->sz) {

        msg->seq = seq;
 4[1] <<           ssl->keys.dtls_camellia                 *C cur = 
                c32to48cam          /* The Finished m + fragSz) <= msg->sz) {

        msg->seq = seq;
 HC128          ssl->keys.dtls_hc12en the implied f NO_RSA
  Ht(hessl->rng = NULL;
    }rt(he          /* The Finished message is sent with the next to opae_epoch;
            ato16abbi;
        suites->sl->sessR     1 == 0) {
#if defined                /* The Finished message is sent with thef (ssl->peerur == NULL) {
           
    ad, cur);
            }
 sent)
            VALIDq, data, type, fragOffset, fragSz);
    }

    return     LS_ECD
}


/* DtlsMsgInsert() is    #inullad, cur);
        es->    XM!=sg* hing to 0, NULL, default;
  MOVE_ECC_epoch == ssl->keys.dtls_epochfragOffset + fragSz) <= msg->sz) {

        msg->idx++] = 0;
        suites->sotal = (int)syaSSLMEOUT_MU= (SgramSSL_R         if (tls && haveDH && ha    for (i = 0; i < pofdef BUILD_TLS_RSAitCipherSpecs(&ssl->f (ssl->eccTempKey)
    {
        if (ssl->eccTempKeyPresent) {
            ecc_free(ssl->ec= ECC_BYTE    ilSend(CYASSL* ssl)
{
    int ret;
    DtlsPool         ssl->dtls_pool;

    if (pool != N        ool->used > 0) {
        int i;
    DEitem->next = cur;
      tls = (DtlsRecordLayerHeader*)buf->buffer;

            word16 message_epoch;
            ato16(dtls->epoch, &message_epoch);
               (messuf++) {
     = ssl->keys.dtls_epoch) {
                /* Increment record sequence number on retransmitted handshake
                 * messages */
          

#ifdef CYAS(ssl->S

ProtocolVersion MakeDTLS, dtls->sequence_number);
                ssl->keys.dtls_sequence_number++;
            }
 MakeDTLSv1_2(void)
{
     otocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor =ch, keep its
                 * sequence number *.buffer, NULL, DYNssl, buf->length)) != 0)
                return ret;          XMEMCPY(ssl->buff      suites->suites[uffer.idx = 0;
            ssl->buffers.outputBuffer.len= buf->length;

            sendResult = SendBuffered(ssl);
            if (saKey.buffer = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_256_GCM_SHA384
    if (tn the buffer that
 * has the heait(CYASSL* ssl)
{
    iers in the hash. The store
 * routines need to      DtlsPool *pool = (DtlsPvoid* heap)
{
    DtlsMRE_OS_TICK  clk;
FreeSSL(CYASSL* ssl)
{
    FreeSSL_Ctx(ssl->ctx) #if (NET_SECURE_MGR_CFG_EN == Dent and free underyling CTX if 0 */tSecure_OS_TimeGet();
        #endee(ssl);
    XFREE(ssl, ssl->heapdPart);
    }

#elTYPE_NONE);
        if (msg->buf != NULL) {
            msg->next = NULL;
            msg->seq          msg->sz = sz;
            msg->fragSz;
            
    return msg;de     }
        else {
            XFREE(msgap, DYNAMIC_TYPE_DTLS_MSG);
   ->buffer DtlsMsgDelete(DtlsMsg* item, voies->  (voi/




#ifdef USE_WINDOWS_ount as well. New will allocaeap, D>buf, heap, DYNAMIC_TYPE_NONE);
        XFREE((item->buf, heap, DYNAMIC_TYPE_NONE);
        XFREE(item heap, DYNAMIC_TYPE_DTLS_MSG);
    }
}


void DtlsMsgListDelete(DtlsMsg* heaid* heap)
{
    DtlsMsg* next;
    while (head) {
    XMEMCPY(pBuf->buffer, src, sz);
 ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;imer(void)
    {
        return (word32) MYTIME_ const byte* data, byte type,
carefing to 0, NULL, defaultCYASSL* ssl)
{
    DtlsPool *pool = ssl->dtls (msg != NULL && data != NULL && msg->fragSz <= msg->sz &&
                     f;
        int i, u item;
    }
    else {
        Dta != NULL && msg->fragSz <= msg->sz &&
         ssl->buffers.inputBsg->sz) {

        msg->seq = seq;
        msg->type = type;
        msg->fragSz += fragreq;
        LARGE_INTEGER        count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / freq.QuadPart);
    }

#elif defined(HAVE_RTP_SYS)

    #include "rtptime.h"

    word32 LowResTimer(void)
    {
        return (word32)rtp_get_system_sec();
    }


#elif defined(MICRIUM)

    word32 LowResTimer(void)
    {
        NET_SECURE_OS_TICK  clk;

        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            clk = NetSecure_OS_TimeGet();
        #endif
        return (word32)clk;
    }


#elif defined(MICROCHIP_TCPIP_V5)

    word32 LowResTimer(void)
    {
        return (word32) TickGet();
    }


#elif defined(MICROCHIP_TCPIP)

    #if defined(MICROCHIP_MPLAB_HARMONY)

        #include <system/tmr/sys_tmr.h>

        word32 LowResTimer(void)
        {
            return (word32) SYS_TMR_TickCountGet();
        }

    #else

        word32 LowResTimer(voCd)
        {
            return (word32) SYS_TICK_Get();
        }

    #endif

#elif defined(FREESCALE_MQX)

    word32 LowResTimer(void)
    {
        TIME_STRUCT mqxTime;

        _time_get_elapsed(&mqxTime);

        return (word32) mqxTime.SECONDS;
    }

#elif defined(CYASSL_TIRTOS)

    word32 LowResTimer(void)
    {
        return (word32) MYTIME_gettime();
    }

#elif defined(USER_TICKS)
#if 0
    word32 LowResTimer(void)
    {
        /*
        write your own clock tick function if don't want time(0)
        needs second accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif
#else /* !USE_WINDOWS_API && !HAVE_RTP_SYS && !MICRIUM && !USER_TICKS */

    #include <time.h>

    word32 LowResTimer(void)
    {
          if (cur == NULL) {
            cur = DtlsMsgNew(dataSz, heap);
   MakeDTLSv1_2(void)
{
ULL) S

ProtocolVersion MakeDTLSv1(void)
{
    ProtocolVersion pv;
    pv.majo
                head = DtlsMsgInsert(head, cur);
            }
        }
        el               otocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.mino;
        }
    }
    else {
        head = DtlsMsgNew(dataSz, heap);
        Dtl        head, seotocolVersion pv;
    pv.major = DTLS_MAJOR;
    peturn head;
}


/* DtlsMsgInsert() is an in-order insert. */
DtlsMsg* DtlsMsgMakeDTLSv1_ if (!ssl->options.dtls)
        c16toa((word16)length, rm->seq < head->seq) {
        item->next = head;
        head = item;
    }
      ilse if (head->next == NULL) {
   S

ProtocolVersion MakeDTLSv1(void) else {
        DtlsMsg* cur = head->next;
        DtlsMsg* prev = head;
        while (cur) {
            if (item->seq < cur->seq) {
              ocolVersion MakeSSLv3fdef BUILD_TLS_RSA_WI8_CBC_here it NAMI   ifites-state.
        suites->suites[indif

Tex  ecc_free(ssl-es->sui>rng, sdx++] s(ssl->suiteTRUN) {
D_HMAYPE_CIes->suiminctx);
   Write;rulse
ed_pool,?  (HandShakeHeandefgAlgoSz = (word16)idx;
}

void InitSuites(S:to list. Eitssl-RY_ERRkea        output;
    hs->type = tdef CYASSL_DTLS
g) {
 ss *n ZLeamx->failNoCerer);
    FreeX509Nanext = b = ctx-blo
    if (tls1_#ifdeshake he %to list. Eit     unctionSAsig && haveStaticECC) {
B      }
#endif

allo          _WriteCtx = &ssl->wfd;  /* corls1_2 && haveECDSA           
    hs->++  CYASpaA wi] = TL            suites-ut;
        c16 >(length, d
#elif definedns.dtls) {
        Dtls       c16ndif

#ifdef BU suites->suites[1_1ndshake message */
statisuites[iAddHeaders(byte* r(&coKey);
#enIVdif

    /& havePSK) {
      der extensions */
  sig,toa(ssl->keyns.dtls) {
        Dtlsurn MEMORY_ERROerifyCbuthT       = TLS_PSK_WITH_NULL_ScordLayerHeader*)buf->buffe ssl-rt() is an i
#elif define{
    if (!sstions.haveNTRUe = 1;A384
   AddRecordHeadif

    /s handshadShakeHead<ers for handShakeState  = NULL_STAndif

tls->messminimumeq);
        c32t0, dtls->fragment_offset);
 
                prevMIC_TYPE_SU       v->next = item;
veRSAMd5Roundsease r  intsaKey);
      es[id     sx++] = ECMd5 md5ssl->heap,ioid)
  SLv3Md5(&md5d32 LowRl->peerEccKey, sd;

  ed) {
h);      MdessionIDv ca,x->CBIO ssl-prev-H_RSAUILD_mmy shaset");sl)
{
    H word32 sz)
Sha   int recvd;

    if (ssl->ctx->CBIORecv == NULL) Shaecv(   CYASSL_MSG("Your IOSha(&sha  }
pt/as
      8_CBC_on purposfferBIOResl, (charack is null, please set");
        return Sha
    }

s  if:
    recvd =               (void)_LIBZyte* buf, word32 sz)
Sha256IOCB_ReadCtx);
    if (recvd < 0)
        switch (recvc.
 sN_RST
            case CYASSL_256CBIO_256ERR_GENERAL:        /* general/unknown error */
                return -1;

      = ECC_BYTE;
     YASSL_CBIO_256ERR_WANT_READER_SZ, handERAL:        /* general/unknown error */
  error ifdef BUIt = MAX_RECORD_SI
    slock */
                384IOCB_ReadCtx);
    if (recvd < 0)
        switch (recvfreessee i
            case CYASSL_384CBIO_384    #ifdef USE_WINDOWS_API
                if (ssl->options.dtls) {
                    goto ret384YASSL_CBIO_384   }
                #endif
                ssl->options.connReset = 1;
               return -1;

  512lock */
                512IOCB_ReadCtx);
    if (recvd < 0)
        switch (recv512f we51ary *so       case CYASSL_512CBIO_512    #ifdef USE_WINDOWS_API
                if (ssl->options.dtls) {
                    goto ret512YASSL_CBIO_512                       getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_vaRIPEMDyte* buf, word32 sz)
Rmd   int recvd;

    if (ssl->ctx->CBIORecv == NULL) RipeMd ripem   (voiSSL_MSG("Your IO      (&   gotllback is null, please set");
        return       
    }

   gotry:
    recvd =          /* DHA
 wn error 0;
        s word32 sz)
Do   int recvtx->couecvd;

    if (ssl->ctx->CBIORecv == NULL) er      = 0;
    ssl- ssl->keynol->d    || defined(ls_expected_peer_ha ssl, byant read, wMD5def HAVE_PK_CAmd5= 0 && DtlsPoolSend{
    int d;

     }
                 = 0;

    ssl->ctx     = ctx;Sd;
}


/* DionCacha= 0 && DtlsPoolSendl->IOCB_Re     return -1;

            default:
                       returnd blrecvd;
        } Cya
    return recvd;
}
return WAN     return -1;

            default:
           return -1;

      recvd;
        }384fer(CYASSL* ssl)
{
   ERR_ISR:  G("Shrinking output buffer\n");
    XFREE(ssl->buffers.outputBu.tv_recvd;
        }512fer(CYASSL* ssl)
{
             G("Shrinking output buffer\n");
    XFREE(ssl->buffers.outpuAD;
   ernal.c
 *
 *rmsl->d    || defined( }
            return -1;

            default:
        110-1301, USA
 */


#ifdef HAVE_CONFIG_H
Baderror *IOCB_WriteCtx = &ssl    ssl->sessffers.wdoA
    XFREE(saKey);rn;
       on       endif  return -1;

        CsaKey);   int    return MEMORY_d;

    if (ssl->ctx-    ssl->opti poo  int   return     case tlsRecordLaketbuf->buffe,ssl->bufffer.l,  hav TLS_     cvd = s(tls && hallL) {
    ssl)
 (tlsquality
    ssl-s[idx++] = 0;
        suite_CTX)antedFrar      ifap, DYNsaKey);
      b(&ssl->d_ handl->options.haveDHO_ER poolE_CIPHER);
#ebadsl->optack is null, please s RSA sid) {
    = pv.minor <    
   ->lentem, void* heoodout  = out;

        suites->ba   usedLeAddHandShakstatic=uffer.bn id for user retx;  /* f (ssl->options.side0f
#iadRR_GEN
       if (tls*/
             _LEN)
        return;ETX
 ad) {
ueASSL_MSG("Shrinking input buffer\n")PadmyDeCcedFree && usC_TYPE_cketbase  XMEMCPY(ssl->buffers.inputBuffer.staticBuffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers..inputBu&x509adidx,
               usedLength);

    XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
          ssl->heap, DYNAMIC_sl->8_CBC_BUFFER);
    ssl-suitning up */
vextr(ssl, (    return -1;

   O_ERGet   int recvp/
   .side);ease set"      = CYASSssl->bL12)sz;R_GENsl, (cup flEND)->heap, DYNARROR_E2uffer = 0;
O_ERE;
   && usedLCONSTANT +pleas -  /* all doner.le	int sent = ssl->ctx->CBIOS);
   BuffIOSenddx,
 L1


/ && usedLUPPEf
#elseL2.outputBuffer.buffers_expected_L1 %e && usedLength               wRROR_E;
   ssl->he      2  ssl->buffers.outputBuffer.idx,
      r.le    ssl-L1 /utputBuffer     er +
                       ngth,
  +=
       er +
    x);
     2 */
    if (ssrs.o nt <    }


iSSL_Rresi    i    /Algo(Su8_CBCASSL_MSG("Shrinking input buffer\n")Tt) {
Padrs.dtlsS_128_CCM;
    }
#endif

#ifdef set");
        reeturn (word32) SYS_TICK_Get()l, please set"ites_TLSsl;

#ifdef Algo(SEE(ss  if (tls1_uffers.t_lenfer.lEE(ssP;
}
    ssl->ooutput_CLIENT_END;
       icedFreeif

SA_WITfer.leL* ssl, int  (C
      (ch)
   >pleas_RECORD_HEADER_SZ, lengtPap, D (challo{
   enoughf (sslad/macassl/ctaocry->bufferscedFreesaVer));
     Reset = 1;
         CYASSL_MpoolDtlsMsAlgo(S      }

->CBIOSesaKeyconnendiHeades[idx+
       message poi;

    if (!forcOn) {
       ctx->CBIOSe, veRSA) {
            */
    }
#endif
#elseAddHandShak->buffers    XMEM->CBIOSces(     /* ASSL_CALLBACKS
            indow = 0;
    ssl->keys.dtls->buffernextSeq = 0;
#endif     #ifdef CYASSL_CALLBACKS
                    (char*           if (ssl->toInfoOn) {
                            struct itimerval timeout;
                            getitimer(ITIMER_REAL, &timeout);
                            if (tim                   XSTRNCPY(ssl->timeoutInfo.timeoutName,
    
        susl->toInfoOn) {
                    (char*)ssl           streccTempdFree)
{
    i     ack is nullease );
      suifer.le                                 getitimer(N_CLO               co)pipeindow = 0;
    ssl->keys.dtlsidx++] MAC_TYPE_IN_BUFFER
}


/* return byte                      if (timeoutAES_256_G  default:
                    return  BUILD_TLS_RSA != NOAp   if ionDataICE) {
        AesFreeCavium(ssl->encrypt.a_hmac = 0;
#endms   rsl->groupMessages = c, DYNAMIC_TYPE_    __MORP
    XFREE(ssl->decrypendi == NULL) {
    vE   CY         ap, DY rawsent     suitesidx }

  keep  if (sslturn;pool,->heap, DYNAMICLIBth);  fdef FOfdefmpEE(ssLID_BYTE;
  +DSAsigOMPdshake  XFREE(ssl->de 0;
    ssl->options.usingSA_WItls_pool;

    if (pool != N+] = TLS AppBuffer;
     a ctx->haveDH;
    e      defaultssl->options.haveDH = 0;
    ssl->options.haveNTRU      = ctx->haveNTRU;
    ssl->options.haveECDSAsader extensions */
        dtls = (DtlsHan length, byte type, CYASSL* ssl)

        svoid AddHeaders(byte* oerRsaKey, ctx->heap);
  AKE_HEADER_SZ, handshake, ssl);
     
    }
#ifdef CYASSL_DTLS
    else  {
        AddRecordHeader(outpCORD_HEADERLS_HANDSHAKE_HE* NO_RSA */
_READ_can'SSL_M-CORD_HEAD_
void dx++] = TLS_PSK_def B              /*
    JOR) {
        return   ctx-     CBC_);
#es[i    X?
}


/* return byte305, ssl->heapT(&ssl->msgsRe* anduffer(CYt */

    if (grade    = ctx->raw   }
 READ_ER_SZ, hand     raw       CYA    adjustribut      XFREEngth -= sent;
l->buffers.outputBuffUBLIC     cas= 0;
        suneed
       toyDe     casSL_CBItputBufeturn );
     ss case CYAS   ss    = 0;
   t */

    if (align)l->sess    ssl = TLS_ECDHE_RSA_WITH_AES_    x);
    oid)
    {
20_POLY1305_SclearOcDsaKB  ctxCDSA */
  tputBuf       CYASSL_MutputBuffer.length);

    error on CREAD_E;
   AddHandSs->suites[idx++] = TLS_uffer.length -= sent;

#ifdefaKey);, ssl->be bigg   #* dtwril, bDH = Algo(Su(sizeof(Suites), if (!tmp) return MEMORY_int doFree = {
   n - hdrSz; (ssl-> align,LayerHeader* d>error = 0= sentth, byte type,
           CYAS_BYTE
    ssl-levex++] ->devId != NO  = INCE) {
        AesFreeCavium(ssl->encrypt.ae    *SSL_CBh);         /* type >cipher.ssl = ssl;

#ifdef outpussl->optionSSL*HA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_Sdx,
         if
#ifdef HAVE_  = IXFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_dx,
         
     *ssl->op  = ctxhod->sidtns.hfo + 2              ssl++] = TLS_ECDHE_v1_MINOR;     buffer, should t default */
    ssl->error = 0;h);         /* type and len->downgrade;
   , 2 +MENT : 0;
    /* th1_2 = pv.major =++] = SSL_RSA_Wssl->nxCtx;  /* and write */
#endif
#ifdef CYASSL_DTLSAL#ifdutputuites[idx++] = TLS_PSK_WITH_NULL_SHA384;
output    sui[    suites)++uffers.ef BUr alignment requirement. in trrays BYTE;hinCery.tes-_rx.ef BU=         to get size of record and put their a           *b = ctl data backRROR;
heir DECOYTE;
    uites[idx++] = SSL_RSA_WIA
    if (tlsBuffeDA_WITdef Bc   i_not_BUFER);

 >eccTempKey = C) {
         assl/cta     b = ctx-ength + alig_in  = inSz;
        ssl->d_engthif w
#ifdef CYASSL_ ssl->options.aoseN alignecCtx    put, l same fo->he_TYPE_ closed */
 groupMessages = ctx->groupMessages       suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM;
    }
#endif

#fdef BUILD_TLS_PSK_WITH_AES_256_CCM
    if (tls &uffers.outpuwitch = (voidpf)GR;  putsent > (int *

    /* han>encrypt.aesSSL_M(cur ==sl->bu == NULL) {
maxtex(&ctx->coO_ER (ss             sslHC_1       ssl-   if (tls && hmax

    wIC_TYPE_SOCKAD->heap,DYNDER_SZ;
_SHA
       X XFREE(ssl->bu_
void )
        ssl->buffe = align ,
       SG("SendB)
        ssl->buffe
         c-l->heap,DYNAMIC_TYPL_MSG__MORPH  ers->su;
    ssl->bu  }
#_RSA_WI suites->->me
    Xa */
     ecc_init(ssl->peerEccKey);
    ecc_init(ssl->peerEccDsaKe   if<MSG("EccDsa#ifndef Nrxnt GrowInputBuIN_BUFFER);
uffer =rs.inputBuffer.lengtutBu               (metho


/* check availableTLS_RSA_WITH_AES_128_GCM      /,
       XMEMCPY(tmp, sslGrow XFRE;

   SL_CBI   if (IN_BUFFER,
    ssl->bucareful with the suites[idx++] = TLS_RSA_ilableSize(CYA FreeStreams(CYASSL* NULL_SHA384
    if (tlANON
      endifa   }>metifif weturn eer.length += 1;
    ifss in tuffer.offset = align - hdrSz) {
        if 1;

    issl->buffers.inputBuffer.offsetffers.outputBufferssl->buffers.inputBuffer.offset;
      .offset = align - hdrSzffers.outputBuffer    ssl->buf>buffers.oumo>sui_SERVER_Ee* tmp;
                                 ssl->optionsalign)
        ssl->buffers.inpu=l->heap,DYNAMbuffers.outputBufftBuffnetworkutputBufdorade    = ctxhod-MELLIASL_CBh);         /* type an        return MEMORY_E;
    }

 HAVE_FUZZER
        if (ssl->fuzzerCb)
        t    tlh);         /* type an#endif
#ifdef HeSize()
  -, CYASSL* ssl)
->wfd;  Oions= aligf

#ifdef BUIzerCtx);
#WANS_PSASL_RSA_WITH_RC4l->sess_SZ);
   ndif

#ifdef BUi  if#endi ecc_init(ssl->eccDsRECV_OVERFLOWf

#ifdef BUIalign)
        ssl->buffers.inpu+    to output buffe-n same+ ssl-        align)
        ssl->buffers.inpufer) {
 */
    if (ss_NETX
    ssl-fdef HAVE_Tites->Mac                 return WANT_WRIT     CYASSL_
#elif defined(CYASSL_TIRTOS)

   /* connium(ssl->eSA_WIyte* out,int ou
        ssl->buf>decrypt.aYASSL* ssl, ssl->nput, word32*  ato32(inB_lener.le */
    hs = (HandShakeHeader*)output;digeVALIDype = type;
    c32to24(length, hs->length);         /* type and length same for eac */
#ifdef CYASSL_DTLS
    if (ssl->optio /* advance pastdef CYASSL_DTLS
   itX509Namfdef FO*/
                    ssz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ :
                                      RECORD_HEADER_SZ;
    byte  align = CYASEE(ssl-    e.tv_sec o define their alime,
        ->keys.dtlHA;
    }
#e                    

#ifndef NO_CERTS
   ld block */
    tls_handshak = ST /* advading efine their     msg->next = NULL;
            ms       S_ECDHE_ECDSA_WITH_AES_256_Gead = DtlsMsgNew(dataSz,*/
      x++] = TLS_ECDH_RSA_r(&couslv3, some i
   O_RSA
    && ve     ys */
voi = (SA_WIh);         /* typSecrlow      = size IO_ERR_CONN_RST:, DYP      _TLS_DHE_PSK_WITHptions.connReset = 1;
    IATION_INDICATION             case CYASSL_CBIO_ERR_ING which mayAD, >wnKeyefine /* advanry.laer;
    ssl->buffers.outputBuff  /* see if we got our timeout */
                FUZZ_HEAD, C, ssl->opR_GENERA== CYASSL_CLIENT_END &&
(ssl->b         _128_GCM_SHA256
    if (tls1_     #ifdef CYASSL_CALLBA
               1;
   t) {

   ss_CLIENT_END &&
      }
                    #endif
 LY_DONE)
          AD, - 1eturn (word32) SYS_TICK_Get();inue;

      
        suites->                     getitimer(eckWindow(&ssl->keys.dtls_state) != 1)
            returtxRes/* advaLL;
    }
    XFo EPOCH
        */
    }
#endif
#else /* !USENTRU_RSA_WITH||return VEReptState == ACCEPT_BEGIN) */
    }
#endif
#else /*  {
        suitesALIGNMENT;
    /* the encrypte;

   }


void FreeSSL_Cons.dtls) {
        if (DtlsCheckWindow(&ssl->ntinue;

      
    }
#endif

    /* record layer length check */
#ifdef HAersion.miname as #ifndef NO_CERTS
NGTH_ERROR;
    }
#else
    if (*sizssl->options.acceptState == AC
                            if (timeoutANDSHAKE_HEADER_SZ, handshake, ssl);
     *SA_WITShakeHeader(output + RECORD->RsaVerifyCtx = NULL;
    );
      /* advan     his reeys./* NO_RSA */
#endif ;
    else
           XMH_AES_2sASSL_MSG("Sisn = c, 1  CYA_LEN suit
    hashMd5);
#es wenegnor >A
    XFis
      lVersiodif

#ifdef             ssl->optionsrypt.aes, PeerRsaK = sD_E;
        }
atomicUsHC_12inOutIdx, &ssle - soffsets_state.cuinit(ssl->peerEcc, word (ssXFREE(ssl->bufferATOStatUS
            int/
          ites->esult;
     nst byte *ptrcert if (ssl->buffers.ou      _WITH_3Dr[1], size);

_SZ);
   84;
    } 0;
}


#ifdefWRITEASSL_SERVER_END)
      dif

#ifdef B XFRtain
      init( /* truside       default:
     DTLS
stati + ssl->buffe, ssl;;uites[idx++] ls = (DtlsRe   haveRtic intfdef (ssl->didStreYASSLr = s#endif

#ifdef *
 ,sl);
    includt_lenYPE_detecVATE   return NOheapctx->certChaDTLS
    if  *
 *dodif

#iSLv3:suites->suites[i;
     ) {
        if (ss
    }
#endif

#ifden the buffer that
 * has thesystem_sec();
    }


#elif defined(MICRIUMZ + DTLS_alert) {
        if (ss_TICK  clk;

        #if (NET_SEend ==   = ctxo         tIdx,
   eccTempKey = NULL;
#endif

   HC_128_SHA
    if (tls &f (ssl->pee    XFREE(ssl align + DT)eSize() called with= ACCEPT_BEGIN)
            E(x509->sig.buffer, NULL,l within the buffer that
 * has thers.outpuef HAVC_SHC_SHA
    v    = ctxmessage pointer is  (ssl (align)
        ssl->buffers.inputh);         /* type and uffer.offset = align - hdrSz;
    ;

    c24to32(i (ssl<
    idx                         nput + idx, fragOffset);
    idx += DTLS_HANDSHAKE_FRAG_SZ;_SZ;
    c24to32(input + idx  suites->suites[idx+rtificateLngra#endoff WEDo16(input + idx, )XMALLOdef sl *SSLv2rd32 idx = *inOutIdx;

  0;
#ifdef HAVE;
    ssl->options.connectState = CONNECT_BEGIN;
      ssl->options.acceptState  = ACCEPT_BEGIN 0x36, 0x36, 0x36, 0x36buffers.inputBuffer.offsetgo[idx.offset = align - hdrSz]28_GCM_SHA256;
    }
#endif=
        sCYASSL_MSG("Server at_lenb0, bHA;
    }
#endifx36, 0x36, 0x36,
        wordl->bundif

#iOld.key = ctx-PerformanceCounter(&cou default cb  if    igsuites    CYs->sroASSL_M if (tls && haveRSA) {
        su6, 0x36, 0x36, 0x36h);         /* type and len                             +f (s!=
          6
    if (tls1 ssl->buffers.outputBuffer;    {
    word32 idx = *iame != NULL) {
        if (nameAVE_CAVIUM
  +, dtls->sequence_                        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 035c, 0 0x33_MAJOR+] = TLS_DHE_PSK_WITH_AE0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };

/* calculate MD5 hash for falertd */
x5c, 0x5c, 0x5c, 0x5c,
                         ss */
in= 0;      0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x freow many    ret_Met                      st required */
statib0  }
#endif

#ifdef 36, 0x36, 0x36, 0x36, 0x36, 0x36
                           ent. in tesult);

    1* make md5 outer */
    Md5Update(&ssl->hashMd5, ssl->arrays->masterSecret, SECRET_LEN);
    Md5Upda.closeNo    ceECDSAsig)(((b0_TYPE7f)ssl-8) | bme,
        es->suites[idx++] = TLS_ECDH_ECDSA_WITH_R 0x5c, 0x5c, 0x5c, 0x5c, 0x5get  ssl-Lay8_CB= ct                  ites[idx
    x509->basicConstCritt, word32 *fragSz,
           ruord32  word32 idx = *inOutIdx;

    *inc,
                     DSHAKE_HEADER_Send == sz    retdtls_peer_handshake_number);
    idx += DTLS_HANDSHAKE_SEQ_SZ;

    c24to32(input + idx, fragOffset);
inal(&ssl->hx += DTLS_HANDSHAKE_FRAG_SZ;
    c24to32(input + idx, fragSz);

    return 0;
}
#endif


#ifndef NO_OLD_TLS
/* fill with MD5 pad size sincet required */
static const byte PAD1[PAD_MD5] =
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
            * make sha ou             0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0* make sha outer */
    ShaUpdate(&ssl->         0x36, 0x36, 0x36, 0x36, 0uites     }
#endsl->hashSha, sha           0x5cLv3_MAJd5Final(&ssl->hashMdYASSL_SMALL   if (GrowOutputBuffer(ssl, size) < 0)
    
#ifndef NO_PSK
    ssl->a return 0;
}


/* do all verify and sanity ch5c, 0x5c, 0x5c,
                                0                           { 0x3c, 0x5c,
                                0x5c&& haveRSA) {
        suites->suites[idx++] = Ee sha ou_ECDHE_ECDSA_WITH_AES_= DTLS_HANDSHAKE_FRAG(ssl->arrays, sslerride */

    if                             = }
#endif

#ifdef BUILD* sha256 = (Sha256*)XMALLOC(sizCYASSL_MSG("Server a 0x5c, 0x5c, 0x5c, 0x5c, 0x5OutIdx += HAN     = 0;
    x509->basic(tls && haveDH &&_timeout&& ha                ites[idx++] =(ssl);
    ssl->opl sene biggest required  *
 *onst byte* sender)
{DSHAKE_HEADER_SZ t + idx  ssl->optionfndef NO_SHA
        Sha* sha = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPETMP_BUFFER);
    #endif
    #endif
    #ifndef NO_SHA256
        Sha25s.closeNotify  = 0;def CYASSL28_MD5;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_1}
#endif

#SEQUE, DY alig_BUFFER);
    #endif
#else
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        Md inOutIdx,
                               suites->suit                             ifndef NO_OLD_TLS
  lt[SHA_DIGEST_SIZE];

   0;
        suites-ERROR_E;
            }(Sha384*)XMALLOC(sizeof(Sha384), ASSL* ssl, Hashes* hashes, consfers.o         #en XFREE(#endif
    #ifne* tmp;
    byte    Sha2sent ssl->arrays->masterSecret, SECRET_LEN);
    ShaUpdate(&ssl->hashSha, PAD1, PAD_SHA);
    ShaFinal(&ssl->hashSha, sha_result);

    /* make sha outer */
    ShaUpdate(&ssl->hashSha, ssl->arrays->masterSecreN);
    ShaUpdate(&ssl->hashSha, PAD2, PAD_SHA);
    ShaUpdate(&ssl->hashSha, sha_result, SHA_DIGEST_SIZE);

    ShaFinal(&ssl->hashSha, hashes->sha);
}
#endif


static int BuildFinished(CYASSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;
#ifdef CYASSL_SMALL_STACK
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
  x36, 0x36, 0x36, 0x36,TMP_BUFFER);
    #endif
    #endif
    #c,
       ingOneM_WITH_384;
    }
#enditIdx;
     #ifndef NO_MD5
        XFR  CYASSLTMP_BU> 1 */
 pgest r         #en  #endif
    #ifnisap, DEOF_SENDER);
    ShaUpdate((!ssl->optionDSHAKE_HEADER_SO_SHA
        || sha == NULL
    #endif
    #endif
    SHA;
    }
#endif

#ifdef BUILD_T     DtlsPoolhes* haswResTimer(void)
dif
#if !des->suites[idx++] = TLS_RSA_f (ssledCfaultthe GNU Generalad->next;
        Dt  if (usedLength)
        84;
    }>hashSha256 = sha25);
            inWITH_AES_128_GCM_SHA256
hakeHeader* hs;
    (vASSL_SMALL_STACK
 xt_in   = in;
        Sha384* sha384 = (Sha384*384*)XMALLOC(sizeof(Sha384), _128_GCM_st byte *CYASSL_MSG("Server aSZ;
    if (*inOutIdx >tes[idx++] = 0;
      alSz)
        return BUFFfdef HAVE_FUZZER
        ifER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input +                                            DYNAMIC_TYPE_TMP_BUFFER);
    #ena384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif

    return ret;
}


    /* cipher requirements */
    enum {
        REQUIRES_RSA,
 &ssl->hL_SMALL_STssl->ct    h);         /* type and length sameTMP_BUdx++] = TLL_SMALL    return BUFordLaurn (word32)rtp_get_system_sec();
    type,84;
    }
der extensions */
        e new item and insert into lis                   0x5c,                           FUZZ_HEate(&ssl->hashMd5, go pes->A_WITH1dHeader(out(&x509->issuer);
    FreeX509NaADER_SZ, handshake,+] = TLS_DHE_PSK_WITH_AES_128_CBt from the front of the buffer by
       the header, if the useSA requires an rsa key thus rsa_kea */
    scrypted alignment th = ECC_BYTE;
        s if (*inOut++] = TLS_ECDHE_RSA_WITH_AES_128_CECC) {
        suites->suites[i       dtls;

     a384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif

    return ret;
}


    /* cipher requirements */
    enum {
        REQUIRES_RSA,
        REQUIRES_DHE,
        REQUIRES_ECC_DSA,
        REQUIRES_ECC_STATIC,
        REQUIRES_PSK,
        REQUIRES_NTRU,
        REQUIRES_Rphemeral key exchange will Sha384* dif

#ifdef BUILD_TLS_ECDH_ tmp += alignIENT_CACHE!= NULL) {
        if (nameocolVersion MakeSSLRSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdstill require the key for signing
       the key exchange so ECHDE_RSA requires an rsa key thus rsa_kea */
    static int CipherRequires(byte first, byte second, int requirement)
    {

        if (first == CHACHA_BYTE) {

        switch (second) {

        case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            bsz &&
                   =N_SZ;
     
                return 1;
            break;

        case TLS_DHE_RSA_W                                 DYNAMIC_TYPE_TMP_BUFFER);
    #endi  REQUIRES_RSA_SIG
    };



 h);         /* type and length same fecond) have the er++, dtls->sequence_number);
        extensions */
        if (first ==_BYTE) {

        switch (second) {

#if NO_RSA
        case TLS_ECDHE_RSA_WI5_SHA256 :
       SendBuffered() out nput,   REQUIRES_Rndef NO_OLD_TLS
    #if>hashSha256 = sha256[0];
    #endifhes, sender);
 ILD_TLS_RSA_WITH_HC_128_SHA
    if (tl within the buffer that
 * has the>specs);
#ifdef Aecond) haveimer(void)phemeral key ex   }
    #endif
 (sizeof(Md5), NULL, DYNAMIC_TYPE_TMVE_CONFIG_H
   suitesndif
    #ifnmss[idxs, sender);
  ls = (DtlsRe    };



 */
        if (firs_CAMEL= 0;
    ad, cur);
        dif

#ifdbugg0x5c.hav = ctx->devId  suites->suites[idx++]   idx += DTLS_HANDSHAKE_SEQ_SZ;

    c24toq        = 0;
    HAVE_MAX_FRendif
#ifdef CYASSL_SHA384
    XFREE(sh, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x3    msg->next = NULL;
            msg->seq = 0TMP_BUFFER);
    #endif
    #endif
    #ifndef NO_SHA256
        Sha256                   DYNAMIC_TYPE_TMP_
    if (tls && haveRSAsig && haveStaticECC) {
    l within the buffer that
 * has the headers = 0;
  /
    ssl->arrays      return 1;
            break;
#endif
#ifndef NO_RC4
        case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_DSA)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_RC  DtlsMsg* msg = NULL;

   _CCM_8;
    }
#endif

#ifdions.acceptState == ACCEPTFRAG_SZ;
    c24to32(input + idxCHA_AEAD_TEST)
    #ifdeef HAVE_PK_CALLBACKS
    #ignin   return 1;
         VE_CONFIG_H
gotE(ssNGE LS_ECD SPEyassl/ctaocrypt/s   ssl->heap = ctx->heap;    /* defaults to  REQUIRES_ECC_STATIC)   ssl->options.tls    = 0 0;
}


/* Grow the input bl->buffers.pr    ssl->options.dtls = ssl->version GrowInputBuffer(CYASSL* ssl, int size, i}


voidse CYASSL_CBIO_ERR_CONN_Rsl->options.downgrade    = cagSz < sz, copy data Sz = DTLS_RECO   if (requirement ==t default */ITH_3DES_EDE_CBC_SHA
    if (tls && haveRSA) {YNAMIC_TYPE_TMP_BUFFER);
#endif
#endif

    return re  #ifndef NO_MD5
        XFREey) {
        if (          break;

        case TLSEncCcrypted data will be offset from t6 :
            if (requ= 0;
    ssl->options.closeNotify  = 0;
    ssl->options.sg* DtlsMsgNew(word32 sz, void* heap)
{
    DtlsMement == REQUIRES_RSA)
    AX_MTU;
    ssl->keys.dtls_sLLBACKS
    #ifd      }

        /* ECC extensi  if (requirement == REQUIRES_RSA_SIG)
   nCacheOff;
    ssl->options.sess    return BUFFER_E;

    *type =x->haveECDSAsig;
    ssl->ophashSigAlgoSz = (word16)idx;
}

void InitSuites(SuiDTLS
s= TLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_DSA_WITH_RC4_128_SHA
  TLS_Pssl->options.ve miifnderement == REQUIRES_ECC_D&ssl->wfd;   ssl->optionssMsgECfdef BUILD_TLS_ECDH_Edx++] = sha_mac;
     def CYASSL_SHA384
        ssl->hashSha384 = shatputBuffer.dynamicFla */
        if (first == ECCan rsa key thus rsa_kea */
    staticngNonblock = 0;
    RES_NTRU,
        REQUIRES_R    (ssl, hashes, sender);
          if (tls && haveRSAsemeral key exchange will still&ssl->ha!sed++;
        if (first == ECC_BYTE) turn 0;n *= 2;
    orru6 = length = 0;
  S_EDE_C            return 1;
          ENG[idx_SHA
    if (tls && haveRSAsig && haveStaticECC)>dtls_timeout_init;
             if (requirement == REQUIRES_ECC_STATIC)
, 0x36, 0x36, 0x36, 0x36, 0x36,.buffer, NULL, DYNAMIC_TYPE_P  }
#endifdif

#ifdef HAVE_ECC
    ssl->eccTempKeySzaveRSA) {
        sunge so ECHDE_RSA requires DE_CBC_SHA :
         {
      ites-> */
        if (first == ECCTH_AES_128_CBC_SHA :ctx->cedi NO_SHsedLe  if0;

#ifdef CYASSL_return 1;
            if (requiNO - cur] = TLcount as well. New will alloca     case TLS_ECDHE_ECDSA_WITHtic void BuildMD5(CYASSL* ssl, Hashes* hashes,SECREndif

#ifdef BUILD_TLS_PSK_     ssl->hashSha3 version mismaanceCounter(&counl->daKey = NSHA3     foside0x5cK_WITH_ef HAVE_LIBZ
;

    c24to32(input + (ssl->sSidendif

ocolVersSIDE_ONLYULL;
    }
    XFndif
#ifndef NO_SHA
    XFREE(sha, NULL, DYNA1;
            if (requirement == REQUI headers, and will include those headers in the hash. The stoRUNCPoolRes ssl->ccount as well. New will allocaastTLSv1_2(ssl)) {
    #ifndefCDHE_RSA_WITH_AES_128_CB REQUIRES_RSA_SIG)
              ATIOtes->suites[idx++] = TLS_ECDH     case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 G("growing output buffer\    return BUFFER_E;

    *type =utputBuffer.dynamicFlag = CDSA_WITH_3DES_EDE_CBC_Sd_rx = MCYASS

   += al == REQUIRES_RSA_SIG)
           EQUIRES_RSA_SIG)
                return   DtlsMsg* msg = NULL;

      ssl->buffers.o 0);
#endifS_128_CBC_SHA256;
   s);
        AesFreeCavium(ssl->decrypt.aes);
    }
    #endif
 

#ifdef BUILD_SSL_RSA_ /* internal.c
 *
 *ret = BuildFinished(ssl, &ssl->verifyHashes, server);
/* internal.c
 *
 * else if (!lfSSLoptions.resuming &&  is free softside ==is part of CyaSSL.
 *der the terms of the GNU General Public LiCYASSL_SERVER_END)d/or modify
 * it under tCopyright (C) 2006-2014 wolfSSL Inc.
 *
 * Thcliente is part of CyaSSL.
 *yaSSCopy!= 0 by
 * the Free Software FounurnFoun is part of CyaSSL.
 *break;
is part of CyaSSLcase applicae so_data:is part of CyaSSL.
 *ense asMSG("gotRANT DATA"at your option) any later vversi= DoANTY; withoData2014 d/or modify
 * it under the terms of the GNU GenelfSSLbuffers.inputBave r.have reral Public License for more details.
 *
 * You solfSSLhave received a copyidx) by
 * the Free Software Fn, Inc., 51 Franklin Street, Fifth Floor, Boston,on.
  {d/or modify
 * it under tense asERRORverse is part of CyaSSL.
 *buted in the hope that it will be us}pe that it will be useful,
 * but WITHOUT ANY WARRAlerten the implied warranty of
 * MERCHANTALERT!or FITNESS FOR A PARTICUURPOSE.  assl2014 would have received a copy of the GNU General Public License
 * alonrogram; if not, write to the , &typeeral Public License for more details.ogram; if not, write to tlengthat your option) any later versi==cyassl_fatal *
 * CyaSSL is distributed in thFATACONFIG_ is part of CyaSSL.
 *
 * CyaSSCopy<.
 *
 * CyaSSL is distributed in the hopis part of CyaSSL.
 */* catch warnings that are handled as errors */ your option) any later v(SHOe
  close_notify *
 * CyaSSL is distributed in thlfSSLSSL_C = ZERO_RETURNif
#ifndef FALSE
    #dGE_STATIC_BUdecrypt_SSL_Cude <stdio.h>
    #endif
#endif

#ifdef __sun
    #include <sys/fieful,
 * but WITHOUT ANYdefaull/error-ssl.h>
#include <cyassNFIG_HUNKNOWN_RECORD_TYPEh>

#ifdef HAVE_LIBZ
    #n thon-indication
#endi is part of Cy}f
#ifndef FALS is free softprocessReply = doPst bytInidif
#ifndef FALS/* eived exhausted?LLBACKS) && !defyaSSogram; if not, write to the e
  T)
    #ifdef FREESCALE_MQX
    is part of CyaSSLage(CYA0 is part of Cy/* more messages per recordLLBACKS) && !def
 * CyaSSHelloVerifyRequest(CYASSL* ssl- startIdx) <const curSize2110-1301, USA
 */

y of
 * MERCM             ithe     or FITNESS FOR A PAR#ifdefint DoSeDTLS
#ifndef FALSE
    #defiread-ahead but dtls doesn't bufine                     word32);
    static int DoHelloVree soft    2110-1301, USA
 */


#ifdef            const byte* input, int inSz, intn, Inc., 51 Franklin Strcontinuee <cyassl/ctaocrypt/settings.h>

#includ#endif                            const byte* inputrunint inSingOneM      if
#ifndef FALSE
   DoHelloVkeys.enif deionOn2110-1301, USA
 */


#ify of
 * MERCB     d        ed         , remove mid    pa, const byte* input, _TEST)
    #ifdef FREESCALE_M cons const 32*,
padSz                  ,
                                       ttings.h>

#in        * ssl,ALLBACKS) && !def
 * Cd32);
    static int DoServerKeyExcL* ssl, inf NO_Cor FITNESS FOR A PAR byte* input, word32*,
                                    2);
    static int DoCli          both secure-renegoti             ad nst bytf NO_CYstate,Checgram; youSSL_Cor FITNESS FOR Aage(CYAINPUT_CASEf __sun
    #incttings}
}


int SendChangeCipher(ense a*c in)
10-130byten, Inc., 51 Fr*outpu       pede
        static endSz = ation
#HEADER_SZ + ENUM_LENrunProcessOldClientHello, ssl  f
    getRecordLayerunProcessOldClientHello,endif
#ifnword32*,
                  tatic int DoCertificateRequest(CYASSL
#endif+=     cation
#EXTRA              ingOneM             int content, int ttings    #if     /*
#if weinedscrLLBACKS)put, word32*,
            u can redistributdefiShakeDonword32);
              MAX* MEnt content, 

#ifdeefinheck for avalaible sizeHashes* hashPURPOSECgAlgAvailable*, wlib.h"
#endi))ion.
 *
 * CyaSUE  1
#endif
#ifn/* get ouO_CYhave rLLBACKS)R
      const byte* inR
     a copy of th +               /* min */


int IsTLS(conQX
   if
#ifnAddR ssl,Header(R
    , 1, cm {
 _c  doP_spech"
#e)if
#ifnR
    [idx] = 1; FALSE
    #defie(CYAit onLLBAhes* hashes);
#endif

static void PickHashSigAlgo(CYASSL* ssl,
          def Neived[ader,
  ]          cessOeiveddif
 ader,
          returv1_20
}


intLSv1_2(const CYASntHello,
#endif
 ght (YASSL* 2014 winor >=T32 min, == DTurn 0;
Szeral Public License for more det1_MINOR)
        re is part o DoHe#endif

#ifndef TRUE
  eeds LAR#endionst byte* ha SSL_hmac(CYASSL* ssl, byte* digest, const byte* in, word32 sz,
LAR PURPOSE.tlsPoolSav   return 1;

    ret(word32 a, word32stributed in the hope that i int BuildCerng;

    if (cmd =CALLBACK ssl, byte* digest,hsInfo    AddPacketName("um {
    doP" wolfSSLo(CYASSL*if (d, byte* out)
{
fSSLtoif (cmd             == GET_NUif (TES_PER_BYTE_OF_ENTROPYtimeou
#endturn 1;

    retuee Software
 * Foundation, ITROPY)eape is pa    #ifdef if (ssl->version.major == SSLv3_#end   statihes* hashes);
ree softgroupYASSL* s a, word32 b)
          word32*,
              
 * CyaSSc int DoCertificateRequest(CY/* If uicke     ,o, wce the um {
    doPSpec         to bL* ssthe          * same t evate)(CYAin >f) 2006-        .LLBACKS) && static INLINE return (RNG_Gener
 *   in & 0xff;
}

f en a cop6-2014);


ty#ifnd32*NO_OLD_    sStaicturn e ashmacrocessInit =,or >=* digest,32);st c[0] =in, word32 sc32to24(word32 in, wpede    en
}


t  Inc.
 0,
#ifndef NO_warelt[    DIGEST_SIZE       c[1] =  (u16 dif
   ret   rlgo(sh_igAlint IsAtLeastes(CctualSigAlALLBACKS)c[1] = SL* sOneMes(HAVE_AESGCpad* convunProcessOldCopy] = (= INLGenerMd5 md5te* c)Sha sha        ret evLLBACKS)def Nseq[SEQ_SZ       def NconLen2_MINOR)
 + LENGTH >>     #definned(NO & >  8) &.minor  8) & 0xff;
macSecef min
yae asGetMbit one 2014 wLS) || ;
statd32*HAVE_FUZZERhes* hashes);
fuzzerCb   }

      *u32 = (u242014 w    sz, rd32_HMACh"
#end2 = (u2tx);
uildCertHashXMEMSET(seq, 0, u32 >>e is pa
    c[S_MAJ(def )* conveto16(co16toa((c[1]16)2];
&
    c[3] =  u3]ato16(co32u16 GetSEQIncremen c24to32(const woleq[igAlof= (wo32)[1])hes* hashes);
_AESGCmac_algorithme
  md5_mac2110-1301, Uz, iMd5(&md5e is part odef Nn : a;
    24) & 0Update2(con,2 bit one ,  || defie is part o*u32 = (c[0] << PAD1,LINE v| (c[2] << 8) | c[3];
}

#ec INL void ato16(c << 8) | c[3];
}

#e
    c,SigAlof(
    c)st byte* c, wordb ? b : a;
     << 8) | c[3];
}

#eu24[2]| (c[2] << 8) Final[0] << HACHA)st byte* c, woout2* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

#endi2 /* CYASSL_DTLS */


#ifdef HAVE_LHACHA)1] << 16) | (c[2] << 8)  {
        ( (u16 e is pattingsrd32*, word32);Copyriz, iSha(&shad, byte* out)
{ersion.
 *
 * CyaSSL id in the hope that i word32* u32)
{
    Sha2 = (c[0sha< 24) | (c[1] << 16) | (c[2] << L* ssl)
    {
  ndif /* CYASSL_DTLS */L* ssl)
    {
  IBZ

    /* alloc userL* ssl)
    {
  with zlib */
    static void* myAlloc(void* opaque, unsigL* ssl)
    {
  signed int size)
Sha {
     {
  void)opaque;
        return XMALLOC(iL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;yFree(void* opaque,L* ssl)
    {
     {
        (void)opaque;
) != Z_OK)
    emory, opaque, DYNAstatic INL}
static INLINCERT c16toa(wvoidMINOR)
D5_CertVInc.
yte* c)
{
    c[0] = (u16  0,
#ifndef N*/
sHACHA) |D5defined(HAVE_AE      remak     ord32* u32)
{
*u32 = (c[0TROPY) shMVE_LIfSSLarrays->master | (c[1]SECRET,
  e is pal)
    {
        if (ssl-ndif /PAD_MDnst byte        XF      if (ssl-   return T)

/* cid FreeStrea return XMALLl)
    {
        if (ssl->didStreamInit) {
            deflateEnd(&ssl->c_stream);
            in2lateEnd(&ssl->d_str    {
        if (ssl-   return , ;
    }


    sT)

/* cstream);
        }
    }emory, op

tyf (inflateInit(&sSHA>d_stream) != Z_OK) return ZLIB_INIT_ERROR;

     shareturn 0l->c  }


    static void FreeSshaord32* u32)
{
L* ssl)
         if S (fredidStreamInit) {
            deflateEnd(&ss       err = deflate(&ssl inflateEnSHA (err != Zeam);
        }
(&ssl-xt_out  =compress in to ol_ou return XMALL       err = deflate(&ssl->c_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_EN   {
  rn ZLIB_COMPR    err = deflate(&ssl-xt_out  =, out;
        ssT)

/* cMPRESS_ERROR;

        ream.next_in    #is in        it i)ssl->d_streaE void CYASS->heap;

        ic16toa(word1ght (d_st *
 * yte* c)
{
     *
 * *  if YASS10-130/* st    currnversStats, bht (;
  requiresetur_ (u16  whicheam.ets      it integtatic INLINE void c24) & 0xff; c32toa( if (ss
    c[1] = (
        if S (u3] = (in >> 16) tatic INLINSHA256func)myFree;256ut,ieturrr != Z_STREAM256_END) return ZLIB_DEd32*,
     SHA384func)myFree;384ut,i


vrr != Z_STREAM384_END) return out[2] =  in & 0xff;
}icateRe#if !YASSined(    ssl->d_s   }

    stream);
        }
    }sl->d_->const byte* c,MPRESS_ERROR;

        rLIENT_EN init     #ifdef HAVEyaSSIsAtLeastTLSv1_2opaqung) == 0) ? 1 : 0nt
static int input, worCOMPRESS_ERROR;

      E_LIBZ);
    }am.totESS_ERROR;

       256* Initialze S256e is part of CyaSSLer version.
 *
 * CyaSSL is distrid in the hope that it wi    #ifdef HAVE_SESl;
    }

#endif /* HAVE_LIBZd = method;
    c384ESS_ERROR;

       384* Initialze S384TX_free or SSL_free can release */
#ifndef NO_CERTS
    ctx->certificate.buffer = 0;
    ctx
#endif
  method->version    = pv;
    mrd32*, word32);it(&ssl->d_stream) !
    LIENT_END;
    method-   ssl->c_stream.avaart off */
   init zlibyte* hashSre_out  .minor       if (ss r */
_END) = deflate(&sitSS (u3    #ifdef  0 on success */
int InitSSL_Ctx(CYAS* method)
{
    ctx->method = nt = 1;        O_PSK
total_outbuffer = 0;
    ctxrtChain.buffer   = 0;
    ctx->pr   ctx->serverDO_PSK
ASSL_METHbuffer = 0;
   

#ifde (voidpf)ssl->ssl->d_stense asLEANPSKCYASS/*aticEC16 u YASSL* ,           */        ssl->d_st
       te* c)
{
    c[0] =inor >=TTX* oifdef HAVE_NTRU

static byte G 8) & 0xff;
  SERVER)
 ineturn t (SHOstrerd24 u24, woTRUNCATED/* coESCCM) \
    || definedminert opaque tM)
/* con32to24(word32 in,   returuncated16, b ? tx->timeout = ayer:d(HAVE_AESGCM)
/* conSL co

/* con) \
    || defined(HAVE_AESGCM)
/* conv   ctx->havec[1] =  uf
    getRecordLayerHedif  +  || defiAESCCM) \
   pad(u32 , iAESCCM) \
   ingOnessage
} processReply;

bedSendTvdif
 0int IsA/*  */
i.1  IVe */
static INL    erdif
    getRecordLayeIOCookie =16SigAl 8) & 0xff;ee or SSL_free v[AES_BLOCK(HAVE_Afndef FALSE
    #defimaxSigAlgoSz);

#X* ctx    ctx-32 >>#if !defatomicUseC_BU >> word32*,
               out[6])
{
    out[0] = 0;
    ousvoid 

#endif

#ifndef NO_CERTS
staticingOneM
#endif

#ifndef NO_CERTS
statice
    /*              int content, nt)ssl->R_IO */
#ATOMIC_US* u32)
{
    *u3ctx->MacE      24[0] << 16)f /* CYASSL_U16 bit integer onvert opaque t)
     TATIC_BUblock2110-1301, Uc[1] = RU = fined(HAVE_AESGCRU = 2, byte* c)od, ProtocolVersion pv)
1_1ng) == 0) ? 1 : 0edGeneays on               
   += by lif
#ifndef FALSyaSSby lo> ION_TICKb */
  ivFree Software
 * Foage(CYABUFFlishif
#ifndef FALSCopyriRNG_GenerateBU = t[6])
rng, iv->haYASSL_DTLS */free can release */
#ifndef NO_CERUE  1
#endif
#ifndef ttings.h>
sllbac
int IsAt/*x->CBdef N.minor <= D->CB= (sz -verifyCal) %ding key */
#endifn't seays on c- ser          tx->sut, add pssl->he4 u24, woAEADSSL_CLIENT_END)
        ctx->haveNTaead2110-1301, Uonvert opaque tbulkR)
      bit integ!= cyassl_chacha   }

    retuby loadites_EXP_IV/
   dd psk later */side =+32toa(word32E, cstat* con -] << 16) | (c[2] << */
sCPY(haveHello(CYAS ctx-exp_IV,  ctx->verifyPe    ctx->  ctx->havePSK s == CYASSL_C   ct2110-1301, Uy of
 * MERCOops, waOPENo writdif
s
     > b ? b : igAlor FITNESS FveECDSAsig  = 1; }
#endif
 igAlg= CYASS16)t yet */
    /*ifdefdef Nclude2 bi andTotal = /* user& ssl->version.minor >=TR_IO
c, word(SHOWturn 1;

   /*x->quieto }

#endashes* hashStati*, word32);ionCachedown = +
   ->have

#iStatlib */
  ND) d, byte* outdx HAVE_ECC
}
#endif
 cryptVerifyCb = NULL;
#  = 0;
#YASSL_DTL#ifdef HnECC
    iGE_STATIC_BUdefisSSL*
    ctx->DeCopyri *
 Oown =  return 1;

 erifyCallbndif /* taticECC = 1; p/decomp streams, 0 on success */
    stat

#ifdeLIENT_END)
        ctx->haveNTRU = 1;           /* alwtmpIssl,EccVereFrom;
    inor <= D, wo(ienerati <*/
    i++   }

    retu return */
#e++e* c, wordex(&cuites = 0;  g   e->CBvalutx->oyptCb   = NULL;
   f /* CYASS) {USER
 YASSLsl->ve Layer Callback defin;
  l_oucm = CyaSSL_CertManageULL;
    #else
t, wordndif
#ifdef HAVE  return 1;
= NULL;                         ER_ERROR;ignCb   = NUfdef dif /*#ifdef0  }
#endif
    return 0;
}

/* In case contAGER_ERROR;*/
void SSR_IO
    ctx->CBIORecvCBIORecv = Em
#ifdef HAVtx
    if (cmd == GET_Bd in the hop = 0;
#endif   ctx->haveECDSAsigLIENT_END)
        ctx->hav!RUE, ctx->RA */

    ctx->timeout = CYASS = 1;
        retuedReceive;
    can red_AESGCM)
/* con >] << 16) |*, word32);
   l;
    }

#endiMALL_STACK                 c[0] =;
   = NULLrtificate.buffer

/* convertion.minor >=Tffer, || defined(HAVE_AESCCMate.buffer = 0; ctx->heap, DYNAMIC_TYPE_KEY);
    XFREE(ctx->certificafer, ct, wor*)X);
 OC(|| defined(HAVE,tx->heral Public License for more details.
 *
 * You shTX* ctxDYNASL_Cendi_TMP_sig  =TX_free or SSL_free canfer, cctx->h */
#ifndef NO_CERTS
    ctx-MEMORYf HAVE_CDYNAMIC_TYPE_CERT);
    CyaS  #ifndef = defl, byart ofmacSSL_CtxResourceFreeexts are held ee Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Bostonn arraye is part of CyaSSLcryptVerifyCb = NULL;
nt--;
 << 16) | ( ctx->heap, DYNAMIC_TYPE_KEY);
    XFREE(ctx->certificaXFREEx->co(ctx->e)
{
    int doFree = 0;

    if (LockMu    #ifdef HAVE_SES}/


/*    #ifdef HAVE_SESSION    }
    ctx->refCoudown =+ULL;
    if (ctx->refCount == 0)
        doFree = 1;
    UnLockMutex(&ctx->countMutex);

    if (doFree) {
        CYASSL_MSG(ttings.h>
p/decomp streams, 0 on success */
    Cert Manager New");
 fdef HA_MANAGER_ERROR;*/
void SSL_CtxR+*/
void S CYASp, DYNAMIC_TYPE_METHOD);

#ifndeendif /* HAVE_ANONszt_in  pedef enC) 2006-2ocessInit = 0,
#ifncessOldClientHellvoid c32to24(word32 in, word2& 0xff;
fined(HAVEersion pv)
  ctLS_FINISHED Embeee Software
 * Foundation, Inc., 51 Franklin Street, FULL;
#endif  = NULL;
    ctx->CBIO== DTLULL;
#endif
+      HANDSHAKERecordLaye#ifd       ff;
    c[2]CYASSL_SERVER
    runPro       sif
#ifdef l->d_te* c)
{
    tx->privateKel->encrypt.chacha = NULe
    /* us->encrypt.rabbit = l->encrypt.chacha = NULdown =ECC
    iword32*,
                  c[1] =  equence_numbSSL_UHello(CYAS    _
    ssl->decry          ->CBIORepochhacha = NULt.setup = 0;
#ifduth.sL_METHOD* method, ext_etup         32*,goSz);

#ifndef minSetKeysSid   retuENCRYPd(HADE_ONLY(word32 a, word32 b)
    {
        reigAlgo, word3atic ISigAlgoSz);

ly1305 =0;
#AVE_PK_  = ) +             const b#ifndef min

    static INLINE wordly1305 =(word32 a, word32 b)
    {
        SSL_hmac(CYASSL* ssl, byte* digest, const byte* in, word32 sz,
/*t int C) 2006-  out[3] with  8) nextauth.s sslt do    commitdif

              UM_D {
  until  8) other _TYPconfirms its) ||e     5] =  in & 0xx->verifyCallback = 0->encrypt.t content, int veri#endif
}


/* Free c++>decrypt.des3);
    }
    #en
    ssl->decrypt.rate      et afeturuth.seId != N.minor <= D int BuildCertHashes(turn a > b ? b : a;
    }

#endif /* min */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && sH(CYASSL*rsion.mLL;
   cam = NULL    AesFreef ATOMIC_USER
 FreeS& 0xff;
     ssypt.des3f
    X= (       )&== DTLe
    /*       Copyright (C) 2006-2014 w    ss      doFree = 1;
    Unn redistribute it anck(&rng, LIENTshed ?or
 * (bedSs file is pap/decomp streoading key */
tes(&ctx->suSECURE_RENEGOTIATIONNULL;
        cecure_renegotiwithotx->haveNTRU,
       _CIPHER);
#endif
#ifdef HAVE_CAME   }

    retuionCache ssl->heap, DYNAMIC_TYPE_->r
 * (_ Inc.
ut ev>decrypt.aes, ssl->heap, DYNAM = NULL;
#endife is part oPE_CERT);
    XFR>heap, DYNAMIC_TYPE_CIPHER);
    XFEE(ssll->decrypt.hc128, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdefS
    ctx-<= DTLSv1_2_MINOR)
        return 1;

 ly1305 =NULL;
   tx->refCoun  AesFreeCaee Software
 * Foundation, /* HAVE_EC>encrypt.c
    /* TODO: add loveECDSAsiILD      __sun
GenerateBlock(&rng,AVE_NETX
    ctx->CBIORecv = NetX_Receive;
endif
}


/* Free c =REE(ssadd psk latetup = 0;
#ifdef HAVE_ONE_TIM0;
#f HAVE_ONE_TIME_AUTH int BuildCertHashyaSSL is free software; yoPE_DH);COMPRESS_ESSION_CACHEinor <= DAddSnTico#ifndVICE;
#enjust tryal_out;

 ssl, byte* digest, const bC128
    XFREE(ssl->encryp*, word32);
   Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of Cypt.cam, ssl->heap, DYNAMIC  ssl->encrypt.arcrd32*, word32);
   ickHashSigAlgo(CYASSL*Sr = i#endif
#ifdeDONtput, int outSzickHashSigAlgo(CYASSL* ssl 0;
1, DYNAMIC_TYPE_ord32*,
                           out[6])
{
    out[0] = 0;
    oul->heap, DYNAMIOVICE)e it will sooSL* seive ourPE_CIPHER, gox->MUILD                      *REE(ss(ssl->encrypt.despt.des3);
    }
    #endif
    XFREE(ssl->en(ssl->encrypt.des3, ssl->heap, DYNAMIC_TY
               DoClientKeyExchan ctx->haveNTRU           XFREE(ctx->serverDH_G.buff        = INVALID_BYTE;
    cs->sig_algo         >block_size  = 0;
}

static void InitSuitesHashSigAlgo(Suites* suites, int haveECDSAsig,
                                                  int haveRSAsig, int haveAnon)
{
    int idx = 0;

    if (haveECDSAsig) {
        #ifdef CYASSL_SHA384
            suites->hashSigAlgo[idx++] = sha384_mac;
            suites->hashSigAlgo[idx++] = ecc_dsa_sa_algo;
        #endif
        #ifndef NO_SHA256
            suites->hashSigAlgv_size     = 0;
    cs-oundation; either version 2 of the License, or
 * (at your option) = 0;
    cs->key_size    = 0;
    cs->i int Bu    if (cmd == INIT)
        return (InitRng(&rng) == 0) ? 1 : 0;

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (RNG_GGenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTEC) 2006-F_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endif        #endif
  used by ssl.c too */
void c32to24(word32 in, word24 out
{
    out[0] = (in >>  16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2 16 bit integer to opaque */
>heap;

        ipedef enuertif; wiTRA) || defin = NULL;
#endif   returQX
   ream);
 endif
#bedSendTf
    getRecordLayerHendif
#ifdef HAVE_POLY1305c[1] = cerl->enli;
        c[0] = }

#endif >> 24)  out[6])
{
    ou 0;
 PSKR)
     ||o;
        #en 0;
 AnonR)
    SSL_DTLS

static IN_CIPHnot needndif

id)tls;  /* shut up co   sream) ndifSEND_BLANK     ig_algo     OR;
  ;
    int tes >  8) &=     ef HAVE_POLY1305es pont   ;
    int o[idx++] = sha256_macSL_MSG("Iogram; if notOR;
 = pv.m SSLv3_MAeap, DYNAMI   } +     SigAlgoSz);

es pointer erSL_MSG(+ 2 *rror");
        return;
    }

   END && haror");
        rdon't overrimayhaveNx->M   s      ofl->d    al    ydecr lead_strypt.(s)ypt.des3, ss DoHelloVerifyReqOR;
Cme by of thig_algo         >  8) & 0xfSSL_SERVER_END && havetings, don't oven;
    }

 g = 0;     /* can't have RSA sig if signeddx++] = sha_
#endif
 >  8) & = pv.major == SSLv3_MAJOR && pv.minor >= fdef HAVE_POLY1305
    XFREEbyte* digest, const byte* in, word32 sz,
                    int con
    ssl->encrypt.t content, int verif  ctx->CBIOSend = NetX_SenHAVE_RENEGOTIATION_INDICATION
   algorithm = INVALID_BY word32*,
             inor <= DTLSv1_2               conO_CAVIUM_DEVICE) {
        Arc4FreeCaviu#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && srsion.sminor >=TTLSv1_MIust user seef ATOMIC_USER
 de */totalit intege

#i24(   }

 0 yet, no irypt.cha_INF do RSA with ECDSA ke
   eecrypWITH_AES_25OR;
          CYASSites[idOR;
    ;
        suites-tes->suites[idx++] = TLS_"CTX ref count down to 0, h"
#endif

#ifdust user set of the  /* ca   ctx->RsaV_INFOR;
  CDSA key */
  haveRSA; /* some bNT
    static= CYASSL_SERVER_END && haveECDSAsig) {
        haU && haveRSA) {
        suites->suite& haveECDSAs      doFree = 1;
    UnLockMutex( 0;     /* can't have RSA sig #ifndef NO_SHA
*/
        (void)haveRSAsig;   /* non ecc builds wohes* hashes);
#endif

static voversion.minor >=ef NO_C       return 11;
    if (i -ser will set */
  _RSAsl->d msg add_Free hd_AES_on.major == DTE_TLS_EXTENSIONS
 

#ifdef    byte h      XFREE(ctx, ctx->heap, DYNAMIC_ = NUHE_RSAtMutex) != 0) {
    SL_MSG("Couldn't ctx->sessionCacheO  = 0;ER_ERROR;   getRecordLaye}


#ifdee is part oTLSv1_2_MINOR)
        return 1;

    return 0;
}

#ifdef(ssl->decrypt.chctx->countsuites-
    }
#endif

#ifdef BUILD_TLS_ECDHE byte* out)
{
    /* TODO: add locking? */
    static RNGAMIC_TYPE_LIBZ);
    }NO_RSA
        ctx->RsaS   retur CYASSL_MSG(VerifyCb = NULL;
        ctx->RsaEncCb    = NULL;mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #ifdef HAVE_ANON
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = anonymous_sa_algo;
s    = pv.mF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endif D_TLS_ECDHE_RSA_WITused by ssl.c too */
void c32to24(word32 in, word24 out)
{
    out[0] = (in >>    (void)haveStaticECC;
#endif
#ifdef published by
 * thehaveStaticECC;
 filtatic vo publisror")COMPLETECDSAsig& 0xff;
    out[1] = (in >>  8) & 0xff;
    ut[2] =  in & 0xff;
}


#ifdef CYASSL_DTLS

static INLINE PE_CERT);
    16 bit integer to opaque */
snt    tls    = pv.mR    strocessInit = 0,
#ifndef NO_ER
    runProcessOldL;
    ssl->decr   static RN   tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= unProcessO(SHOT   suAJOR && sonly 1/

  now>CBIOCookie ream if (ssl->ver +_AES_256_CB[idxQ= ECC_BYTE;
integdd auth laeturn X->suites[n success */
int InitS}
#endif

#LS_E+=& 0xff;
}
yNone = 0uitT_EN_STREigAlgob = NULL;
   /* shut up compiler */
    (void)tls1_2;
    (void)haveDH;
    (void)havePSK;
    (void)haveNTRU;
    (v
#endif
    getRecordLayerHe->encrypt.rabbit =  +suitesLS_MAJOR) {
        tls    = 1;
        tls1_2 = pv.minor <= DTLSv1_2_MINOR;
    }
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    if (side == CYASSL_CLIENT_END) {
        suites->suites[idx++] = 0;
        ndif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_AES_128_CBC_SHA
  uitestls && haveNT_eam.16 >> ATOMIC_USER
    ctx->MacEncryptCb    return  CYASSL_MSG(AES_256_Cif (tl#/* s(SHO XFREtes(&ctx->suEC CYASS = TLS_ECDH_ECDSA)
    S    028_CECC_BYTE &&                      
    XFREE(sigECDSA28_Cecc_dsa_saECDSAig_algo     384;
    }
#enec    signuites->suiteifdef HAVE_256_CBC_AES_128_uites[idx++] = TLS_ECDH_rSA_WITH_AES_25#endif

#suppor        /si     havePSK            = 0;
    ctx->server_h  *u16 TE;
        suites->suites, & return [1]));
}_3DES_EDE 0xff;
}
CDSAsig) {
        dx++] = TLAMIC_TYPE_CIPHER);
    XFRETE;
        suites->suitDH_RSA_       suites->suitessuites->suites[iTE;
        suites->suites[iurn BAD_MUT  *u16 0[idx++] = TLS_f (tlsuth' XFREE(ssdef fls1_2     ->MacEncr, adINVALiites->suitC_SHA384
    ifSAsig &&mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #ifdef HAVE_ANON
            suites->hashSigAlgo[idx++] = shaECC_BYTE;
        suites->suites[idx++] = TLS_p/decomp streams, 0 onrc4, ssl->heap, DYNAMIC_TYPE_CI out, 1) == 0) ? 1 : 0;

    if (cmd  }

    return 0;
}

ef BUILD_TLS_ECDH4
    iE_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig) {
        suites->suites[idx++ites->suites[idxused by ssl.c too */byte havePSK,
                retur
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    >suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_Wfdef HAVE_!ream.total_oITH_AES_25 GNU te* c)
{
     8) & ateI6) & 0VER)
 sz = NULL;
#ens   XOSendex erlainTILD_f (side == CYASSvoid c32to24(wor(c[1#ifdef CYAtlsExtrNO_P(void)tls;  /* shTATIC_B= WANT_WRITES_256_CBC_SHA38TATIC_BU(void)tls;  /* shut up co= 0;
}

static !void InitSuitesHtx->haveNTRU,nt  st&& haveNTRy of
 * MERC/* HAVE_Eoid)hcompleNTRUtry;
  to->heap,or FITNESS Fger Neers)
{static NAMIC_TY   re.des3 e as UCCESSHA256
    if (tls1_2 +] = TLS_E_SHA256
  lShutused system soT_NU->suitesst CYASwas full}
#en aga>> 1d)haveReECDSAsig) & 0xff;
    out[1] = (in >>  8) &> 02110-1301, Uy of
 * MERCBYTE;
        suites->suitedif

#ihaveR[idx+UILD_TLS_ECDH_ECDShaveECDSAsig) integer to opaqunput02110-1301, USA
 d renegotiatihaveECDSAs #ifndef NO_SHA
   H_3DES_EDE_CBCSOCKETendif
_ECC)_SHA384
    ifconnRR);
                           .setSuitee     );
 LBACKS) && !defeeds LARGE_STATIC  = 0;
    cs->iv_size     = 0;
    cs-(tls1vanc2] =   ctxpreviousECDHE_+ TLS_EECDSA_INVALCDHE_LBACKS) && !defites[id 0;     /* ca_WITS256_CBRSA_WITH_AES_2LS_Eey */
#endif
#ify of
 * MERCCDHE_->quiehave red) & 0or F   static int DoHeDHE_>    *, word32);
    #if !defined(NOSSL_C: {
   ()    XFR_SHA
    if
#ifdsho  if (sor FITNESS FOR A PAReeds LARGE_STATIC_BUBAD_FUNC_ARGstatic int DoClientKeyExS_ECDHE_RIO */
#ifdef HAVE_NETX
    ctx->CBIORecv = NetX_Receive;UILD_TLS_ECDk = 0;

#ifndef NO_CERTS
    ctx-S */

   ;;PE_DH);
    XFRE    FRAGMENTg) {
        sulenUT;

#ift seTE;
ndif
# 0;  max_fragSSL_, OUTindoation
#    iSSL_DTLS
    LS_ECDHE_RSA_WITH_AES_128_GCM_S haveRSA) {
       L context, return(HAVE_WEB&& haveNTR&& havites a copE_TLS_EXTE & 0x+8_GCMULL;
   y swi FALonSHA;
    }
#endif
essOlhave */
    ifdef CYASSL_DTLS
  */
      _WITH_AES_128_CBC_SHA
    if (tlly1305 = Ntes(&ctx->suLIBZsion.minor >=TSHA;
 || dA) {
            A{
  N_INDI]6 bit integer = ECC_BYTE;
 , coz)ON)
    #mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
     SA_W= 0;


#il zli    UDP[idx++] x->certificat && haveRSA) = 0;
    cTYPE_CERT);
    IUM_DEVICE) {
        Arc4FreeCaviuavium(ssl->encrSA_W+ ifdef BUIL* HAILD_TLS_E     Arc4FreeCavium(sum(ssl->decrypt.arc4);
    }
    #endif
    XFREE(ssl->encrypt.a_ECDH_RSA_WITH_AES_256_C NULL;
#endif
YPE_CIPHER);
#endif
#ifdef idx++] dif /* min */


int IsTLS(const CYASSL* ssl)
{
     if (ssl->version.major == SSLv3_MAJx++] = TLS_ECDHE_RSA_WITH = TLS_ECDH_ECDSA_WITHComprlgorit   suites->suite[idx++] =myes[idx++E word32 m a cop ssl&& h[idxmplib */
    mpLLBACKS
    BYTE;
  [idx++]YTE;
        suites_ECDH_RSA_W BUILDstatic int DoClientKeyExchan
    }
#endifITH_S_ECDH_RSA_WITH_AESites->suites[idx++] = TLS_ECDHE_ECDSA_FREE(ssl->enndif

#ifdef BUILD_ee Software
 * Foundation, Inc.ANTY; without evd, byte* out)
{
    /* TODO: add locking? */
 IPHER);
#endif
#ifdef 16) & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2Manager New");
 ites[idx++] = ECC_BYTE;
        suites->suites[idx+
    #include <conext_out  #endiILD_callE;
 GCM_SHA384;or uASSLWITHdf en()VIUM
    if (ssl->d          idx+DHE_like->suites[idx#ifdef BUILD_TLS84
    if (tls1_2 & 0;
 TLS_ECDH_RSA  if (tls && have256_GCM_S0xff;                  #else
  
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    ifls && haveRSA) {
        suites->suites[idx++]] = TLS_byte* input, word32_256_C
#ifdefque;
            DSAs out[3]     attemp

#ifdef BUIL = TLS_ECDH_ECDSApartialW>quie== rver can turn on y of
 * MERCPari&& h aveRSAon, BUILDites;
  DSAs* ssl, const byte* inpeful,
 BUILD_TLS_ECDHE_RSA_Wg? */
    tt_in uiteeckWindow(Dtl & 0xff;if (Rg) {
   suites->suites[i(HAVE_WEBSERVER)
 2];
if (peek  suites->suicv   H_CHAd renegoNTER("_WITH_3DES_E)uites[idx_WITH_3DES_EDE_CBC_SHA
REAES_256_CBC_SHA38CDSAsig) {
        suitesCDSA_Won.

#ifdef B  }
#endi_SHA
    if#ifdef BUILD_TLS_ECDHE_YASSL sui;
  static     oc(vCDSA_WsState*id)hallowe, const byte*es->suites[idx++] = ECCE_RSA_WITH_AES_1->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_l->e_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECDSAsig && haveStaticECC) {
     TYPE_CIPHER);
    XFREE(ssl->decr byteScr#ifdefcam, ssl->heap, DYNAMIC_TYPE_DH);
    Xt.rabbit, ssl->heap, D
#endifes->suites[idx++] = TLS_ECDHE_256_CCM_8
    if (tls1_2 && haveEC_TYPE_CIPH      byte oLS_E.minor <= Dy of
 * MERCN (void)h] = TscrThis filream.eCLIEUILD_TLS_ECDH_ECDSA_WITH_3DES_ERe/* HAVE_EA
    if (tls && haveECDSAsig && haveStaticECC) {
    84;
    }
#ewhileCYASSL_SERVER_ENlearSA
   = (in >>  8) &=A 02110-1301, U
        suites->suint inSe* in= ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;FFERS, plea   suites->suites[idx++] = TLS_EZerox++] =     BC_SHA & 0xco; yo#ifdef BUILD_TLS_ECDH_RSA_WrateCook&& hav_8;
    }
#endif

#HACHA20_POLY1305ttings.h>

#inES_256_GCM_SHA384;
    }
#endif
   suites->suites[id   if (tls && haveECDHE_RSvoid)tls1_2;
    isCFERSctx->haveNTRU    suites->suites[idx++]& haveRSA)orUFFERSd[idx+necWITH_don
#ifdef BUILD_TLS_ECD_CBC_SHA
    if (tls && haveRSA)28_GCM_SHLLBACKS) && !definedttings.h>

#inttings.h>

#ines->suites[idx++] = ECC_BYTE;
       TYPE_CIPHER);
    XFREE(ssl->decrypt.->serverDH_G.buffeLS_ECDHE_ECDSA_WITH_AE    ctx->CBIORecv = EmCCM_8
    if (tls1_2 && haveECDSAsig) {
  ites[idxgo;
    }
Sc] = ECC_BYT   }
#endif

#i= 0;
#endif /* HAff = 0;<H_AEt)ites[idx++] = TLS_RSA_WITH_AES_128_CCTY_RENEGOTI   ctxypt.84;
    }
#endif
 haveDH tes[idx++] = TLS_RSA_WITH_AES_128_CC      scryptVerifyCb       suites->suTLS_RSA_WITH_AES_ = 0;
   CYASSLA_WITH_RC havM_8;
    }
#endifs->suites[idx++] = 0;
        suites-ientH             E_RSA_WITH_AES_256_CBC_SHA;
    }
#en*/
  cv   = NUE_RSA_WITH_AES_1idx++] = TLS_RSA_WITH_AES_128_CCM_8;
CC) {
        suites->suiefined(CHACHA_AEAD_TEST)
    #ifdef FREESCALE_MdynamicFlages->suiteShrinkIived a coprefCouNO_FORCED_counifdef BUECC
    ctVEs[idx++] = ECC_Bdif

#ifd_WITH_AES_12cv   

tyRSA_WITHyasslS_DHE_RSACDH_RSAf ende "zlte* c)
{
    ->suit Incty/* OPENSSL_EXTminor >=TLSv1_2pt/as(HAVE_AESCCM 0;  /R
    runProcessO   static RNBUILD_T
    ssl->dely1305 = N_RSA_WITHUILD_TLS_ECDHE_ECDSAAES_12itesD_TLS_isf (tled(Cidx++#endifnblokls1_2 && haoid)haveStaticECC;

 de "z ECC_BYTE02110-1301, Uf

#ifdef BUILD_TLS_ECD= TLS_ECDH_RSA_WIT_8;
 c_dsa_sa_algo;
        #en>suites[idx++] "InitSuites ptx->RsaEncCb    = NULLmac;
            suites->hashSigAlgo[idx++] = rsauites->suite  suites->suites[idx++] = TLS_ECDHuildCertHashes(_DEVICE) {
        Arc4FreeCavium(ssl->encr[idx++] = ls && haveRSAsigHA
    if (tSA_WITH_RCdecrypt.arc4);
    }
    #endif
    XFREE(ssl->encrypt.arc4, ssl->heap, DYPE_CIPHER);
#endif
#ifdef BUILD_AES
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        AesFreeCavium== DTLS_MAJ, word && have   }
#env1_21
#endif

#ifde self */
#i      hi_outy.es->_tx.coit aH_ECDLS_RSA_WITH_AES_128_CBC_SHA;
    leveCBC_;
        suitecha, & havee
        #incluA_WITH_AES_128_C6_CBC_SHA256;
  BC_SHA384;Ddef HhaveRFFERS)
    # return BAD_MUTtes[idx++aveR          S_128_GfE(ssl->deceger tolySHA;
    }
EVICEwi
/* converEVICE)D_TLS     ot(in     Ato defineconsECDH_ECDSA_WITH_#endif

static void PickHashSigAlgo(CYASSL* ssl,inor <= DTLSv1_2_MINOR)
        return 1;

 EE(ssl->encrypt.c[idx++] = uilder, opaquerd32*,     cs->mac_sl->version.minor >=TDH && havePSK) {
] = TLS_urn 0;
}

/* In user will set */
    ctxut, word32*,
                       suites->suites[idx++] = 0;
      _TLS_ECDH_R#endif

#ifndef NO_CERTS
static    #ifdef HAVE[idx++] = TLS_DH&& haveDH && haveites[idx++] 
#endif
    getRecordLayerHe[idx++] = s[idx++] = 
#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveP                    int content, int f NO_CERTS
    XFacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_POLY1305
ig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;de "zF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endifsuites[idx++] used by ssl.c too */
void c3   byte haveDH, byte haveNTRU, byte haveECDSAsig,
                byte h   }
#endif

#ifdef BUILD_TLS_RSA_1 haveStaticECC, int side)
{
    word 8) & char*2 && havERRveDHsonfined(_string(unWITHed lo    _EXTRA */

NO
#endifSTRINGSs->sui(ateI)#ifdef age(CYA"no   if (tif (taveRSA) _PSKs     endi"es->PE_CE  }
#endiCDSA_WITUILD_       suitesss    CTaoCSSL* eECDSAsig) CDSA_W<if

#ifDEf

#ifCDSA_W> MINUILD_TL
        suitesn thM_SHA256;GetESL_CSE_PSK_TLS_ECDHE_RS_SHA256_WITH_A   suittes->sui WARRUNSUPPORmeouSU384;#ifdef HAV{
      un  if (tls1
    (v     suitsuites->seWindow(DtlsStatS_PSK_WITH_AES_128_ow(DtlsStat  stati
#ifdef BUILPREFIXPSK_WITH_AES_128_CBC_SHA2bH && dex    key rounds haveDH && ha"Couldn'K_WITH_AES_128_CBC_SHA2dif
ofA_WIory haveDH && haVERIFYNULL;
#end= TLS_DHE_PSK_WITH_AES_1 Inc.


#iblemAES_& 0xff;
;
    }
#endif

#ifdd = TLS_PSK_WITH_AES_128_CBC_SHA256ef H
    if haveDH && havARE_PSK_WITH_AES_128_CBC_SHA2pars(tls &&AES_e
     haveDH && haef HA= TLS_DHE_PSK_WITH_AES_1wr28_Gr
 * (/

#ifde(SHO haveDH && haNO_PEDSAsig)S_128_CBC_SHA256;
  & hadidTLS_RSA_WIites
#ifdef BUILon-indic->encrypt.endi28_CBC_SHA
    if (teirs1_2ITH_AES_      suites->sui
    }
#endif

_PSK_WITH_AES_128_aveRSA) {
 AES_ = ECC128_CCM
    if (tls NOITY DH && havePSK) {
   xpec    BYTE;
] = VICEf

#ifdef BUILD_{
      _     suites->suites[idxfdef Hhave enough }
#entoSHA;
     taskPSK_WITH_AES_128_CBC_ation
#endiS_PSK_WITH_AES_128_GCknown_AES_ASSL* ssl,s[idPSK_WITH_AES_DE  #ifd= TLS_DHE_PSK_WITH_AES_1endif
du_PSK

#if deio suitsuites->s#ifdef __suDH && havePSK) {
  revc_WITH_NU#incltls && haveDH && ha    #ifdE_PSK_WITH_AES_256_CCM;
    }
#endif
          ILD_TLS_PSK_WI++]  ECC_BYTE;
        suitesfeDH &suites[idx++] = TLS_tes[idx+KEYDH && havePSK) {
    (vo>sui's
   WITH_AES_256_CCM
RIVATE if (tls && havePSK) {
     in >priviteses->suites[idx++] =DH_PARAMSDH && havePSK) {
  

#ifdemiTicke DH paramuites->suites[RSA= ECC_BYTE_PSK_WITH_AES_256_CCM;
    }
#endif
rsa+] =  opites->suites[iATCH] = TLPSK) {
        suites->suca    me FAL    }
#endif

#ifdef BUILIPHER);
#endif
     suites->suites[    suout[3] failu_AES_128_CCM;
 BC_SHELLO= TLS_PSK_WITH_AES_1
    Xhello malformavePSK) {
     DOMAIN_NAME_MISs->su 0;
        suites->suitsubject nout[misM_8;
PSK_WITH_AES_s[idx++] DH && h    ifnegotiat_84
    if (tls &SK) {
        n-RU = /
   = ECC_
   sCCM
    ibuiteavePSK) {
     NOdx++] ] = TLS_DHE_PSK_WITH_AES_1_PSK_WITH_l(ctx-] = s won'yc[1]f (tls &&firs[idx++] = ECC_PMS_VERLID_BTH_AES_128_CBC_SHA256;
  ret) {
  s one *veroritDHE_PSK_Wtls && haveDH && haK) {
        suites->suites[idx+       BUILD_uites->sls && haveDH && haGCM_SHA384;(tls && haveDH && havePSK) (tls && havsuites->suites[idx++] = 0;
      
        sutes->
#ifdef BUILD_Tg  = 1TH_AES_256_CCM_8
    ifs->suites         NO_CYA+] = TLS_PSK_WITH_NU#ifdror")TLS_PSK_WITH_AES_128_CBC_SHA256
    if (tlust user se;
    }
#endif

#ifdSIG       suites->suites[idx+_SHA256
    if bauite->suignat{
        suites HAVE_CICM;
    }
#endif

#ifdef BpskIA
    Xident    K_WITH_NULL_SHA256 publisHIE_CAFIG_(tls && havePSK) {
   

#ifdehdx++] =&& haveDH && havSK if s->suites[idx++] = TLS_PSK_W     sui== NU;
    }
#endif

#iNTRUf BUILD_SSL_RSA_WITH_RC4_128itesA
   RSA ) {
        suites-DRB#endif
dx++] = 0;
        suitdrb   stati{
        suites-dx++] = ECC_Bdx++] = 0;
        suitCYASSL* suites[idx++] = SSL_RSA_ TLS_DHE_PSK128_SHA;
    }
#endif

##if des->suites[idx++] = ZLIB_INIes->suites[idx++] = TLS_Pzlib ini_RC4_128_MD5;
    }
#endi{
  RESSifdef BUILD_SSL_RSA_WITH_3DESITH_dx++RC4_128_MD5;
    }
#endiDE ) {
        suites->suites[idx++] = de0;
        suites->suites[iGETTIMidx++] _PSK_WITH_AES_128_getused fday()ifdef BUILD_TLS_RSA_WIITH_HTH_NULLMD5
    if (tls && haiusedr        suites->suiteSIGACes->suites[idx++] = TLS_Psiga  if ] = TLS_RSA_WITH_HC_12[idx++] = 0;
        suites->suises[idx++] = TLS_RSA_WITH_HC_1 0xff;
->suites[idx++] = TLS_Pef BUILD_TLS_DH && h;
    }
#endif

#if    if uites->suites[idx++] = Tc    
#endSA_Wer_PSK_WITH_AES_256FFERS, plea(tls && haveDH && hav
        suites->  }
#endif

#ifdefDHE_FFERS_TLSA256K) {
tes->suites[idCC_CURVEnt do->suites[idx++] = TLS_PtlsCif

Curve T    ++] CM_SHA256;2B256;
    }
#endif

#f BUILD_TLS_RSA_WITH_AES_128_CBC_B2B25 if (tls && haveRSA) {
        #ifdf BUILD_TLS_RSA_WITH_HC_128_128_CBC_WITHKs->suites[idx++#endMAKEf BUILD_TLS_RSA_WITH_HC_128if

M
   KeyPSK) {
        suites#endEX[idx2B256
    if (tls && haveRSAExes->s       suites->suites[idx++]SHARLD_TLS_P    if (tls && haveRSADHEPSK
uiteSK) {
        suites_PSKCAites[idx++] = 0;
             CA byndificidx++]ra_SHA;
    }
#endif

#iBC_SPA suites->suites[idx++] = TtlsChathif (topsuittes[idx>suites[idx++] = ror")MANAG] = 0;
        suites->suitlsCuite Manag CHA
    }
#endif

#iOCSPLIA_12REVOKED_PSK_WITH_AES_128_= 0;{
    revokhaveRSA) {
    CRL
        suites->suites[idx++] CRLS_RSA_WITH_CAMELLIA_128_CBC_SHMISSINGdif

#ifdef BUILD_TLS_SK_WITH_PSK_WloadhaveRSA) {
    MONITOR_RUNNING_E  if (tls && haveDH && onit words won'run0
#eLD_SSL_RSA_WITH8_CCMCREavePS_PSK_WITH_AES_128_TheDH &cre_WITH_suites[idx++] = TLS_= 0;
NEED_URLes->suites[idx++] = TLS  (voURLuites[idx++] = 0;
     on-indies->suites[idx++] = TLS_RSA_CC_BYTELIA_256_CBC_SHA
  LOOKUP_FAIls && haveRSA) {
       RespondH_HCookupBBIT_        suites-X_CHK_WI->suites[idx++] = TLS_PMaximum>> 2in Depth ExcveNTRMELLIA_128_CBCOOKIes->suites[idx++] = 0;
       Cookie SK) {dx++] = 0;
    QUENC suites->suites[idx++] = TLS_DS    ssl_WITH_CAMELLIA_256_C= TL      suites->suites[idx+sig &s Poin;
  WITH_CAMELLIA_256_CSL_tes[iMRecordL{
        suites->su PEM rsion.uites->suites[idx++OUT_OF_ORrdLa }
#endif

#ifdef BO8_CBC_orA_WI&& have,
     >suites[idx++] = KEAint do }
#endif

#ifdef BtlsCKEA;
    f   sRSA_WITH_HC_12ANITY_CIPH    }
#endif

#ifdef BSan    igAlgodx++  doPtILD_SK) [idx++] = 0;
  RECV_OVERFLOW (tls && haveDH && h_WITH_3  if (haveif (tlER);_SHA;hathe BUILD_TLUILD_TLS_RSA_W_128    su_PSK_WITH_AES_128_et side DHE_RSA_WITH_CAMELLIA_256_tes[idx+
    idx++] = 0;
               s++] = 0;
   32(consuites->suites[idx++F    itls && haveDH && haveRSAftes->sWITH_CAMELLIA_256_YTE;
_s->sui->suites[idx++] = TLS_PCachuite_out  e
    CM_8;
 WITH_CAMELLIA_256_on-indicSNI_HOSTITH_AE     suites->suitesUn* ssgnizls1_osD_TLS_DWITH_CAMELLIA_256_KEYUSE[idx+AT   X     suites->suites    Usel fritalSf BUILD__TLS__WIT  suites->suiteSz = idx;
EN] = 0;
        suites->suiites, hakeyEn_DHE_RSSL_RSAsig, 0);
}


#ifndef NO_EXT= idx;
AU sui    if (tls && havexLS_RSA, ha (tls1/        && hSAsig, 0);
}


#ifndef NO_tes =OOBx++] 
        suites->suitaveR>cm == NUUILD_TLB   su RDH &WITH_CAMELLIA_256_CB    XFREE(ssl->dec (name != NULL) {
  Invalid RE_ECDSA_WITH_WITH_CAMELLIA_256_CBALID_BTI   }
LE /* OPENSSL_EXTRA */
algorit Ti ECC_Too L28_G9Name(CYASSL_X509_NAME* name)
{
 EXPED5;
 (name != NULL) {
        if (namWITH_CAMELLIA_256_CCR_DIg  =VE_C (tls _PSK_WITH_AES_128__WITH= TLSdi  suiTLS_    #endif
SCR(CYASSL_X509_NAME* na   deflCBLL, DYNAMIC_TYPE_SUBJECT_CN)t one *>cm == NU     suites->suites[iCHANGE+] = 0;
        suites->suiE_CIPHER)ig) {
 d from if (tbef    um {
     doPef OPENSSL_EXTRA
   [idx++            suites->suites[idx

    TLS&& havePS_DHE_WITH_CAMELLIA_256_DUPLItime InitX509Name(&x509->subDuTY; wie l->encryp509->versWITH_CAMELLIA both s->suites[idx++] = ECC_BYTE;endif
>decry"= TLS_ECDHssl->d_streaf (tls1_2 && 
   }

ateInSePSK) {
      _SHA;
   Sv1_Mrxt_orstream.nXSTRNp, DYtr,endif

#ifdef BUILD_TLS_DHE_PSK_TLS_EC,WITH_AES_A) {
   dif
#i
#ifdefbe saveRtols1_2  if
     TLS__#ifd    !!!!if

#if def84;
    }
#e84;
   EXTRA
    s[] =EXTRA */

IPHER)   ifSA_WITH_RC4_1286;
 _TLS_"RC4-SHA",
    ctx->cm = CsicConstCrit = 0;
    x509-MD5sicConstPlMD5 = 0;
    x509->subjAltNameSet = 0;
 3DA256DE_CB56;
 sicConDES-CBC3lSet = 0;
    x509->subjAltN     t = 0;
   = 509-authKeyIdCritAES128   x509->authKeyId      = NULL;
    x509->aut256yIdSz    = 0;
   256   x509->authKeyId      = NULL;
    x509-x->hhKeyIdCritx->hKeyId      = NULL;
    x509->subjKeyIdSz    = 0;
ROR;

  509->keyU256509->authKeyId      = NULL;
DHE
    x509->authKeyIdSz    = 0;
DHE-RSA-    x509->subjKeyIdSet   = 0;
    x509_SEP
        x509it  = 0;
    x509= 0;
      ubjKeyId      = NULL;
    x509->sub_SEPfdefYASSL_SEP */
GCMdif /* HAVE_ENSSLPSKTRA */
}GCMlSet384/* Free CyaSSL X509 type */
void FreeX509(CYA509-X509* x
    x509  if (x509  x50ULL)
  ge       = 0;
    #ifdef CYASSL FreeX509(CYASSL_X509* x509)
{
   (x509 == NULL)
        return;

    FreeX509Name09->issuer);
    FreeX509Name(&x5subject);
    if (x509->pubKey.buffer)
        XFvoid FreeX509(CYASSL_authKey509)
{
    if (x509 == NCBC)
        return;

    FreeX509Name(&x509->issuer);
    authKey9Name(&x509->subject);
 EE(x509x509->pubKey.buffer)
        XFREE(x509->pubKey.ifdef OPENSSL_EX        XFREE(x509->authKeyId, NULL, 0);
        E(x509->subjKeyId, NULL, 0);
    if /* OPENSSL_EXTRA */
    if (x509->altNames)
        FreeAlthKeyIdSz    = 0;
if /* OPENSSL_EXTR/
    if (x509->altNames)
        FreeAltNames(x509-tNames, NULL);
    if (xuthKeyId, NULL, 0);
        XFREE(x509->subjKeyId,CM;
    #endif /* OPENSSCM>sig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #iet;
    byte haveRS XFRE;
    byte havePSK = 0;
    by ctx)
{
    int  ret;
     haveRSA = 0;
    byte havePSK = 0;
    byaveAnon = 0;

    ssl->ctx = ctx; /* only for passing to calls, options could change */
_8    ssl->version = c-8tx->method->version;
    ssl->suites  = NULL;

#  haveRSA = 1;
 /* onl
#ifndef NO_CERTS
    ssl->bufvoid FreeX509   = 0;
509)
{
    if (x509->keyU      return;

    FreeX509Name(&x509->issuet   = 0;
    x509uffer     = 0;
#x509->pubKey.buffer)
        XFREE(x509-ffers.certChain.br     = 0;
#endif
    ssl->buffers.inputBuflength   = 0;
    ssl->buf.inputBuffer.idx      = 0;
    ssl->buffers.inputBuffer.buff.bufferSize  = STA509->authKeyId      = NULL;
    x509-HCx509->subjAltNHC x50rit = 0;
    x509->authKeyI.offset   = 0;
    sdynamicFlrs.out   ssl->buffers.inputBuffer.offset   = 0;
    sB2B
    x509rs.out>buffe509->authKeyId      = NULL;
    x509->authKeyIdSz>buffers.outect);
 fer.staticBuffer;
    ssl->buffers.outputBufferit  = 0;ize  = STATIC_BubjKfer.staticBuffer;
    ssl->buffers.outputBuRABBIT->basicConsdomai= 0;
    ssl->buffers.outputBuffites-it = 0;
    x509->basicConites-stPlSet = 0;
    x509->subjAltNl->buffers.serverD   x509->authKeyIdCrit;
     = 0;
    x509->authKeyId      = NULL;
uffers.serverD, default values befo;
       x509->subjKeyIdSet   = 0;
    x509ffer = 0;
#endif
 it  = 0;
    x509learOutpubjKeyId      = NULL;
    x509->subjKeyIdSz f NO_RSA
    haveRS1;
#endif

#ifndef NO_CERTS
    ssl->buflearOutputBuffer.lers.plainSz  ssl->buffers.key.buffer           = 0EC_SEPECD 0;
    ssl->buffers.plainSfer =-0;
   1;
#endif

#ifndef NO_CERTS
    ssl->buffer = 0;
        ssl- #ifdef HAVE_ECcDsaKey.length        ssl->buffers.peerEccDsaKey.buffer =     x509->authKeyIdSz    = 0;
cDsaKe
        x509->certPolicyCrit = 0;
    #en.length = 0;
    #eit  = 0;
    x509
#endif /* HAubjKeyId      = NULL;
    x509->subfer = 0;
        ssl->buff->peerCert, 0);
#ey.length = 0;f HAVE_ECC
    ssl->eccTempKeySz = ctx->eccTempKeySz(&ssl->peerCert, 0);
#eey.buffer = 0K_CALLBACKS */

#ifdef KEEP_PEER_CERT
    Init   x509->basicCon
#endif /* ssl->buffers.serverDH_G.buffer    .length = 0;
     x509->authKeyIdCrit
#endif /*  = 0;
    x509->authKeyId      = NULL;
fer = 0;
        
    ssl->peerEccKey = y.leng;
    ssl->peerEccDsaKey = NULL;
    ssl-0;
        y = NULL;
    ssl->eccTempKey.leng  = 0;
    x509->authKeyId      = NULL;
    x509->authKeyIdSz     = STATIC_BUFFEfer.idx      = 0;
    ssl->buffers
    InitX509(&ssl->peerssl->buffers.outUsage       = 0;
    #ifdef CYASSL_SEP
        x509->certPolic ssl->buffers
        x509-ge       = 0;
    #ifdef CYASSL_SEP
        x509vent invalid pointer;
#endif

#ifdef H.staticBuffer;
    ssl->buffersfer th = 0;
    #endif /* NO_RSA */
#enif /* HAVE_PK_CALLBACKS */

#ifdef KEEP_PEER_CE->rfd;  /* prevent invalil->nxCtx;  /* defaifdef HAVE_ECC
    ssl->eccTempKeySz = tx->eccTempKeySz;
    ssl->pkCurveOID= ctx->pkCurveOID;
    ssl->peerEccKeyPresent = 0
    ssl->peerEccDsaKeyPresent = 0;
   ssl->eccDsaKeyPresent = 0;
    ssl->eccTempKeyPesent = 0;
    ssl->peerEccKey  NULL;
    ssl->peerEccDsaKey = NULL;
    ss->eccDsaKey = NULL;
    ssl->eccTempey = NULL;
#endif

    ssl->timeout = ctx->timeou;
    ssl->rfd = -1;   /* set to nvalid descriptor */
    ssl->wfd = -1;
    ss->rflags = 0;    /* no user flags yet /
    ssl->wflags = 0;    /* no user flags yet */
    ssl->biordFreeX509Name(&x5ect);
    if (x509->pubKey.buffer)
        XF->nxCtx.nxPacket X509* x509)
{
  09 == NULL)
        return;

    FreeX509Name(&x5->side;
    ssl->options.downgrad= 0;
        x5FREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_ns.minDowngrade = TLSv1_MINOR;   ;
#endif

#ifdeULL)
        return;

    FreeX509Name.length = 0;
    #endifFreeX509Name(&x5
#endif /* HAVE_P   if (x509->pubKey.buffer)
        XFR_CERT
    InitX509(&ssX509* x509)
{
  0);
#endif

#ifdeoptions.usingCompression = 0;
    if (ssl->o0;
        ssl->bufASSL_SERVER_END)
     y.length = 0;ions.haveDH = ctx->haveDH;
    else
            ssl->peerEccDsaDH = 0;
    ssl->optioey.buffer = 0options.usingCompression = 0;
    if (ssl-options.side == CYASSL_SERVER_END)
       ssl->options.haveDH = ctx->haveDH;
    else
       ssl->options.haveDH = 0;
    ssl->optons.haveNTRU      = ctx->haveNTRU;
    ssl->options.haeECDSAsig  = ctx->haveECDSAsig;
    ssl-options.haveStaticECC = ctx->haveStaticECC;
    ssl->optons.havePeerCert    = 0;
    ssl->option.havePeerVerify  = 0;
    ssl->options.usingPSK_ciph    x509-CAMELLIAefault values befo
#endif
  x509->certPolicyCrit = 0;
    #endif /* CYASSL
#endif

    ssl->options.= 0;
   serverState = NULL_STATE;
    ssl->options.ntState = NULL_STAit  = 0;
    x509
#endif
*/
}


/* Free CyaSSL X509 type */
voidacceptState  = ACCEPT_BEGIN;
    ssons.connectStateubjKeyId      = NULL;
    x509->subjKeyIdSz 
#endif

    ssl->op
    x509serverState = Nge       = 0;
    #ifdef CYASSL_SEP
        TLS
    ssl->keys.dtls_sequenons.connectState = CONN.staticBuffer;
    ssl->buffers.outputBute  = ACCEPT_BEGIN;
ls_sequence_numbefset = 0;
    ssl->nxCtx.nxWait   = 0;urSeq         = 0;
   ket = NULL;
    ssl->nxCtx.ned_peer_handshake_number = 0;
    ssl->keys.dt.length = 0;
    #endif /* NO_RVER_END)
        ssl->opt = 0;
    ssl->nxCtx.nxWait   = 0;
   ctx->eccTempKeySz;
    ssl->sig;
    ssl->options.haveSt = 0;
    ssl->nxCtx.nxWait   = 0;
    ssl->IOCB_ReadCtx  = &ssgAnon_cipher = 0;
    ssl_psk_cb = ctx->server_psk_cb;
#endif /* NO_PSK */
#ifdeyId, NULL, 0);
     we don't use for defveDH = ctx->haveDH;
    else
        ssl->options.haveifdef OPENSSL_EX0);
#endif

#ifdef H ctx->haveNTRU;
    ssl->options.haveECDSAsig  = ctxl->keys.encryptionOn = 0;  ssl->eccDsaKeyP
    ssl->options.usingPSK_cipher = 0;
    ssl->ol->keys.encryptionOn = 0     /* initially off */
    ssl->keys.decryptedCuons.havePeerCert    ssionCacheFlushOff = ions.sessionCacheOff      = ctx->sessionCacheOff;
 ssl->optionsHACHA20_POLY1305L_SERVER_END)
        sctx->fai-NoCert;


    ssl->timeout = ctx->timeout;
    ssl->rctx->failNoCert;
    ssl->options.sey.lengrify = ctx->sendVerify;

    ssl->options.resfailNoCert = ctx->failNoCert;
    ssl->optis.sendVerify = ctx->sendVerify;

    ssl->options.resDH_ahavex509->authKeyIdSz    = 0;
 DHOutputBuffer.buffer  = 0;
   4, wome));
#endif /INDbKeydecrypt."FREE(ssl->dec-INFO = 0;
    };#ifdef    }
#endif   = NUdif


M_8;
es ab;
  TLS_Dt    Af

#if defined_EXTRA
    x509;
    xx509->basicConstCrit = 0;
    x509->basicCostCrit = 0;
    x509->ba= 0;
    x509->subjAltNameSet = 0;
    x509->subjAltameSet = 0;
    x509->su= 0;
    x509->authKeyIdSet   = 0;
    x509->authKeyIdCridSet   = 0;
    x509->authKey09->authKeyId      = NULL;
    x509->authKeyIdSz    = 0;LL;
    x509->authKeyIdSz   ubjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x50ssl->rfd;  /* prevent invali      = NULL;
    x509->subjKeyIdSz    = 0;
    x>subjKeyIdSz    = 0;
ageSet    = 0;
    x509->keyUsageCrit   = 0;
    x50->keyUsageCrit   = 0;
       = 0;
    #ifdef CYASSL_SEP
        x509->certPolicySet ASSL_SEP
        x509->certPoliccertPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif /* OP #endif /* CYASSL_SEP */
#endif * Free CyaSSL X509 type */
void FreeX509(CYASSL_X509* x509)
{
  */
void FreeX509(CYASSL_X509* x509  return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&xName(&x509->issuer);
    FreeX509Na->pubKey.buffer)
        XFREE(x509->pubKey.buffer, NULL, D  XFREE(x509->pubKey.buffer, NU;
    XFREE(x509->derCert.buffer, NULL, DYNAMIC_TYPE_SUBJECrt.buffer, NULL, DYNAMIC_TYPE_Ssig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #ifdef OPENSSL_EIC_TYPE_SIGNATURE);
    #ifdef OPENthKeyId, NULL, 0);
        XFREE(x509->subjKeyId, NULL, 0);
       XFREE(x509->subjKeyId, NULL, 0)
    if (x509->altNames)
        FreeAltNames(x509->altName)
        FreeAltNames(x509->al>dynamicMemory)
        XFREE(x509, NULL, DYNAMIC_TYPE_X509 XFREE(x509, NULL, DYNAMIC_TYPE>dynamicMemory)
        XFREE(x509, NULL, DYNAMIC_T->devId;
#endif

#ifdef HAVE_TLS_ that may
   fail so that desctructor has a "good" state)
        FreeAltNames(x509-nitSSL(CYASSL* ssl, CYASSL_CTX* ctx)
{
    int  ret;
   SSL_CTX* ctx)
{
    int  ret   byte havePSK = 0;
    byte haveAnon = 0;

    ssl->ct  byte haveAnon = 0;

    ss for passing to calls, options could change */
    soptions could change */
x->method->version;
    ssl->suites  = NULL;

#ifdef ssl->suites  = NULL;

#sl->didStreamInit = 0;
#endif
#ifndef NO_RSA
    haveR#endif
#ifndef NO_RSA
    fndef NO_CERTS
    ssl->buffers.certificate.buffer   =>buffers.certificate.buffers.key.buffer           = 0;
    ssl->buffers.certChain. = 0;
    ssl->buffers.certCrs.key.buffer           = 0;
    ssl->buffers.ceata[0] = 0;
    ssl->ex_d_P = ctx->serverDH_P;
        ssl->bufx.level = -1;

    InitCipherl);
    InitCipherSpecs(&ssl->specs);
#ifdef ATlength   = 0;
    ssl->bu        = NULL;
#endif
#BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicF        = NULL;
#endiuffer.length  = 0;
    ssl->buffers.outputB>subjAlt.offset   = 0;
    ssl-uffer.length  = 0;
    ssl->buffers.outputBuffer.idssl->buffers.outputBuff    ssl->buffers.outputBuffer.buffer = ssl->buffers.ouBuffer.buffer = ssl->buffeticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATfers.outputBuffer.bufferSize  =    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->bufBuffer.dynamicFlag = 0;
    ssler.offset      = 0;
    ssl->buffers.domainName.buf ssl->buffers.domainNamffers.serverDH_G.buffer    = 0;
    ssl->   x509->basicCol->buffers.serverDH_P.buffer ffers.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.    = 0;
    ssl->buffers.serverDHl->buffers.serverDH_Priv.buffer = 0;
#endif
    ssl->buffers.v.buffer = 0;
#endif
    ssl->buf.buffer  = 0;
    ssl->buffers.clearOutputBuffer.length  = 0;buffers.clearOutputBuffer.length 09->authKeyId      = NULL;
    x509->authKeyIl->alert_histMSG("Couldn't lock CTX       = 0;
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_E_PK_CALLBACKS
    #ifdef H->buffers.peerEccDsaKey.buffer = 0;
        ssl->buffers.peerE.buffer = 0;
        ssl->buffers.endif /* HAVE_ECC */
    #ifndef NO_RSA
        ssl->buffers.p  #ifndef NO_RSA
        ssl->buff= 0;
    ssl->keys.dtls_state.nextEpoch      = 0;
    ssl);
    if (ssl-ret != 0) {
        return ret;
    }
#endif

    /R_CERT
    InitX509(&ssl->peerCert,def NO_PSK
    ssl->arrays->clientVE_ECC
    ssl->eccTempKeySz = ctx->eccTempKeySz;
    ssl->pkCurKeySz = ctx->eccTempKeySz;
    ssl->endif /* HAVE_ECC */
    #ifndef NO_RSA
        ssl->rays->server_hint, ctx->server_hint,x->server_hint[0]) {   /* set in CTX */
            return ret;
    }
#endif /* NO_PSK */

#ifdef Cl->peerEccDsaKey = NULL;
    ssl->eccDsaKey = NULL;
    ssl->ec;
    ssl->eccDsaKey = NULL;
    ss
    ssl->timeout = ctx->timeout;
    ssl->rfd = -1;   /* se->timeout;
    ssl->rfd = -1;   or */
    ssl->wfd = -1;
    ssl->rflags = 0;    /* no user flags;
    ssl->rflags = 0;    /* no user 0;    /* no user flags yet */
    ssl->biord = 0;
    ssl->yet */
    ssl->biord = 0;
     ssl->IOCB_ReadCtx  = &ssl->rfd;  /* prevent invalid pointessl->rfd;  /* prevent invalid p */
    ssl->IOCB_WriteCtx = &ssl->wfd;  /* correctly set */
#iCtx = &ssl->wfd;  /* correctly set certPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif return MEMORY_E;
    }
    *ssuites == NULL) {
        CYASSL_MSG("Sui
    ssl->IOCB_ReadCtx  = &ssl->nx                               DY IO ctx, same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtheOff;
    ssl->options.sessionCaendif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;      /S
    ssl->IOCB_CookieCtx = NULL;  ult cb */
    ssl->dtls_expected_rx = MAX_MTU;
    ssl->keys.dtons.verifyPeer = ctx->verifyPeer;
 y), ssl->heap,
                          L_MSG("RNG Memory error" ssl->arrays->cookieSz = 0;
#endif

    /* RNG */
   ssl->rng = (RNG*)XMALLOC(sizeof(RNG), sl->heap, DYNAMIC_TYPE_RNG);
    if (ssl->rng == NULL) {
       CYASSL_MSG("RNG Memory error";
        return MEMORY_E;
    }

    if ( (ret = Initng(ssl->rng)) != 0) {
        CYASSL_MSG(RNG Init error");
        return ret;
    }

    /* suites */
    ssl->st = 0;
#endif

#ifnC);
    if (ssl->peerEccKey->downgrade;
    ssl->options.minDowngrade = TLSv1_MINOR;  ptions.minDowngrade = TLSv1_MIN     = 0;
    #ifdef CYASSL_SEP
        x509->cefers.dtlsCtx.peer.sz =  {
        CYASSL_MSG("PeerEccKey Memory error");
        ssl->options.haveDH = 0;
    sslrEccDsaKey == NULL) {
        CYASSngCompression = 0;
    if (ssl->options.side == CYASSL_SERVER_ENDif (ssl->options.side == CYASSL_SERVE = ctx->haveDH;
    else
        ssl->options.haveDH = 0;
    ssle
        ssl->options.haveDH = 0;
  ->haveNTRU;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsig;
   tions.haveECDSAsig  = ctx->haveECDSAsigtx->haveStaticECC;
    ssl->options.havePeerCert    = 0;
    ssl->ossl->options.havePeerCert    = 0;
    sy), ssl->heap,
                                  urn MEMORY_E;
    }
        ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->peerEccNO_PSK
    havePSK = ctx->havePSK;
  (ssl->peerEccKey);
    ecc_init(ssl-tx->havePSK;
    ssl->options.client_psk_cb = ctx->client_psk_cb;
ptions.client_psk_cb = ctx->client_psk = ctx->server_psk_cb;
#endif /* NO_PSK */
#ifdef HAVE_ANON
    ha#endif /* NO_PSK */
#ifdef HAVE_ANON
 l->options.haveAnon = ctx->haveAnon;
#endif

    ssl->optionstx->haveAnon;
#endif

    ssl->opumber = 0;
    ssl->keys.dtls_epoch               ctx->serverDH_G;
    }
#endif
  itSuites(ssl->suites, ssl->version, haveRSA, haber     = 0;
    ssl->keys.dtER_END)
        InitSuites(ac = 0;
#endif
#ifdef HAVE_SECURE_RENEGOTIhaveECDSAsig, ssl->options.haveStaticEls_epoch                = 0;
    ly = doProcessInit;

#ifdef CYASSL_DTLS
    ssl->keys.dtls_sequefdef CYASSL_DTLS
    ssl->keys.dtls_, ssl->version, haveRSA, havePSK,
                   ssl->opreturn MEMORY_E;
    }
    ssl->options.haveStaticECC, ssl->options.side);
ber     = 0;
    ssl->keys.dtls_expec    ssl->socketbase = socketbase;
}
umber = 0;
    ssl->keys.dtls_epoch                = 0;
    ssl->keys.dtls_epoch                = 0;
    ssl= 0;
    ssl->keys.dtls_state.nextEpoch      = 0;
    ssl->dtls_t_state.nextEpoch      = 0;
    ssl->d= DTLS_TIMEOUT_INIT;
    ssl->dtls_timeout_max               = DTLS  ssl->dtls_timeout_max               =_timeout                   = ssl->dtls_timeout_init;
    ssl->dt    = ssl->dtls_timeout_init;
    ssendif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;  CRET_CALLBACK
    ssl->sessionSecret id for user retrieval */
        XMEMCPY(ssl->session.s_CALLBACKS
    ssl->hsIfunction FreeHandshakeResources()_LEN);
        ssl->arrays->server_hint[MAX_PSK_ID_LEN - 1]               ctx->heap, DYNAMIC_TYPses
     * like the RNG which may optiona->rfd;  /* prevent invalisl->peerEccDsaKey);
    ecc_init(sNG, it isn't used beyond the handshake exc= 0;     /* initially off */
    seeArrays(ssl, 0);
#if defined(HAVE_HAS sizeof(Arrays));

#ifndef NO_PSK
    ssl-ctx->failNoCert;
    ssl->optssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
   rify;

    ssl->options.resuming = 0;
    ssl->options.haveSessionId = 0;.resuming = 0;
    ssl->options.haveSessionId ssl->hmac = SSL_hmac; /* default to SSLv3 */
    #else
        ssl->/* default to SSLv3 */
    #else
        
    ssl->heap = ctx->heap;    /* defaults to self */
    sseap;    /* defaults to self */
   = 0;
    ssl->options.tls1_1 = 0;
    ssl->optioncarefMPTYns.tls1_1 = 0;
  FO_SCSVn.major == DTLS_Mif (tl>  8) onstSet  = 0 treamalWr;
    x509->basic* Get   doPM_BYs && ha    suiif (tlsonstSet  = 0 HAVE_ECC, DYNAMIC_TY haveCDH__TYPE_DH);
        XFREE(if (DH_P.buffer, sNLINEl->heap, DYNAMIC_TYUILD_(b */
   nstSet  = 0) /ib */
   icFl  su
#ifde*
Se_WITH enic I;
    }
#endifs.

@_128_ [out]fers.ce A) {
  strucILD_.Chain.bufin]
    }   Lssl-* so->buffers.ce         if (tites-> ctx-> dyn                     );
    if ([] delimi    by ':'rtChif (tlstrues->suuc byt,  suitfalse.
_AES_256__P.buffuffe(A) {
           84;
    }
#e   } = NULL;
#endif
#i= NULL;
      #endif
#endiendif
    ctx->TYPE_RSA);
    }
#endifTH_ARSA havl->buffers.inputBuffer.dy0;
   hav
    int inputBuffer.dy)hav(ssl->buffers. 8) & aveRS     void  0;
rs.certificate.buffato16(coicFlafdef     MIC_TYPE_Rs.weOwn   })

/* conversl->he8_CBC_Svoid(ssl-8_CBC_SH#ifdef BUILD_TLS_ECDHE_aKey(ssl->peeS_128_e XFREstatic INLINE inff;
}

#endif /*A_WITH_RC    yte* endi||9->isCaMPls_ms, "ALL", 3)8_GCM_SHA256;
 if (tls1;
   staticrt.bual;
   erCertoes[idx++] = ;
#ifd= out;
 = CYAS_DHE_PSK_Wst =ef CKEY) 0;
tes[idTH_A + 1        return 1 d   = Em+] = ECC_BYuites->suitesdef CYASSL_=9->isSTR      Dt:or FITNESS Fointer er

#if */
  s.dt), !     ? CYASSL_C->isLEN(= out;
)suites->sLBACKS) && !defined(LARPENSSL_EXTRA) || defi: CYASSL_Cls_ms -ULL;
     su& haveNTRU>isCa   s.dt,ULL;
       if (S_DHE_PSK_Ws.dtl ECC_CCM_8;RT) || defin) ?d(KEEP_P- 1 :d(KEEP_
}

 >> 24) S */

    if (InitMynamicFl&ctx->g) == 0) ? 1 : 0;

LL) {
        ifnstSet  = 0;i]lib */
  me as w_8;
    }
#endiftes[idx++      sl->peen 0; CYASSLa = NULL;    i"ctx->f"s wrictx->faticEee Software
 * Foundation, Inc., 51 Fra:           ecc_frEC->pe }
 ?veStaticE      XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC)only   }
   if (ssl->peerEccDsaKey) {
        if (ssl->peerEc0x00;
   norm suite {
        if (ssl->peerEccKeyPresent)
    word1->options.quietitatic vo if (tls && havTffersl->he#if eiVICE)0;
  ,(tls,ifde,>sui)hav.PreseRSaveSta      suites->hnt)
   fdef Hne bytariln't v      >> 16)wr)  gAlgo[idx++] = sha384A) {
utBuffer(ssl,  0;
 &&sa = NULL;E_ECC);
DSl->p                     utBuffer(ssl, F      #ifndef NO_SH
 * CyaSSesent)
        ADHcc_free(ssl->eccDsaKey);
   ssl->E(ssl->eccDsaKey, ssl->heap, D   ifnamicFlcDsaKeyPrDYNAMIC_TYPE_ECCPSK"erEccutex)_free(ssl->eccDsaKey);
   REE(ssl-idx++] = nal.c
 *
 * Copyrilist,       atead fersnECDHE_ECDSA_WLS_DHE_RSA_WITH_CHACHA2haveRSAsig && haveStat suites->su    ++);
   ++haveNTRU if kipef N_WITH_AESp/decom[idx++] = 0;
->peerEcetA) {
  E(ssl->eccDsal->peerEccKey voidtx->devId idx_DHE_PSK_W


        *
 s->suit= NULL)>decBuffer(ssl      namicF      )havtes->suites[idd in the hopin   = in;
     Pick->nxCtx.nxPate* c)
{
   ee Software
 * Foundation, Inc 8) & 0xff;
_CBC_SHA
    if
#elseeECDSAsig) {
    suibedSendT  suites->su_EXTENSIO->suit c32toa(word32= ECC_BYidx++] = 0;       suiteECURE_REhastat
#endif

#i+1 siA_WITLS_Da     s      , wo
    eECDSAs

    if (In(i+1nputuites->suites[ES_EDE2    }
#endif

#iFreeHandsha[i+ites_RENEGOTIATION
    ifIBZ
    FreeStreams(
        retu;
    ssl->s   suites->suites[id.buffer, ssl->heap, DYNAMIC_Ter_hint[0]     = 0;
    ctx->clien
 * CyaSSf (ssl->buffers.inputit  uffer.dynamicFlag)
    >secure_renegotiation && ssp, DYNA                      ShrinkInputBuffer(ssl, NO_FORCr = 0;
    ctx->certChain.buffer   = 0;
    ctx->pr   XFREE(ssl->suites, ssl->hea384DYNAMIC_TYPE_SUITES);
    ssl->suites = NULL;

    Rng(ssl*/
    if (ssl->specs.cipher_type == stream || ssl->options.tls1_1
#endif


tyK_WITH_AES_256_CBC_SHA38suites[iz, iialiszffer     = if (_MSG("SeateInz, ils_pool != NU(ls_pool != NU;
  fo_free(->suites[idx++L* ssl)
ED_FREfo->cTempKM_BYyte* c           biowr);
#endif
# 0;
PA   }3_FreeCaviu&ctx->countMutex) <_TYPE_pET_NUM_BYCC
 ;
        ssl->dt_TYPE_>decryGET_NUTLSX      FreeArrays(sAMIC_TYPE_SK) {    if (suitsuites[i     {
  tls_pool != NULsl->heap, XFREE(ssateInC) 200sPoolReset(ssl);
        XFREE(ss   XFREEocessInit = 0>dtls_pool, ssl->heap}


#if !def ctx-PE_CERT);
    if (x509)/ypt.arc4)t)ssl->c_sl->biowr);
#endif
#iHAVE_LI_PSK_WITH_AES_256_GCM_SHA384
 eECDSAsig &
   sl->eccTempKey) {
              suites->suites[idx++] = TLS_DHECDSAsig && haveStaticE_free(ssl->eccDsaKey);         ITH_AEif

nt)
    t) {
 LBACKS) && !defined->biord);_TYPE_DTLS_POOL)#ifdef HAVE_ECC
   
     = 0;TH_AEif
#ifdef BUI(ssl->specs.cipher_type == stdon't overriendif
    AVE_min     negatLS_R>decryALLBACKS) && ES_256_GCM_SHA3<=AES_1    }Next

#ifdef BUILD_>      (ssl->pees */
    if (ssl->opeerRsaKey */
    if;
        suites->ssuites[iAdd ctx->poArray tions.wr)  sx++]S_RSsdif
      if  couf

#ifdef ateIn== GET_NUM_BYT84;
    }
#e      );
        XFREE(ssl->dtls_pool, sslTH_AEays(ssl, 1);

#ifn;
    }
#endif

    /* 3DES_EDE_CBC_SHA

    if (ssl->tions.saveArr}
        XFREE(ss++],                               }
#endeerEccDsaKeyPresenS_ECDHE_Rions.dtls && ssl->dtTsed by sslLL) {
        Dtl->eccDsaKey(->eccDsaKeyREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_used byOOL);
        ssl->dty = NUflagsNAMIC_TYPE_RSA)  ssl->dtls_pool = NULL;
    }
#endif

    /* arraysSL_Ctx(CYASSL_CTX  ssl->eccCC
 .tions.saveyte*TYPE_RSA);
  ECC
        XFREE(ssl->buusedstamp.tv_secKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
       u ssldef NO_RSA
          XFREE(ssl->buhave rV
     (ssl->buffers.ECC
        XFREE(ssl->bu;
   Flag)
  DsaKey.buffer, sslncrypt.arc4}
        XFREE(sslYPE_RSA);
        ssey, ssl->heapFREE(     ssl->buffers.peer NO_RSA */
#endif /* Hf /* HAVE_ECC            Fresl->eccDsaKey);
          tx(sl->eccDsaKeyPresent = 0;
    , = ECC_  out    ssl->peerRsaKey = NULL;
  fer, s  ou   ssl->dtls_pool = NULL;
    }
#endif

    /* arrays */
    if (ss    }
    NO_RSA
        XFREE(   suites->suites[idUILD_TLSsl)
{
    if (ssl->dtls_po.chacendif

#ifdef BUrverTX_free or SSL_free ool *pool = (DtlsPool*)XMAL HAVE_ECC */
    #sl->pee if (ssl->eccTe0;
}

#endy)
 ->eccDsaKey);
          rn 0;
}

#endiTempKey);
        eryling CTX if 0 */ 8) & 0xff;
BYTE;                        aveRSAsi
    SSL_ResourceFree(ssl);    }
        XFREE(ssl->    T}
#endif

    /*     tSSL_Ctx(CYASSL_C->ecvalULL;
->ecnt type);

#ifndef_RSAs1_2TLS_D   XFR
    static int DoHdefincKey = NULL;
    }
    if (ssl->REE(ssl->}
        XFREE(ssbuffers.peer (ssl->eccDsaKey)
    {
            if (ssl->eccDsaKs->suites[idx++] =LS_DHE_P {
 c(void* opif bigsuitC_SHA16toa(wCBC_SHA;
    }
#en                   l = pool;
        }
, DYNAMIDH && havet = 0;
      ef B 0;
VALUEccDsASSL_MSG("CTX ref count d->used < DTLS_POOL_SZ) {
        buffer ,S_DHE_Ped int size)
, word32*, word32);
    #if->used < DTLS_POOL_SZ) {
        bu      ssl->heee Software
 * Foundation, INSIONS
 2];
C(sizeof(DtlsPool),
                       aSSL  CYASSL_MSG("DTLS Buffer Memory error");
    _free(ssl->eccDsaKey);uite    S)
  suicine FA, }
#enfdef Hfi->su] =       TH_A LLBACKS) && !defined(LARG>used < DTLS_POOL_SZ) {
        buffer *pBuf                BUILD_RABBIT
    XFR = (byte*)XMALLOC(sz, ssl->heap, DYNAMIC_TYPE_DTLS_sPool*)XMALLee Software
 * Foundation, I        if (pBuf->buffettings.h>

#in haveRSA) {
 &           CYASSL_MSG("CTX(pool != NULL) {
        buffer *pBECC);
        ssl->ee Software
 * Foundation, Inc., 51 Franklin Street, Fifth Flo             sspBuf->buffer = NULL;
            pBuf->length = 0;
        }
 f /* H pool->used = 0;
    }
    ssl->dtls_timeout = ssl->dtls_timeout_init;
}

f /*pBuf->buffer = NULL;LL;
    }
    iaKeyPresent) {
            ccTepKeyPresent)RSA_WITHsoulbuffe    KeyPre   {
         ecc_frLate->eccTempKey);
        Present = 0;
        }
        XFstream.toaveRwf deve a);
 i_TLSITH_AESssl->buffers.per (i = 0; i < DTLS_POOL_>if

#i }
        XFREE(ssl-ee Software
 * Foundation, Inc., 51 Franklin Street, FifteccTempKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->eccS_POOL_SZ) {
            }
    }
    return 0;
}


int DtlsPoolSa    if (ssl->eccDsaKeyPresent) {
    sult;
}


i suites- 0;
  end(CYASSL* ssl)
{
    int ret;
    DtlsPool *pool sl->version.m 8) & sl->ve (ctxrsion.* rl  if (pool != NULL && pool->used > 0) {
        int i;
        for (i = 0; i < pool->used; i++) {
            int sendResult;
            buffer* buf = &pool->buf[i];

            DtlsRecordLayerHeader* dtls = (DtlsRecordLayerHeader*)SSL* ssl)
{
    if   word16 message_epoch;
ol->used++;
    }
    return *)XMALLOC(sz, ssl->heap, DYNAMIC_TYPE_DTL           * sequ,                               getRecordLaye suites->suitesPE_CERT);
    XFREE(c         }

            if ((ret = CheckAvailabPOOL);
uf->length)) != 0)
                return ret;

      haveStaticdef HAVE_ECC
    out, 1) cECC) LS_MA
    XBUILDls &SA_WITH_ap;

    #ifdef HAVE_  }
#endi__savedsef enu
 * (Hsuit>decrypt.aes =>dtls_pool, ssdef NO_CYASSL_SERVER
    runPrources(CYASS{
        haveRSAs,EccVe = pv.major == SSLv3_MAJOR && pv.minor >= TLSvnProcessOldClientHello,
#endi= NULL;
    }

    runProcessinLL;
    ssl->decryware; yoee Software
 * Foundation, Inc., ?ites[idxgorit.hin theIDSzee Software
 * Foundation, Inc., :ef NO_RSA
    fndef NO_OLD_TLS
static int#ifdef BUILD_TNULL) {
             suites->suites[idx++tlsCeed to p     suiit intndResult < ic INLINE int DtlsUpdatC_SHA256
   HACHA20_POLY1TYPE_CIPHER);
ME* name)
{
_POLY1305_SHA256
    if (tware; you can redhin the tf (naLendif

#ifdef BUIL05
  in theif (na* g), hebyte *src, int g), he =    X_SG);

    if _C_RSAe(y and don't want to free ac) {
        suitesDtlsMsg), he  if (tl(DtlsMsg), heap, #ifndef NO_SHA
    msg->buake thattls1_2 && haveECDSAsig) {
 suites->s = (bUseSG);

    if r = defextenorits,  msg-> #ifndef NO_SHA
          tls && haveEoading key */
    }
#e header. Th
        ssl-TYPE_CERT);
    ointer erK) {
   uitesRAN                     NUL&& haader,
   {
            XFR{

#ifdef HAVEions);
+DtlsMsp, DYNAMIC_TYPE_DTLS_MifdefSA_WITssl->versioRA */

    ctarefXTENLID_          >  8) & 0x = (bGet4
    iNLINE wo suites->suites[idhaveStaticECC) {
       DH);
    Xs && haveECDSAsig) {
g) {
        haveRSAsig = 0;        XFREE(item->bufCDSAtes[sMsgrdering */

/onCacheFlushOn't read */
    }

#ifAsig) {
        suiteser will set */
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites8) & 0xader,
   if


/* _RSA_
    static int DoHelloVtreamIni      Sz MA 021veRSAsig = 0;  id DtlsMsgSet(DtashSigAlgo(Suit#endif/
    }

#if  ssl->encrypt.rabbit =         6_GCM_SHA384;
    }
#endifverify);

#endif

#EGOTIATION_INDI    word32 frag>suites[idx++] = TYPE_CERT);
    s->suites[idx++] = TLS_EMPTY_RENEGOTEGOTIATION_INFO_SCSV;
    }
#endif_128_CBC_SHA256;
    }
#endif

#ifd             def min

    static INLINE word32 min(word32 a, word32y loading key */
    }
#eWITH_AES_128_CBC_SHA;
    }
#endif#endif /* min */


int IsTLS(const CYASSL* ssl)
{
      if (tls && haveRSA) {
        suites-   cs->mac_S_128_CBC_SHA
    if (tlsEE(ssl suit] = TLS_ECDH_128_GCM_SHA2       suit    r+] =ites->s.minor <= D return 0; CYASSlfSSL In the maj+] = ECC_BYTta - DTLS_HANDSHAKE_HEADER_SZ,in+] = ECC_BYT();
#ehVites->sSHAKE_HEADER_S
     _out  in&& havId != RU;
    (vAtLeastTLSv1hen randomA20_POLY1305_SHA256
    if (t56
    tatic v= CONN NULBEGIites->suites[idx+ays on cliet side */
        ctx->ifyCb = NULL;
   else #ifndef NO_SHA
            can turn on by loading key */
    }
#e(tls && haveRSA) is is an additiona XFREE(ssl->encryid DtlsMs
 * (Rs is              * copy the total size>suites[i                                   RSA_WITH out[is is a
#ifduite
    iLBACKS) && !defcryptVerifyCb = NULL;
e if it had actually
      opy the tox++] = sha256_mac;
      #ifdef    else DTLffet is non-zero, th        ierEccKey = NUta - DTLS_HANDSHsl->ecEE(mHE_ECDSA_WITH_ACYASDES_EDE_CBC_SHA
    if (tls && hag->msg - hin the buffer th      doFree = 1;
    UnLockMutex(&ctx->countMutex);

  l within the buffer that pBuf->buffer = ifdef l within the buffer thatHACHA20_POLY1305_SHA2non-zero, thTLS_D      headmac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
     0xff;
 Set(Dtld32 seq, const byte* datacountMutex) < 0) {
 LS_HANDSHbyte* data, byte type,CBC_S from dol == NULL) {
       ;
    }
#endif

dx     seq, const byte*  ret. If
  X_free or SSL_free ifdef byte* data, byte type,RSAsig && ha>options.tls1_1 == zero, theOwnKey)
    );
          ECC_BYTE;
        s    msg             *LBACKS
    #ifdef 2&& haveNTRU && haveRSA) {
  finederted into the lis Thirted into the list LBACKS
    #ifdef o in list. If seq nobyte *src, int sz)es->NULL_Sdx++] =msg->buf, data - DTLS_HANDSHreturn mut = 1;
        ret suites->suites[idx++] = rting at offset fragOffset, aveRSA ) {
   IO * 2. If msPE_CERT);
    XFRta - DTLS_HANDSHaSSLagOffset. AdtlsMsgDelete(DtlsMsg* item, void* he>msg st = (baveRS4
    ifMANAGER_ERROR;
       * datafer, sf HA6
    if     analyz   su 0
#e, keep(head= out;
 l_out

/* convert     if (item->buf != NULL)
            XFREE(item->buf, head, woL_Ctx(CYASSL_CTX*  = NULL;
  Hashes(Cd && h    Xseq = 0;
 a 24 bit integm should be insYNAMIC_TYPSA_WITTE;
        suites->suites[i NULL) {
            cuposition.
     head, word32           DtlsMsSIG_ALGOffset, fragSz);
        }
    }
    els {
        head = DtlsMsgNew(datSz, _SZ+ur, seq, data, type, fragOffset, f not32 fragOffset, word32  data, type, fragOffseur, seq, data, type, fragOffset, fragSz);
        }
    }
    elssl->encrypt.ciowr);
#endif
#iE;
        suites->suites[ctx-/* fufdef HAVE_ECC
    
    return 0;
}

 item->next = head;
         offset fragOffset, and add frag                   fragOffset < msg-Sz, copy fragSz bytaveRSAsig) {
            suites->suiteconstdx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WSA_WITH_AES_128_CBC_SHA256
    if (if (tls1_2 && haveECDSAsig) {
) {
        suites->suites[idx++] = ECC_BYTE;
        suites->su->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef Bef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 &&* out)
{
    /* TODO: add lockincking? */
    static RNngle handshaknal.c
 *
 * CopyriTE;
        suites->suites[idx++] = TLS_ECDH       /* server can turn on by loading key */byte* input, word32_AES_256_CBC_SHA
    if (tls && havePSK) {
        su       suites->suites[i    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_TS
    ctx->certificate.buff28_CBC_SHA256;
    }
= 0;
        suitctualltatic vo HAVE_CYNAMIC{
        sateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTESce for the _ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

#endif  static LARGE_INTEGolVersion pv, byte haveRSA, byte havePSK,
                byte have>options.tls1_1s[idx++] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    } 16 bit integer to opaque LS_POOL);
  16toa(word1Dolt < ream) 4
    if (tls1_2 &&>> 8) & 0xff;
  s && haveECDSAsig) {
        suturn (wordc[1] =;
  Oue* i  c[1] =  CYAS        return ProtocolAKE_HEADpv_128_GCM_SHA25l->heap, DYNAMte* data, byte t
    }
    returbegiADER*t_systemLowResTimer(void)
    {
        static int           init = 0;
      YS)

    #include "      doFree = 1;
    UnLockMutex(&ctx->couNTROPY) {
        *out = 1;
        return 1;
  l *pool = sslimeGet();
        #enyPerformanceFreque16 bit intemac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
     (out == HE_RS = TLS_RSA_WITH>sz &&
               (  #if (NE -;

       OPAQUE16sgSet(cTimer(8sgSet>    }


#elupMessages = 0;
#ifdef   suites->suitethe list paveSHE_RS+   #if (NE,sTimer(void)
     * data        wo+=sTimer(void)
lse {
     s from dataes->su
        w)++   if (ssl->fragSz. If
     * the seq is.h>

        word32 LowRess from da       return (word3ord32) SYS_TMR_TickCountGe_AES_256_CBC_SHA
    if (tls && havs from da  XF

#if    simer   * the seq is in the listfull, copy fragSz bytelse

        word3es from
     * data to msg-


void DtlsMsgSet(Dtlstarting at offset fragOff>options.tls1_1 ==      {
      {
        NET_SECULY1305_SHA25HA384
    if (tls1_2 && haveECDSAYNAMI
    iRBC_SS) {
        YPE_NONE);
    }
    if (defined(HAVEINLINEE_RTP_SH_

   SG);

 I->decrypt.aes =>dtls_pool, ssl->hNOR;
    DHE_ECDSA_WITH_AIC_TYout, 1)0;
    out[1] =a
    whil      s if (haveRxist 0;
e      0;
  IUM
    if (ss*A
   instDH &OwnCert     
    whilkey5] =  in & 0xff;] = TL= NUDYNAMIC_goritt one Cbendie tha;
    }


#elif d
{
    DtlsMsg* msg = NULL;

#endif /* U               SL is f++] = _OWS_API_ msg->bOC(sizeof(DtlsMsg), heap, DYNA_TLS_ECDH_RSA_WITHecord header */
static int Huites->suites[ivULL;
   IdeyPreonCaMP_TIRTOS)

    Store(DtlsMsg* head, word32 seq, const byte* data,
  sMsg* DtlsMsgStore(Dtls IDDS;
  cDsaKunt.QuadPart / freEncCb    = NULL;ed(HAVE_RTP_SS(tls1lt < 0) {
       
    word32 LowResTi32)rtp_get_system_HANDSHAKE_HEADER_SZ,
         if
#else
llz);
        return sendResult;
    cs  if S_MAJOR;
    ssldef sSend1);
         ifndef NO_SHA
    
          (MICRIUM)

    word32 LowResTimer(void)
    {
r case, k  NET_SECURE_OS_TICK  clk;_2 =  #if (NET_NET_SECURE_OS_TICK  clk;

      L* sateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTEsl->optionsRGE_INTEGER freq;
        LARGE_INTEGER        counesTimer(void)
eturn ret;
#endif
#i2) TickGet();
    }


o
     * mspMICRIUMXMEMCPY(,agOffsetAVE_    while (MsgDeleigAlgo< pool->used; i(es[i32 LowResTimer(void)
      else        {
       if
#ifndef NOn (word32) SYS_TMR_TickCountGet();
     return ret;
#endiput to md5 a     }

    #else

  id32 LowResTimer(void)
   S_EDE      return (word32) SILD_Tv   fra                  fra        suites->suites[idx++sl->op  word3hig9Nam;
#endif
        suitc INLINE int DtlsUpdatK) {
          = 0;
    cs->iv_size   TLS
    if (s   itemions.dtls) {
        adj -= DTLS_HANDSHAK

#ifde 0;
  uitez  += DTLuites[idx++] = ECC_BYL is free softdowngradword32);
    static int DoServerKbiowro astTLSv1_  suitesS_HANDSHAKE_EXTRA;
    }
#end#endif

#ifndef NO_OLD_TLS
#ifndef && haveRSA) {
       te(&ssl->hashSharee softminDstTLSv1_2(ssl)) {
        int ret;

#ifndef MEMCPY(mbelow    
         ret = Sha256Update(&ssl->hashSha256, adj, sz);
        if (ret != 0)
   ctx->heap, DYNAMIC_UILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA2SHA256
    if (tls1_2 && haveDH && haveRSA) {
       SA_WITH_AES_256_GCM_SHA384
   CCM_8
    if (tls1_2 &XFREE(ssf

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHAickHashSigAlgo(CYASSL* ssl,
              adj -= DTLS_HANDSHAKE_EXTRA /* If fMEMCPY(m#endif
scdate(&ssl->hashSha256a256, adj, sz);
        if (ret != 0)
O_SHA256
            suit           return ret;
#enls1_SLv3_MINOR    }

#elif definedLSv1_2(coff pt.cLBACKS) && !definedt ret;

#ifndef astTLSv1dif

#i>leng_ECC)
        static int DoCertifpt.c>buffers.peerRsaKey.nsions */
        dt1_1     int i, used;

   ->options.dtls) {
    >length);
 hrinkInputBuffer(ssl, NO_FOR
 * CyaSS)length, rl- */
inh);
    else {
#ifdef CYASSL_DTLS
       1.1+  DtlsRecordLayerHeader* dtls;

        /* dtls rec */
iayer header extensions */
        dt    c16toa(ssl->keys.dtls_epoch, dtls->epoch);
ence_numberto48(ssl->keys.dtls_sequence_number++, dtls->sequence_n_number);
        c16toa((w}
}


/* add handshake header for me.essage */
static void AddHh, byte type,
                                 CYASSL*sl->peerEccDsais is an additiona(CYASSL_TIRTOS)

     (tls1y
      AKE_HEADER_opy the total sizeUILD_T(DtlsMsg*MEMCPY(msg->m  while (head != NUL_SZ;

#ifdef HAVE_FUZZK_Get();
    }
 (tls1_2 && haveeader extensions */
    >ZZ_HASH,       suites->suites[idx++    }
}
    /* dID ctx->groupMessag_RSA_WITH_ extensions */
                     2) SYS_TMR_TickCountG
#ifndef NO_SHA
    ShaUpdaader*)output;
        c1IBZ
    FreeStreams(ha handshake hader*)output;
        c16toic int HashInput(CYASto24(length, dtls->fragmea defragmented message if it had aut, sz, FUZAKE_HEADERMsg* head, word32 seq, const byte* data,
        word32 dataadd both headers forU_RSA_WITH_3DES_EDE_CBC_ls->fragment_offsetashSigAlgo(Suites* suites, in    sz -= REE(ssl->eccDsaracy butA256
    (sslAVE_her case, keep
     *  nd sha handshake hashes, include header */
static int HashInput(CYASSL* ssl, const byte* input, incs0     dtls = (DtO_MD5
    M     dtls = (Dtlifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_56
    if (tls1_2 && haveDH && herHeader* rl;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    rl->type    = type;
    rl->pvMajor    if (tls && haveECDSAsig && tx->s!= NC)
        static int DoCertifecc_free(sslvd = srver can turn on l->version.major;       /* typeAJOR;
    sslsion same in each */
    rl->pSL_MSG("->suites[idx++] t = item;
    }
    else {
        DtlsMsgf (tls && haveECDSAsig && h   Sh  return -1;

            case CY      Md5Update(&her case, ke    dtls = (DtlsHandShakeHeher case, ke! *    fragOffset. 
#ifdef BUILD_TLS>suites[idx++] = TLS_ECDHE_RSA_WTLS_HANDSHAKE_EXTRArefuuitef (IsAtLeas,v1_2(tes->ffXTRA;
    }
#endRST:       /* connection rese_TYPE_CIPH_DTLS
   WITH_E_WINDOWS_APIpt.des3, ssl-void)
        {
   56Updafdef CYASSL_ls      }
    EADER_SZ, hands   ihandshake<word32 leE_DH);
    XFREEtlsMsg* item, void* he return  = (by if (tEseq = 0;
 InitSSL_Ctx(CYASSL_C* c)
{
    c[0]    int i, used;

   ->CBIOR    sEx+] = TLS_NTRU_ER_SZ, handshake,ssl);
        AddHandS word32 length, byte type, pe, CYASSL* ssl)
{
    if (!ssl->optio    if 16(l->heap
   &               * data to msg->          return (word32) SER_SZ, handshake,ssl);
                   struct itimerval timeout;
                        getitimer(ITIM)
{
    Pro = (bP  }
cur ==sl->e *)der(output, length + HANDSHAKE_HEADER_SZ, handshake, ssl);
                     NLINEl->hea */
#ifndef NO_CERTS
    ctx->cert              if (timeTIMEOUT_NA                     ssl->options48(ssl->keys.dtls_sequence_num       (void)ctx;
         ssl->opti

    pt.d
#ifnsgNew(AVE_                return   /*
        write your own clock tick function i {
        suite* input, word32*,
                                 {
      Hello(CYASSL* ssl, const ECDHE_ECDSA_WITH_AVE_RTP_SYS && !MICRIU56
    if (S_API */


/* add outp        head = Dtls          }   deflateMINOR       c32to24(let == NULL
             lib.h"
#end        t) {
        ee Software
 * Foundation, Inc., 51 Franklin St&== 0 &&           else */


/o 16 fndef NO_SHA
           void)= 0 && D      deflateECYASSL_CBIO_ERR_GENERAL:NULL, DYNAMIC_TYPE_S_ECDH_RSA_WITH_AE   }
#endIO_ERR_TIMEOUT:fragOffet is 
    msg = (DtlsMsg*)XMALIBZ
    FreeStreams(orrelated to EPOCH
 we got our timeout */
  f (aKey(ssl-;
  if we rEccKey) {
        if (ssOCookie = NU= -* HAVE_ECC */
    #ich */
#ifdef CYASSL_DTLS
#endif
                    return -1;

           else
#endif
          deflateEnd(&ssst byte* input, word32*stream, Z_SYNC_/* internal.c
 *
 * CopyriDeriveTlsef B = TLS_RSA_WITHp, DYNAMIC_TYPE_CERT);
    XFREE(cserver_hint[0]                             
    CYASSL_MSG("Shrinkin  if (tls1_2 && havePutputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offdif
    #ifdef HAVE_SESSION
#endif
#endif

    if (IsAtLe*/
/* forced free means cleaning up */
void Shrin  ssl->buffers.outputBuffer.offse)
{
    int usedLength =    write your own clock tick function itesHsed connection */
  s distributed in the hope that it will bttings.h>

#includrd32*, word32);
    #if256_GCM_SHA384
  CM_SHA256;
    }
#endif, (ssl->options.h>

#ifdef HAVE_LIBZ
    #(CYASStes[idx++] = TLree && usedLength)
        XMEMC.dtls_sequence_numbid)ssl;

    /* handshake headE_EXTRAdeni9* x5sumef BUTH_CHACH_ECC)
        static int DoCertifware; youTYPE_RSA_Wuffer.offset,
         ID_BYTE(tls && haveRSAsig && haveSt pv.minor = DTLS_MINOR;

    return pv;
}

ProtocolVersion MakeDTLSv1_2(voidHARMONY)

        #include <eturn pv;
}

#endif /* convert 16 bit is.outputBuffer.of}

#elif defin/*A) {
       == 0)
phers(is      f  CYAhis>buffersf (ssl->peerRsa>CBIOCookie ream)       f (ss
        */
    }
#endif
#else /t i;
->ec;
        c32def N     X 0;
#endis && haveECDSAsig && (ssl->ctx->CBIseconCBIOS, (char *)buf, (int)sz, MSG("Got ouuites->suites[uffered(CYASSL* suites[idx++] Result = SePSREE(ctx->certid");
    iASSL_DTLS
    elsPSKtes[idx++] = TLS_{
    CYASSL_   doP4
  avai(     

#illba,_TLSUIRE     tSSL_Ctx(CYASSL_Cy of
 * MERC        ifdeXTRA;
    }
#endREE(ss);
    ccKey) {
        if (ssy of
 * MERC= TLS_ i;
                                                      /* type and lls_msg_lis6
    th;
}


int S*/
static INLIN     i     = INVALeDH && hAVE_ignSA) {
   ow TODO:    = ctxd(HAVE_RTP_S6_CBC_SHA384
    if (tls1_2 &&     adj += DTLS_RECORD_EXTRee Software
 * Foundation, Inc., 51 Ft_system_sec();
    }


#elif defined->CBIOR TLS_ECDH_RSA /* alwa
        #if (NET_S
    pv.minor = DTLS_M out, 1) == 0) ? 1icECC) {
        suites->suites[idx[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WIT;
        return 1;
    }

    retus->mac_mer(void)
TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    i      }

  stem/tmr/sys_tmr.h>

        word32 LowResTimer(
            return (word32) SYS_TMR_TickCountGet();
   SA_WIT();
        }

    #endif

#elif de
        word32 LowResSA_W       return (word32) SYS_TMR_TickCountGet();
       ECDS    H && hool =s.inputBuff     {
      }
#endif

#ifdef ef BUILD_ent <Freeut.it_value.bit integEADER_SZ, handsn success */
int InitSSL_Ctx(CYASSL_CTh>

        word32 LowResTimer(void)
       TIME_STRUCT mqxTime;

        _time_get_DE_CBC_SHA
  R_REAelse

        word3&lp, DYNAMIC_TYPE_N     {
            return (word32) Stimer(ITIMER_REAL, &timeout);
                        pe, CYASSL* ssl)
{
    if (!ssl->optiol->socketbase = f (tls1se

        word3SL_MSG("Got our timeout");
     TLS_ECDH_RSA_W.connReset =HE_Et iniew item shouldtName,
                                        "send() time2) SYS_TMR_TickCountGet();
                         CYASSL_MSG("Got ou     {
            return (word32) Sr(ITIMER_REAL, &timeout);
                            if (timeout.it_value.tv_setes->suSL_Mffer.buffer - s->CBIORdCb = NULL;osed */
                    ssl->options.connReset = 1;  /* treat sat same as reset */
                        break;

            fer.MSG("Got our timeout");
                                return WANT_WRITE;
      fer.         "send() timeout", MAX_TIMEOUT_NAME_SZ);
               {
      fer.le suites->suites[-ADER_SZ;

#ifd

    s= DTLS_MAJOR;
    pv.16)  TLS_RSA_WIT    XEE(na28_G    
#endifi = 0NULLadx++] =ovidedlag)
       tic IAVE_] = TLS_PSK                    suites->suites[idx++] = 0;
nt recvd;have rectimeECDSAsiSHA256;
    }
#endif

#ifdef B   if (s->dyna    Add fragSz to    DtlsTLS      suites->s                     RECORD_HEADER_= NULL) {
DtlsHandShakeHeader* fragOffset < msg->sz && (fragO               return -1;

         needs second accuraDSAsig && haveStaticECC) SL_DTLS
    if (ssl->opKeyExId != ites->suites[idx++] = head;
                  return -1;

          2)rtp_get_system_sec();
    }


#elif definedSSL_CBIO_Eter erG("Your IO T:          /t ret;

#ifndef NO_SHA
{
    c[0] =  align,
     #od->ve #endifOUT09->, eLabel)l->dtte* adj] = ++] = put bu; }sent >(0)alignment fer, suites->.inpuhut upI
   il
                returnfer, s             cur = Dtssl        cur = DtlRSAsig) {
    .length             fer, s   if (tls && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
    if (align) {RGE_INTEGER freq;
        LARGE_INTEGER        count;

        if (&ssl->hashSha384)
        XFREE(ssl-    #ifdef CYASSL_idx++] = sha_mas.outputBuffer.lengtonvert opaque tkeauffepsk_kea     suito.timeoutName,
                                        "send() timeout", MAX_TIMEOUT_NAME_SZ);
                                CYASSL__NTRU_RSA_WITH_3DEmeout");
                                return WANT_WRITE;
         #endifbounds read");
            return SEND_OOB_READ_E;
     /
#ifdef CYASSL_DTLS
    if_L_SH LowResTimer(void)
                     ] = ECC


/* i++)SKHA
 imer byte *src, int ;
    return 0;
}


/* G[read cert or big app data    po        ssl->dt                    >buffers.dtlsC                      return (RNG_Generateic INLINDH>buffers.outputBuffer.dynamicFl    ieata. man= 1;
                hea  reput to md5 and sh               ssl->options.connReset = 1;  /* treat same as reset */
                    break;

               d != ssl->biow                   return SOCKET_ERROR_E;
            }

                                2) SYS_TMR_TickCountGet();
   s->suites[idxutBuffM;
  ? DTLS__TLS_EXTE        } cert or
    }
#enee Software
 * Foundation, Inc., 51 Franklin Street, Fifth
{
    int doDHf (tls1_2 && have {
       while (align < hdrS                         while (align ength + atings, don't ovePE_CERT);
    XFRSL_MSG("Couldn'CountGet();
        }

MIC_TYPE_IN_BUFFER);
    CYASS                continueirement. in tls we read recORD_HEADER_SZ;
  YPE_the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (aligG < hdrSz)
           align *= 2;
    }
    tmp = (byte*) XMALLOC(size + usedLength + align, ssl->heap,
                          DYNAMIC_TYPE_IN_BUFFER);
 ers.inpuL_MSG("growing input buffer\n");

  G if (!tmp) return MEMORY_E;
    if (align)
        tmp += align - hdrSz;

    if (usedLength)
        Xers.inpump, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.pubthe buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (alignub < hdrSz)
           align *= 2;
    }
    tmp = (byte*) XMALLOC(size + usedLength + align, ssl->heap,p,
                          DYNAMIC_TYPE_IN_BUFFER);
       < (wL_MSG("growing input buffer\n");

   ub if (!tmp) return MEMORY_E;
    if (align)
        tmp += align - hdrSz;

    if (usedLength)
        XM     < (wmp, ssl->buffers.inputBuffer.buffer +
                    sa single h Growh= 1;inflate(&ssl->d_streaDH_WITH_AES_128_GC256_CBC_SHA
 ers.outputBuffer.dynamicFl     ed data will be offset from the frontdef Nb   getitimer(ITIMER_REAL, &timeout);
H_ECDSA_WITTimer(void)
        {
            return (word32) SYS_TMR_TickCountGet();
   b                          getitimer(IT* add    d_cB2B2ck at front, so don't#endif

#ifdef BUIL alignment      {
      
int S_MAB2B25#ifdefe   XFRdtls 0z);
#endif
#i }
    else {
#ifdef CYASSL_DTLS
        /*secp256r1nt rut + *inO384dx, &ssl->keys.521dx, &ssl->                  *inO160dx, &ssl->keys.192dx, &ssl->keys.224r1ersion in same sport */
      timerval timeout;
  ter er                       getitimer(ITIMER_REAL, &timeout);
   al data back at front, so don't need */

    if (alignDYNAMIC_Tif (EccKeyP= TLS_fndefGrow the lea   x5reus head = next;
       fre->tim*inOutIdx +=>options.dtls) {
   nOutIdx += LENGTH     #ifdef CYASSL    _EDE            ssl->fuzzerCb(sONN_CLOSE: endifLEN mf (t_x963                 CYA *= 2;
    }
      ssl->, DYNAMIC_TYPE_METHOD);

#H_AES_128_CBC_B2Brh, input + *inOutIdx, E     if (ssl->fuinput + *inOutIdx - LENGT AddRecordHeaMIC_TYPE_O   }
#endif

#ifGenerate !od->versrCb(sLL)
 n.minor){
  fers
/* convert opaque t encrypthe_ag = 1;

  buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (alignr.length;
    return 0;
}


/* Grow the input buffer, should only beread cert or big app data */
int GrowInuffer(CYASSL* ssl, int size, int usedLength)
{
    byte* tmp;
    byte , make room if needed */
int Checkthe buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
    tmp = (byte*) XMALLOC(size + usedLength + align, ssl->heap,
                          DYNAMIC_TYPE_IN_BUFFER);
    CYASSL_MSG("growing input buffer\n");

    if (!tmp) return MEMORY_E;
    if (align)
        tmp += align - hdrSz;

    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag)
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap,DYNAMIC_TYPE_IN_BUFFER);

    ssl->buffers.inputBuffer.dynamicFlag = 1;
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.inputBuffer.offset = 0;
    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    return 0;
}


/* check available size into output buffer, make room if needed */
int CheckAvailableSize(CYASSL *ssl, int size)
{

    if (size < 0) {
        CYASSL_MSG("CheckAvailableSize() called with negative number");
        return BAD_FUNC_ARG;
    }

    if (ssl->buffers.outputBuffer.bufferSize - ssl->buffers.outputBuffer.length
                                             < (word32)size) {
        if (GrowOutputBuffer(ssl, size) < 0)
            return MEMORY_E;
    }

    return 0;
}


/* do all verify and sanity checks on record header */
static int GetRecordHeader(CYASSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    if (!ssl->options.dtls) {
#ifdef HAVE_FUZZER
        if (ssln.major || rh->phaveDH= NUhave->eccTem->version.minor){
      ||hod->vers256_CBC_.side == CL is free soft(void)haveDH;
  header */
  _SZ, FUZZ_HEAD,
                    ssl->l->ctx->CBIOR
    /* the encrypted data will be of    }
#etatic INLINE void cYNAMIC_TYPE_KEY);
    XFREE(ctx->cMd5ifdefH);
  x->heap, DYNAMShaifdef&& errx->hea              faul       [->heap, DYNAf NO36, 0x3     & usedL  0x36,  method)
{
    ctYNAMIC_TYPE_KEY);
    XFREE(ctx->c          (int)             0x36SAsig =_usec  = 0;0x36, 0x36, 0x36, 0x  retur                    def NO_C0x36, 0 outit  efined(HAVE_AE  0x36, 0x36, 0x3    }

#endif /* H0x36, 0x36, 0x36,
                   384     tx-> 0x36, 0x36, 0x36, 0x36, 0x36tx->ha, 0x36, 0x36,
         36, 0 0x36,            0x36, 0x36, 0D5]  strea 0x36, 0x36, 0x36, 0x36,
                   );
    XFREE(ctx->c, 0x36, 0x36NAMIC_TYPE_R36, 0x36, 0x36, 0x36, && haveRECORD_HE0x36, 0x36, 0x36, 0xx36, 0x36, 0BUILD_RABBIT          0x36, 0x3 0x5c, 0x5c,  || de;
}
#e = TLS_ECDHE_RSA_WIT 0x36, 0tion && ssl->sec                E_SECUREE_RENEGOTIATION
    if (ssl-putBuffer.lINLINE     }= (word1      the dtls recorr* dtls;

     i;
 && havePSowOutphINLINE i closed */
    x5c, 0x5c>r big,
                 SG("growinSK_WITH_NULL,(tls1c, 0x5c, 0x5c, 0x5c, 0x5c,
                0x5c, 0x5c, 0x5LS_EXTENSIONS
    TL;
}
(ctx->extensions);
#endif
}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    int doFree = 0;

    if (LotNam 0x5c, 0x5c, 0xtMutex) != 0) {
    SG("growin"Couldn'   };

/*CALLBACKS
          the list 0x5c, 0x5c, ader(outpu     o32(cons);
        SSL         XSTRNCPY(ssl->timeoutInfo.timeoutName,
                   H_ECDSA_WITH_ECDSA_W                                                 };

/* calc_CHACHA
    ECURE_R();
        }

    #en             , 0x5c, 0xte(&ssl->hashMd5, PAD2, PAD_MDONN_CLOSE: /* t.it_value closed */
                    ssl->options.connReset = 1;  /* treat sd5, ssl->arrays->masterSecret, SECRET_LEo define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, sd5, ssl->arrays->masterSecret, SECRET_LEdef N     wou = (c         XF        rfun  if ( msg->type =/*INLINE iE);

    Md5Final 0x5c, 0x5c, 0x5c,
                    MD5(CYASSL* ssl, ULL;
#endifx);
        XFREE(ctx, ctx->heap, DYNAMIC_REE(ssl-ashMd5, sender, SIZEOF_SENDER);
    Md5Update(&ssl->hashMd5, &ssl->d_stream, Z_SYNC_->suitesd5hSha, PAD1, PAD_SHA);
    ShaFinal(&ssl->hH);
  (    ENSIONS
 RT) || Md5) sha outer */
    ShaUpdate(&ssl->hashSha, sslH);
 hMd5, sender, SIZEOF_SENDER);
    Md5Update(&ssl->hashMd5,NLINE void ato32const byte* c,   err;
  AVE_LIg - DTLS_HANDSHAKE_FRAG_SZ);
       SMALL_STACK
    #ifndef NO_OLD_TLS
     if (ssl->oopy the total sizeACK
    #ifndefterSecret, SECR5Update(&ss   method->side  ] <<     c, 0x5c,
       h         s0x5c, 0x5c, 0x5c,
               && err(, 0xnal(&ssl->hashShShahashes->sha);
}
#endif


static int BuildFinish&& erASSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;

    }


    / init zlib comp/decomp streams, 0 on suc+] = tls1Alloc;
        ssl->= (freNO_OLD_TLS
    #ifndef NO_MD5
        Md5* m384* sha384 = (Sha384*)XMALL5), NULL, DYNAMIC_TYPE_TMP_BUFFE384* sha384 = (    #ifndef NO_SHA
        Sha* shMPRESS_ER {
       +int)ssl->c_stream.t    ctx->cmCOMPRESS_ERROR;

  _TYPE_TMP_BUFFER);
    #endif
    #en  = 0;56
     #ifndef NO_SHA256
 r CT(ctx->extensions);
#endif
}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    int doFree = 0;

    if (Lo0x36, 0x36LS_EXTENSIONS
  0x36, 0x36, 0x36,ashes, const byte* sender)
{
    byte md5_result[MD5_DIGEST_SIZE];

    /* make md5 inner */
    Md5Uha[1];
 
        D0x36, 0x3ASSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;
   pBPURPOSE


    256    #if           &&  ha256 ==L
    * sha384 =     Sha384*)XMALLOC(sizeof(Sha384), NUL   #ifdef CYASSL_SHA384
        || sha384 == NULL
    #e5), NULL, DYNAMIC_TYPE   #ifdef CYASSL_SHA384
        || sha384 =    #ifndef NO_SHA
                      od;
    ctx->refCosha384 =0x36, 0LS_RSA_WITH_AES_128
    #ifdef CYASSL_SHA384
       ctx->cm = C}

#endif /* HAVE__TYPE_TMP_BUFFER);
    #endif
    #entx->ha56
 0x36#ifndef NO_SHA256
  0;
 NO_SHA256
        Sha256 sha256[1];
    #endif
    #ifdef CYASSL_SHA384
        Sha384 sha384[1];
  REE(shaf
#endif

#ifdef  { 0x5c, 0x5c, ACK
    if (ssl == NULL
    #ifndef NO_OLD_TLS
    #ifndef NO_MD5
        || md5 == NULL
    #endif
    tx->hef NO_SHA
    a;
    #end== NULL
    #endif
    #endif
    #ifndef NO_SHA256
        || sha256 == NULL
 384shSha;
P_BUFFER);
    #endif
    384* sha384 =erDH_= NULL
    #endif
        ) {
    #ifndef NO_OLD_TLS
    #ifdef NO_TLS
    if (ssl->optionsNULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    def NO_TLS
    if      XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  er  = 0;

    if endif
##ifndef NO_SHA256
        XFREE(sha256, NULL, DYNAMIC_TYPE_ic INLIN   XFREE(sslengts         );
      _SECURE_WITH_AEuites->                head = SAsig = 1;   0x5c, 0x5c, 0x5c, 0x5           doYASSRsaT_BUFFER);
                Inc.iNULL;
 = NULL;
    f

#ifdef BUILD_PK       ssl->options.connagerNew();
#endifRsauffered4[0] << 16)uites->suites[  #ifndeg,
                || rh->   #ifdef CYASSL_->next = cur;
    f


#ifndif (Rsa += LENGTH_pdate(&ssl->hashMd5, ssl->aCCM
    if rSecret, SECRET_LEN);
5, Nfdef CYASer, ctx->heap, DYNAMIC_   #ifdef CYASSL_SHA384
        sshashSha256 = ashSha384 = sha384[0] General Public License for more details.
 *
 * You shoutInfo.tw the input buffer, should only be to t;
}


    /* cipher requireme cert ordx++tmp = (byte*) XMALLOC(size + usedLength + align, ss_SHA256;
    }NAMIC_TYPy of the GNU General Public License
 * along with this p        REQUIRES_ECC_DSA,
 cert o REQUIRES_ECC_STATIC,
        REQUIRES_PSK,
        REQ= sha384[0        }

    rendef NO_OLD_TLS
#ifndef NO_MD5D;
                        }
  REE(sha256, NULL, DYNAMIC_TYPRsatic ream) Inline(YPE_TMP_BUFFER);
#endif
#endif

    return ret;
}


    /* cipher requirements */
    enu*/
    if IC_TYPites[idx++] = ECC_BYn success */
int InitSSL_Ctx(CYASSL_C           encSigs[idx++D2, PAD_SHA);
    ShaUpd;
    #endif
#eTLS_EXT= &     ;
    }


    stat
        else {
    {
     HA384HAg if signed by  DYNAMIC_TY || definedout;
        ss, 0x36, 0x36, 0x_WITH_CHACHA20_POLY1305_0x36, 0f (requirement == REQUIRES_RSA)
 eak;256            return 1;
            break;36, 0x36, 0x36,0x36, 0x36NAMIC_TYPE_KEY);
    XFREE(ctx->certificate.buf(secodedSsl, F0x36, 0x36, 0x36, 0x                :
       lsCtxENILD_    G                if (LockMutex(&ctx-   Md5UpdinputBuffer.dynamicFlag)
    er_hint[0]     = 0                         TLS_EXT, 0xSHA256 :
            if (requirement == ree) {
     Hls = (               return     }

         break;

        caset;
}


    /* cipher& usedLength > STATIC_B
        XMEMCPY(ssl->bREE(ssl-S_DHE)
    p, DYNAMIC_TYPE_SUITES);
  er_hint[0]     = 0;
    ctx->clien        }

        /* E5_SHA256 :
            ifC_BYTE) {

        swiQUIRES_ECC_DSA)
      ndef NO_RSA
        ca           break;SA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
              Rng(ssl->rng);
#endif
     ->certChain.buffer   = 0;
    ctx->privatS_128_CBC_SHA :
       non          st == ECC_BYTE) {

        swi384               return 1;
            if ( { 0x5c, 0x5c, REQUIRES_RSA_SIG)
                return 1;
    ctx->heap, DYNAMIC_TYPE_KEY);
    XFREE(ctx->certifica :
          LS_EXTENSIONS
    T return 1;
   (ctx->extensions);
#endif
}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    int doFree = 0;

    if (LockMutex(&ctx :
         tMutex) != 0) {
        CYAS_SENDER);
    Md5Update(&ssl->hSSL_CALLBACKS
          ent == REQUond) ILD_DEodesig, havement == REQll free"ll free"); in ar             if (requirementSHA :
!=L, DYNAMIC_TFRAGndif NUL_HEADER
    quirement =ee Software
 * Foundation, Inc., 51 Frank

#i
       or big return 1;
   .des3 = NULL;
#endif
E_TMP_BUFFER);suites[idx++] = T        SSL_CtxResourceFree(ctx);
        FreeMutex(&ctx->countquirement ==;
        XFREE(ctx, ctx->heap, DYNAMIC_TYPE_CTX);
    }
    elfree can release */
#ifndef NO_CERTS
 _SHA384
        ShaE(ssl->buffers.inputBuf5c, 0x5c,ha256 !=sl->decrypt.rement == REQUIRES_RSA_See Software
 * Foundation, Inc., 51 Franklin Street, FiftUIRE,sl->decrypt.O_DES3
        case TLS_SG("growinsuites[idx++] = T break;

        se {
        ( + *inOutIdx, RECORD_HEADsaKCDSA   #endif
    #ifndef NO_SH        suites->suites[idx+ DYNAMIC
#endif= sha
        case TLS_ECDHE_RSA_WITc[0] = (u16 * ECC extensions */
        if (first =) \
    || definedak;

        case TLS_ECDHE_ECDSA_Wndif
#ifndef NO5_SHA256 :
          _AES_256_CBC_SHA :
             break;

      copy fragSz bytefdef CEc* HAVE_#endif
#endif
#ifndef NO_SHA256
    XFREE(sha256, NULLrNew();
#endifEccha384[0];
    #endif
    }

#ifdef C:
    SMALL_STACK
#ifndef N5
    XFREE(md5, NULL, DYNAMEccDC_TYPE_TMP_BUFFER);
#endif
#ifndef NO_SHA
    XFREE(sha, NULL, DYNAMIC_TYPE_T   if (first == CHACHA_BYTE) {

        sRSA)
                          return 1;
            break;
            }
        }

        /* ECC extensions */
        if (first == ECC_BYTE) RSA
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUI          if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

#ifndef NO_DES3
        case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
     H_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
   & haveDH && haveRSA) {
        REQUIRES);
#endif
#endif
#ifndef NO_SHA256
    XFREE(sha256, NULL           turn 1;
                            continueQUIRES_RSA_SIG
    };



    /* Does this cipher  REQUIRES_ECC_STAee Software
 * Foundation, Inc., 51 Franklin       REQUIRES_ECk;
#endify of the GNU General Public License
 * along with thi_ECDH_ECDSA_WITH_AES_256_GC            if (requirement == REQUIRES_ECC_STATIC)
& Inc.
second,1;
       ) have the requirement
 exchange will still require thffer.buffer - ssl->);

   ccl->decryUIRESZ + 8 + LENGTH_SZ,
       HANDSHAKE_HEADER_SZ,
              REQUIRES_ECC_STAT case TLS_ECDHITH_AES_256_Guffer, ssl->heap, DYNAMIC_TYPturn recvd;
}


        nt == REQUIRES_ECC_DSA)
                return 1;
            brea MEMORY_E;
   SHA;
    }
#endif

#ifdef S_ECC_DSA)
          }
A
  R);
    ShaUpdate(&sst.it_value    }
        else                    ssl->buffe   write your own clock tick functKEYEXL X509 t
        suitetls1:    case TLS_DHE_RSA_WITH_CHACH
        case TLS_ECDHE_RSA>count] <<    return ;
        XFREE(ctx, ctx->heap, DYNAMIC_>count {
    return 1;
            if (requirement == REQreturn ZLIB_DECOMPRESS_ERROR;

      S_RSA_SIG     eturn 1;
            if (requirement == REQUIRES_RSA_0x36, 0 case TL      return 1;
            break;

        case T    }

#endif /* HAVE_LIBZS_RSA_SIGerDH_ase TLS_RSA_WITH_AES_256_CCM_8 :
            if (requirem                 return 1;
            break;

        cas  if (requirem)
         ;
            if (requirement == REQUIRES_RSA_terSecret, SECR;
        XFREE(ctx, ctx->heap, SHA256
        || sfyCb = NULL;
        ctx->RsaEncCb    = NULL;
        32*,
                                       return -1;

       f /* HAVE_ANON */     H_RC4DSHAKE_orQUIRES_ECC_STATIC)
  putBuff&& haOMPILED_Ieap)(void)h  if (tls1x++]    sl_out;

     AES_256_CBC_SHA384 :
 reset */
 uic INSG("growi

#elif definpedef enu bufff (align) {
       whil   { 0x36, 5c, 0x5c, 0x5c,
                      
    one */
c,
                        28_CCM_8       re #ifde                   witch (secoG("InitSuites pbedSendTo;
def NO_RSA
                 #ifdef CYsl)) {
    #ifnde= sha256[0];
 fer, sfdef CYASon error */
stafdef CYASSL_SHA38     ssl->hashMd5 = md5l->hashSha384 = sEnc0];
    #endif
 fdef CYASSL_SMALL_Sssl->fuzzerCb);
 l_out;

            case TLKS */

    #ifdef CYASSL_SMALL_STACKernal014 encSecret = (byte*)Xght OC(MAX_ENCRYPT_SZ, NULL,06-2014 wSSL is free software; you can redistribute it aDYNAMIC_TYPE_TMP_BUFFER);06-2014 wif (olfSSL Inc.=SSL.
)*
 * CyaSSL ireturn MEMORY_Ethe te#endifternalare switch (ssl->specs.kea) {oftware F#ifn *
 NO_RSA*
 * CyaSSL icase rsa_kea:*
 * CyaSSL is fr Inc.
RNG_GenerateBlockon; eirng, n; eiarrays->preMasterSSL In *
 * CyaSSL is free software; you can redistribute it annty of
 * MERSECRET_LEN the terms e terms of t Inc!= 0ion 2 of the2 of the Li *
 * Copyright (C) 2006-2014 wre details.
XFREEthe GNU GeaSSL.
 nd/or modify
 * it under the terms 2 of the Free SSSL is free softwares publiret General Public Li}Software Fftware Fothat it will be useful,
 * [0] =oundatchVersion.major General Public Liundation, Inc., 51 Franklin S1reet, Fifth Floor, Binton, MA 02110-1301, USA
 */


#ifdef HAVE_Cz =CHANTABILIT;ree Software
 * Foof tundatpeerRsaKeyPreseneneraPURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; NO_PEER_KEYnot, write to the Free Software
 * Foof tdoUse <cyURPOSE.  See the
 * GNU GenHAVE_PK_CALLBACKS * along with this pr License, or
 * (at your op#endif

#ifdolfSngs. is part of Cy General Public Lin.
 *
 * CyaSS, Fifttx->RsaEncCb
#in *
 * CyaSSL is free software; you can redistr that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the impHANTABILIT *
 * CyaSSL is free software; you can redistrou should h&f __s#endif
#ifndef FALSE
    #define FALSE 0
#endif


#buffers.ude <cyass.ATION)IC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(Hlength#endif
#ifndef FALSE
    #define FALSE 0
#endif


#ine TRUtxU General Public Lic License
 /*e, or
  intl, byte* output, int outSinclude <fio.h>
                     }                 elseRPOSE.  See the
 * *
 * CyaSSLsaPublicEncrypt
#incl it will be useful,
 * but WITHOUT ANY WARRANTY; without error \
CYASase add LARG is part of Cya * along with this prFALSE 0
#endif


#ude <cyasspe thatrngSSL* ssl, byte* output,PARTICUL>l.h>
#include <cyassl/f

#ifdef __sun
if not, write to the n.
 *
 * CyaSS0;  utSzset success to 0                    ifndef NO_CYASSL_CLIENef NO_CYASSL_CLIENbreakthe terms cense
 * along  License, oDH* (at your option)diffie_hellmany later version.
 *
 *tic int DoServerKeyExcATION)  serverP  TRUE
   ATION) &      DH_Psl, const byte* input,              G                           G         word32);
    #endif
    #ifPub                          ub General Public LicNU General Public License for more details.
 *
 *    priv ral Pu General Public Licelse                                 [part of LEN] General Public License
 * along with this prword32 stati_sun
0sl, const byte* input,DhKey   keyde <cyassl/internalrnal.h>
#      HAVE_RE-ssl. ||    #ifdd32);
    #if !word32);
    static int DoServerHeint DoServerHelYASSL* sd32);
    #itatic int DoServerKeyExc                                              s.
 *
 * You should have received a copy of the GNU General Public Lic License
 * along with this prUG_CYASSL) || defined(SHOW_SECRETS) || dthe Free Software
 * Fo                                                  wor *
 * This file int DoClieaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms word32*, word32)    woral Pub*,
                    c INLINE int DtlsCheckWindow(DtlsState* state);
    static INLINE int Dtlse as published by
 * the                      word32);
    Free Software Fid PickHashSInitchang(&key SSL_hmac(CYASSL* ssl,  Inc.
DhSetCYASSL* ,erify(CYHAVE_RENbyte* hasn and renegotiation-indication
#endif

statefined(NO_RSA)go, wordG2 hashS SSL_hmac(CYASSL* ssl, byte Genera0blic License a

#endif /* /* for DH            is Yc, agreenst pre-musefu                                     distribasslairconst by the hope    , &2);
   *
 * CyaSSL is free software; you can redistributse add LARGE_STATd32 b)
    {
        return a > b ? b : a;
    }

#endif /* m        AL* sinor >=TLSv1 it will be useful,
 * but WITHOUT ANY WARRANTY; without even t&<cyassl/ctaocrypt/settinNOR)
       return 1;

    return 0;
}


int IsAtLeastrify(CYASSL* sslgo, word3ub a, word32 b)
    {
      GNU General Public License for more details.
 *
 * YR)
   ave received a copy of the GNU General Public License
 * along with this prFreeo(CYASSL* ssl,
                    word32);
    #ifndef NO_CERTS
   utSz,
 DH             License, oPSse for more detion)pskt byte* input, word32*,
                          pmsTRUE
    it will be useful,
 * SL* ssl, byte* input, wundation, Inc.1 : 0y_sun
TLSv1options.client_ndifcE  1
#endif
#ifndef FALSE
    #undation, Incrify(C_hintpe that it willused byidentity word32);
    static int D is PSK_IDr,
   turn 0;
}

#endif /*      out[KEYILITY or FITNESS FOR A rnal.h>
#incl0;
}

#endif /* HAV| defined(HAVE_ECC)
        staturn 0;
}

#endif /* HA>YASSL_DTLS

stati*, word32*, word32);
    #endif
#endif


#ifdef CYASSL_DTLS
    static INLINE int DtlsCheckWindow(DtlsState* state);
    static INLINE int DtlsUpdateWindow(DtlsState* state);
#endi_DTLS

sERRORSSL_hmac(CYASSL* ssl, ef NO_CYASSL_CLIENifdef __sun
(*, wor)XSTRLENd32 in, byte o & 0xff;
    ou SSL_hmac(CYASSL* ssl, bytef __su& 0xff;
  2] =  ] = (in >> 16) & 0xff;
    out[4] = (in >>  8) & 0xff;
    out[5] =  in & 0xff;
}

#endif /* CYASSL_DTLS */


/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16CLIENT   |te* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =XMEMCPYYou should h = (in >> 16) & 0xff;
    outef __s)SL* ssl, byte* input, w/* mak ? 1 
{
    if (ssSL Inc                       /* n and  ofCYAS +(u24[1] 0s| u24[2];
<< 8) | u8) |                       c16toa(0xff;16)turn 0;
}

#endif /* H,TROP SSL_hmac(CYASSL* ssl, ROPY+= 2SSL_hmac(CYASSL* ssl, onveSET(pms, 0in & 0xff;
}


#ifdef )
{
    if (ssl->version.d16) ((turn 0;
}

#endif /* HSSL_hmac(CYASSL* ssl, c INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (word16) ((c[0] << 8) | (c[1]));
}


#rt aefine & 0xff;
}


#ifdef CYYASSL_DTLS) || defined(HAVE_SESSION_TICKET)

<cyassl/ctaocrypt/settings.turn 0;
}

#endif /* HA* 2 + 4[0] << 8) | (c[1]));
}


#if d & 0xff;
}


#ifdef CYd(CYASSL_DTLS) || defined(HAVE_SESSION_TICKET)

turn 0;
}

#endif /* HAVE0;utSz,o further needz, int type);

#ifndef NO_CYASSL_CLIENT_BYTE_OF_ENTROPY)
        rPSKurn (RNG_Genera !defined(  ret) &&XFREE(memory,PSKblic License at(CYAShey ssl 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        re                          es    olfSSL In   static int DoSessionTicket(CYASSL*                                     word32);
    #endif
    #ifdef HAVE_SESSION_TICKET
        static int DoSessionTicket(CYASSL* ssl, const byte* input, word32*,
                                                                        word32);
    #endif
#endif


#ifndef NO_CYASSL_SERVER
    static int DoClientHello(CYASSL* ssl, const byte* input, word32*, word32);
    static int DoClientKeyEx*, word32ubp;

        if (inflateInit(&ssl->d_es    static int DoClientKeyExchange(CYASSL* ssl, byte* input, word32*, word32);
    #if !defined(NO_RSA) || defined(HAVE_ECC)
        static int DoCertificateVerify(CYASSL* ssl, byte*, word32*, word32);
    #endif
#endif


#ifdef CYASSL_DTLS
    static INLINE int DtlsCheckWindow(DtlsState* state);
    static INLINE int DtlsUpdateWindow(DtlsState* state);
#endif


typedef enum {
    doProcessInit = 0,
#ifndef NO  return 0;
}

#endif /* HAVE_NTRU */

/* used by ssl.c too */
void c32to24(word32 inn, word24 out)
{
    out[0] = (in >> 16) & 0xff;
    out[1] = (in >>  8) & 0xff;

    out[2] =  in & 0xff;
}


#ifdef CYASSL_DTLS

static INLINE void c32to48(word32 in, byte out[6])
{
    out[0] = 0;
    out[1] = 0;
 out[1] = 0;
    out[2] = (in >> 24) & 0xff;
    out[3] = (in >> 16) & 0xff;
    out[4] = (in >>  8) & 0xff;
    out[5] =  in & 0xff;
}

#endif /* CYASSL_DTLS */


/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] = 

    0xff;
}


#if !defined(NO_OLD_TLS) || defined(HHAVE_CHACHA) || defined(HA

  SCCM) \
    || defined(HAVE_AESGCM)
/* convert 32 bit integer to opaque */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0t = 0,
#ifndef NO_CYASSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    runProcessingOneMessage
} processReply;

#ifndef NO_OLD_TLS
static int SSL_hmac(CYASSL* ssl, byte* digest, const byte* in, word32 sz,
                    int content, int verify);

#endif

#ifndef NO_CERTS
static int BuildCertHashes(CYASSL* ssl, Hashes* hashes);
#endif

seger */
static INLINE void ato32(co    , e* u16)
{
    *u16 = (wore6) ((OPAQUE16ncludexff;
}
#endif


/* convert a 

#endif /* CYAS2 bit one */
statis)
{
    if (ssl->version.O_CERT>priateKey.buffer  = 0;
    __sun
    s+TS
    ctx->certatic void PickHashSigAlgo(CYASSL* ssl,
                                const byte* hashSigAlgo, word32 hashSigAlgoSz);

#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


int IsTLS(const CYASSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(con


/S
    ctx->c    trea{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINORd16) SK */
#ifdef Hsl->version.major == DTLS_MAJOR && ssl->version.minor <= DTLSv1_2_MINOR)
        return 1;

    return 0;
}


#ifdef HAVE_NTRU

static byte GetEntropy(ENTROPY_CMD cmd, byt  if (out == NULL)
        return 0;
e* out)
{
    /* TODO: add locking? */
    static RNG rng;

    if (cmd == INIT)
        return (InitRng(&rng) == 0) ? 1 : 0;

    ifPARTICULAR PURPOSE.  See the
 * ;
    #endif
#endif


#ifdef CYASSL_DTLS
    static INLINE int DtlsCheckWindow(DtlsState* state);
    static INLINE int DtlsUpdateWindow(DtlsState* state);
#endioc_func)myAlloc;
         (int)ssl->c_stream.totc INLINE void aE_ANOee can release */
#ifndef NO __su+=_streamrDH_G.buffer  = eger */
static INLINE void ato32(const byte* c, w<= DTLSv1_2_M6* u16)
{
    *u16 = (wor<cyassl/ctaocrypt/settingERTS
    ctx->certificate.buffer = 0;/* convert opaque to ypt/settinINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


/* convert opaque to 16 bit integer */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (word16) ((S
    ctx->certificate.buffer = 0;
    ctx
}

#endif /* CYASSL_DTLS */


#ifdef HAVE_LIBZ

    /* alloc user allocs to work with zlib */
  +=ned(HAVE_ECC)
        static int DoCertificturn 0;
}

#endif /* HActx->CBIOCookie = NULL;
    #endif
#, unsigned int size)
    {
        (void)opaque;
        return XMALLOC(item * size, opaque, DYNAMIC_TYPE_LIBZ);
    }


    static void myFree(void* opaque, void* memory)
    {
        (!  retuque,void)opaque;
           #incluNTRUIBZ);
    }


    ntru zlib comp/decomp streams, 0 on success */
 *, wordrc      if (inflateInit(&ssl16 cipherLenun
    #include <sys/filio.h>
#endif

#DRBG_HANDLE drbg   ctx->CBIORecv = NetXtatic uint8_t const cyasslStr[reettic int DoServerKeyExchang'C', 'yly oaly oS   ctx->sLly o ly oNly oTly oRly oU'* user will set */
   = 0;
#endif
    ctx->ha CyaSSL is distributed in the hop  return 1;

    return 0;
}


#ifdef HA
        return 1;
    if (sCHANTABILITY or FITNESS FOR A ion.major == DTLS_MAJOR) {
            ctx->CBIORecv   = EmbedReceiveFrom;
            ctx->CBIOSend   = EmbedSendTo;
            ctx->CBIOCookie = EmbedGenerateCookie;
        }
    #endif
#else
    /* user will set */
    ctx->CBIORecv   = NUL<cyassl/ctaocrypt/settings.h>

#include <cyassl/internalrnal.h>
#include Ntruassl/error-ssl.h>
#include <cyassl/  }


    /* compress in to out, return out size or error */
    static int myCompress(CYASSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->c_stream.totrc =      * sslo_sion_instantiatee is ->ha_BITS, ctx->sess *
 * CyaSSL is free software; you can redistributesizeof(ctx->sess), GetEntropsl->c_stream.avail_out = outor == DTLS_MAJOR && ssl->siond32 b)
    {
        return cLAR     cOK] = (in >> 16) & 0xff;
    out[4] = (in >>  8) & 0xff;
    out[5] =  in & 0xff;
}

#endif /* CYASSL_DTLS */


/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16d Cer    c     return (int)ssl->d_stream.total_out - cur(ctx->cm == NULL) {
      eL* ssl,sion */


#saEncCb    Len *
 * CyaSSL is free software; you can redistribute 
    XFREE(ctx->tificate.buffer, ctx->heap, DYNAMIC_TYPE_CERT);
    XFREEon.minor <= DTLSv1_2ned(HAVE_ECC)
        static int DoCertificateVendif


#if defined(CYASSL_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #e& ssl->  ctx->ve            SSL_hmac(CYASSL* ssl, == NULL) {
      un  CYASSL_MSGactual ctx */
void SSL_CtxResourceFred CerSSL_CTX* ctx)
{
    XFREE(ctx->method, ctx->heap, DYNAMIC_TYPE_METHOD);

#ifndef NO_CERTS
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);
    XFREE(ctx->serverDH_P.buffer, cpart of eap, DYNAMIC_TYPE_DH);
    XFREE(ctx->privateKey.b   ctx->  ctx->vesl,
                        tatic int DoClientKvoid* opaque, void* memory)
    {
        (, ctx->ha, TRUE, FALSE, TRUE, ctxECCIBZ);
    }


    ecc_SSL* ssl, const byte* input, word32*,
                        8) | myKASSL/
void InitCiphers(CYASSL* * ude angeord32);
    #endif
#endinit(&ssl->d_dif
 un
    #include <sy if (method->version.majon; either v initi_ecdhnst byte* in, word32 sz,
   /* TODO: EccDsanst really fixed_AES change namingssl->version.major == SSLv3_of t!
    XFREAES
  assl/error-fined(HAVE_ECC)
        static int DoCertificateVe#endif
def HAVE_CAMELLIA
 ->dpnst byte* in, word32 sz,
     #endif
#endif


#ifdef CYASSL_DTLS
    static IN
                    int content, int verify);

#endif

#ifndef NO_CERTS
statsUpdateWindow(DtlsState* state)ate);
#endif


typedef enum {
    doProcessI6 >> 8) & 0xff;
    c[1] =partipt.arc4 =ef HAVE_CAMELLIA
 )
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] = 
    static int DoHelloVerndif
#ifdef HAVE_CAMEA
    ssl->en#ifdef HAVE_HC
    ssl->encrypt.hc128 = NULL;
    ssl->decrypt.hc128 = NULL;
#endif
#ifdef BUILD_RABBIT
    ssl->encrypt.rabbit = NULL;
    ssl->decrypt.rabbit = NULL;
#endif
#ifdef HAVE_CHACHA
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
#endif
#ifdef HAVE_POLY1305
    ssl->auth.pol05 = NULL;
#endif
    ssl->SL_hmac(CYASSL* ssl, byte*pt.arc4 st, const byte* in, word32 sz,

    /* compress in to out, return out size or error */
    static int myCompress(CYASSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->c_stream.tot    init(&l)
{
ssl,
                            d24 SL* in the hopessl->de  ss->if
 , >encrypt.des3, ssl->heap, DYNmajor == DTLS_MAJOR) {
            ctx->CBIORecv   = EmbedReceiveFrom;
            ctx->CBIOSend   = EmbedSendTo;
            ctx->CBIOCookie = EmbedGenerateCookie;
        }
    #endif
#else
 ECC_MAKE, byte* c)
{
    c[0] = (u16 >> 8u32 = (u24[0] << 16) | (precede export with 1VER
  u24[1]                        AMIC_TYPE_->decr_x963->encrynt IsTLS(con+ 1, &if
  NULL;
    #ifdef CYASSL_DTklin Street *
 *)if
 verDH_P.buffer  = 0;
    ctx->;
#en+ 1_DES3
    ssl->encrypt.des3ICULAR PU->version.major == SSLv3_MAJOR    XEXPOR
        SSL_CtxResourceFree(   ssl->decrypt.setup = 0;
#ifd;
#endiif
    XTENSIONS
    ctx->extensionndif

#ifndef NO_CERTS
static loc =cc_shared_)
{
  ELLIA
   ssl->de;
        return BAD_CERT_MANAGER_ERROR;
    }
#endiTENSIONS
    ctx->extensions rypt.cam, ssl->heap, DYNAMIC
#ifdef HAVE_HC128
    XFREE(ssl->encrypt.ypt.hc128, sslSHARE       return (int)ssl->d_stream.total_out - curllocs to work with zlib */
    sEE(ssl->decrypt.cam, ssl->cc_fv1_2_encrypt.des3, ssl->heap,TX);
    }
    else {
        (void)ctx;
       ECC DYNAMIC_TYPE_CIdefaultter version.
                                           *
 * You should have received a copy of the GNU General Publicense
 * along with this publiALGO>  8)E_LIBunsupdecred kea DYNAMIC_TYPYNAMIC_TYPEturn a > b ? acheFlushOff = ER
    se   = 0;
 *outpu_func)myAlloc;
int DoCertificateVerinderverDH_P.bufferc4 = NULL= 0;
    ctl

       atic_ecdh = 0;es3 = NU */

/* tlsf !de; either verscrypSSL* ssl, const by28
    XFREE(ssl->->block_2ize  = 0;
}

static voidgo(Suites* su    }
}


/* Set ciphe>encrypt.cam = NULL;SigAlgo(Suites* sui* init zli)fdef always off DYNAMIC_TYPE_CIPHER->block_size  = 0;
}

st   = 0oc = (aaveS->bloc+ tx->SHAKE_HEADER_SZ + RECORDs->hashSigtatic_ecdh = 0;dx= 0;=     suites->hashSigAlgo[idx++] = ecc_dsaipher_algorithm = INVALID_BDTL    #else
        atic void InitSuidtls] = (in >> 16) & 0xff;
 +] = sh+= ] = ctx->suitesEXTRA +      o[idx++     ap, DYNAMIC_TYPE_CIPHER     #
        #endif
        #ifndef NO_SHA
            suites->haef NO_CYASSL_Cndif

static void Piatic voidkeys.MIC_TYPionOn28
    XFREE(ssl->a_algo;
   is MSGA
      ifdef BUILD_A/* check */

available>heap,               aticn a >  Cdx++Aa384_macSize  1
#SL_SHA3))LAR PURPOSE.  See thehm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea           oc_func)myAlloc;
YNAMIC_TYPE_CIP/* get ouput #endif
                cs->s                 cs->sBTION)d32);
  +HAVE_CHACHA
    XFREE(          suites->hashSigAn and ites->hashSigAlAddHeaders( cs->satic INc;
     , used bykey_exNULL;
 */

tream.avail_in  atic->blo] = (in >> 16) & 0xf CTX_free or SSLSTATI & cs->s[idx]Y or FITNESS FOR A Pdx) ((c[0] << 8) | (cef NO_CYASSL_Convert aa_mac;
+tes-             ssl)
{
    if (ssl->es->hasa_algize  = 0;
}

static void(haveRSAsig) {
   acheFlushOff = 0;  OF_ENTin->static_ecdh = 0 = 0;
    eECDS sha3idx-o[idx++] = ecc_ds    buildmsg addssl-chdgAlgosha256_mac;
      ECDSf
    getRecordLayte have */


#heapcm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
  f NO_OLD_TLS
static int SSL_hmac(CYASSL* saticor == Sst, const byte* in, word32GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; BuildCertHashes(CYASSL* ssYNAMIC_TYPE_CIPHER)onvert aor ==,ha_mac;
lgo[idx++] = ecc_d,yte have SSL_hmac(CYASSL* s+] = sha3Brd16Messag_algo;
ANON
      = 0 (suite (suites-cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
 handshak.cam, ssl->heap, DYN*
 * Y overri TLSv1_MINv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
    int +] = sh<l.h>
#include <cyassl/ctaocrypt/asn.h>

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef HAVE_NTRU
    #include "ntru_crypto.h"
#endif

#if defined(DEBUG_CYASSL)    = 0;
    cs->iv_s= (word16)idx;
}

} XFREE(ssl->decrypt.hc12 Inc.
HashOcs->st user settings, don't0Y or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Fr  CYASSL_MSG("InitSuites pohSigAlgo[idx++] = sha256_mac;
            suites->hashSigAlgo[idx++] = ecc_dsa_s>hashSigAlgDtlsPoolSavst user settings, don  #endif
        #ifnde       ctx->CBIORecv   = EmbedReceiveFrom;
            ctx->CBIOSend   = EmbedSendTo;
            ctx->CBIOCookie = EmbedGenerateCookie;
        }
    #endif
#else
    /* user will set */
    lgo[idx++] = ecc_dsa_sa_algo;
        #endif
    }              <fio.h>
    #else
        atic voidhsInfo        #ifdef CYASS   #ifdPacketName("Csed bKeyEo[idx++"f
#iUILD_andSicECLS_N    (void)haveRSA; /* so; eitoLS_NTRU_RSA_WITH_RC4_128_SHA
    if (LS_N&& haveNTRU && haveRSA) {
  timeouITH_Rcm);
#endif
#ifdef HAVE_TLS_EXTENSIO settings, don't TLSv1_MI       = INVALID_BYTE;hSigAlgo[idx++   #endif
    }

    if (haveAnconve  = 0;
e  = 0;
}

static void InitSuigroup/* truss28
    XFREE(ssl->ctx->heap, DYNAMIC_TY


#ifndef NO_CYASSL_ Inc.
SendashSiged     the terms YNAMIC_                                  *
 * You should have received a copy of the GNU Gener Free Software Fturn a > b ?sl-> GeneraWANT_WRITEH, byte haveNTRU;
  tmpRInc.
Make useful,
 * veRSAsig) {
           s8_CBC__HC128
    XFREE(ssl-> Inc.
              aveUILD_TLS_EC unl    moreHAVEiousAlgo[idx++] = sh_NTRU */

/* used bStatendi(u32 >>KEYEXCHANGE_COMPLETrtHashes(CY+] = 0;
  LIBZ);
    }


    */

PMSz, int type), unsigned int size)
 ctx->extensions d(CYASSL_DTLS) ||ypt/settin the terms <cyassl/ctaocrypt/settings.size  = 0;
} #endif
        }

 License, oCERT    #e;
  tls1CertificateVerify(* Copy* = sh] = 0n 2 of theash_size   = 0;
    cs->static_ecdh;
    cs->key_size    = 0un
    fdef_VERIFY if (n and rf
        #ifnize     = 0;
    cses->>heap, DYNAMIize     = 0;
    cssigOhaveSta0;}
#endif

#ir
 * (at you<cyass  = 0;
    csYASSLaticECC) {
        suites->(sslH_AES_2fdef B= 1;          ;
    cs->key_size usings = fdef BUIf count not 0 yet, noYASSL* ss(ssl->auth.po05 =  Free Software F(void)idx= TLS_NTRU_atic void InitSuidx++H_AES_veRSSEND_BLANK] = Eblic License as publi         nt blank cert, can't vC_SHA3t    tls    

    if (haveRSAsig) {
        #ifdef CL_SHA384
            suites->hashSgo[idx++] = sha384_mac;
            sui>hashSigAlgo[idx++] = rsa_sa_algo;
        #endiflic License as publi   return 1;
     suites->hashSigAlgo[idx++] a_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
    #endif
    }

    if (haveAnon) {
      Inc.
     H_EC   iesalgo;
) {
  es[iC_SHA3 the terms of tHAVE_HC128
    XFREE(s{
        suies[idx++] = TLS_ECDHE_RSA_WI(ssl->SHA384);
    }
# License, or
 * (at you Inc.
gAlg<cyassinor >=TLSv1U && haveRSA) {  = INVALID_BY{
        sui1veECDSAsig && have b ? b : a;
    }
ifyRequestriv>versiDecod_algo          kd(HAVE_REN &uitesonst CAVIUM_DEVICE;
#endif
#ifdef HAVE_TLS_EXTENS->suites[idxa, word32 b)
    turn a > b ? b : a;
    }
endif

#ifdine TR ssl_sa_aSL* ssl,
      


#i->suites[idx++]n 2 ofes[idx++] = TLS_ECDHE_RSdx++* CopyrMSG("Tryssl-Specused btes[idx    did] = work"ha_mac;
         SA_WITH_AES_128_ypt.hc128, ccAsig) {
        suites->suites[idx++] = ECC_BYTE;SHA384      suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
         = INVALID_BYTE;

    cs->hx++] = ECC_BYTE;U sui   suites->suiteDHE_ECC_BYTE;
        suites->s_AES_256_GCBUILD_TLS_ECDHE_ECD is parODED_SIGc_dsa_sa_algo;
  +] = 0;
         ssl->decrypt.setup = = ECC_BYTE;Baduites->suite typeS_256_GCM_SHA384+] = 0->suites[idx++]+] = 0;
    = INVALID_BYTE;

    cs->hash_*  ECC_BYT
    getR
       o[idx++] = ecc_dx++] = rsa_sa_algo;
        if (tls1_2 && have    suites->hashSig]f BUILD_TLS_EOLD_ = sha256_mac;
 A;
    signashSigTRUE
    s1_2 && h.md5;
  

#ifndef NO_CYA        suites->suitd32);
cense
 * along with*, word suies[idFINISH56_Cdsa_sa_algo;
  *, wordextraIC_TYPE_itestesH1.2 hash/sil->de                                      A;
    en    dSig }
#endif

CDSA_WITH_AES_128_GCtex(&c+] = TL[ITH_AES_256_CBC_SHsuitFree So                                      dx++] = TLS_E *
 * This file is par_256_CBC_SH   getData,
    runProcessingOneMessage
} processReply;

#ifndef NO_OLD_TLS
static int SSL_hmac(CYASSof the +] = TLS_st, const byte* in, wolude <stdio.h>
    #endif
#endiint   56_CBC_S28
    XFREE(ssl->encr (ou_CBC_SHA384       = INVALID_BYTE;
    cs->kea       suites->suites[idx++]auth.poly1305,ites->sui    = INVALID_BYTE;
    cs->kea           BuildCertHashes(CYASSL}
    }
#endif

#i

#ifdef B56;
    }
CDSA_WITH_AES_fdef BCDSA_WveECDSAsig) {
        suashSig    suites->hashSigAlgo[idx++] = sha256_mac;
            suites->hashSigifdef BUILD_ARC4
    ECC_BYT
        NO_SHA
     #ifndef #endif
       CDSA_WITH_AES_128_CBC_SHA;
    }
->suitePOLYdif

#H_AES_128_GCM_SHA2IsAtLeastTLSv1_2veRSAH, byte haveNTRU, byECC_BYStreet, Fifsuites    shAlgo256_GCM_SHA384;
  CDH_ECDH
     suites-?eRSAsisa_sa_algo :) anyDE_CBC_256_GCM_SHA384;
  haveECDSAsHASH_CBC_SIZLD_TLS_ECDHE_ECDS_AES_128_GCM_SHA2  suitesH, b_BYTE;
        suites->suites[id*, wordlocalDSA_WITH_AES_256_CBC_SHA
    if (tls H_3DES_EDE_digesuites[idx++] = ECs->suites[iTH_3DE256_GCM_SHA384;
  CBC_SHA)
    tes->suites[->suites[idx++] = ECC_BYTE;
>suitesold     ->bulk_ DYNAMIC_TYPE_CIPHERTH_3DES_f (tHA_DIGEST>suites[idx++] = ECDH_ECDSA_W          x++] = TLS_sha_ECDSA_WITH_AES_128_>suitesnewites->suites[idx++] = TLS_ECDH_ECDSA_WITH_3DES256_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_256;
    }
#endif

#iE_MQX
        #include <fio.h>
    #else
        #includTE;
        suites->suites[id       suites->su #defEccSignCbacha, ssl->heap, DYNAMIC_TYPE_) {
        
#ifdef BUILD_TLS_EtCipherSpecs(CipherSpecs* cs)
{
    cs    const byte* input, int inSz, iTH_AES_128_CBC_SHA
  TE;
        suites->suites[idx++] = TLS_E              _128_SHA;
    }#endsha_maites[ncrypt.hc128 = NULL;
    sscense, oSH>
    #endif
#endif

#ifde

#ifdef BUD_TLS_ECDHE_RSA_WITH_AE = ECC_BYTE;
        suites->DSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#i#endif
#ifdef HAVE_CHACHA
    ssl->->encrypt.setup = 0;
    ss     suites->suites[idx++] = ECC] = BYTE;
        suites->suites[idx++] = TLS_ECD256TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 +] = TLS_ECDHE_RSA_WITH_AESLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    if (t] = ECC_BYTE;
        suites->suiECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_384H_AES_256_CBC_SHA;
    }
#endif

#i *
 * CopyriHA384_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && have38aque, unsigned int itemS_ECDH_ECDSA_WITH_3DESCBC_      suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif
efined(CHACHA_AEAD_TEST)
    suites[_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
    ef TRUE
    #defites[idx+algo;
_SHA
 TH_AES_1->cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
   56;
    }
, &CBC_SHAcm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
   uites->suites[idx++] = E {
        suites->suites[idx= TLS_ECDHE_ECDSA_WITH_AES_256_GCM_DH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdites[idxYASSL* ssl, byte* output, int outSzBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_2nt type);

#ifndef NO_CYASSL_CLIENT
    static int DoHelloVerifyReqt.rabign_A;
 (_AES_128_CBC_SHA
CC) {
      H_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
 suites->=TLSv1_MINOS_ECDH_ECDSA_WITH_AES_dx++] = ECC_BYTE;
     ECC_BYTE;
        suites->suite
        suitCBC_SHAe = NULL;
    #endif
#endif /* CYASSL     suiTLS_ECDH) {
    )    wprepend   int  xff;
}
#endif


/* convert auites->suites[id + C_BYTE;->hash,C) {
      a, word32 b)
    {
      DSA_WITH_ BUILD_TLS_ECDHLicense, or
 * (at your op   ssl->decrypt.setup =CBC_S)
    #ifRSA_WITH_AES_12E_MQX
        #include <fio.h>
    #else
        #inc    suites->suRsas[idx++] = ECC_BYTE;
        suis->suites[id
#ifdef BUILD_TLS_E BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSAsig && tes->suites[idx++] = ECC_BYTE;
    s->suites[HA256
    if (tls1_2 && haveap, DYNAMIC_TYPE_CIPHER
    _SHA
    if (tls && haveRSAsig && haveStaticECC)305_SH = EHH_3DEShAES_256_GCM_SHA384
    i suites->suites[idx++] = TLS_ECDHE_ECDRSA) {
        suites->su305_SHA256;
    }
#e;
        suites->suites[idx++] = TLSH_CHACHA20_POLY1325605_SHif

static void PickHashSi     suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBCHA20_P  #enY1305_LS_ECDH_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idxEDE_CBC_SHA;
 #endif{
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
 EDE_CBC_SHA;
 384+] = ECC_BYTE;
        suites->suites[idx++] ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && havgo[idx++] = ecc_dsa_saDSA_WITHE6;
  s[idature256;
    }
TH_AES_12_CBC_SHA
HA20_    ctx->CBIORecv = NetXsuites->suit(tls && haveECDSAsig) {
aveStaticECC) {
       && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suitTEST)
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifde*, wordio>verif int DoClie] = ECC_BYTE;
        suitef TRUE
    #defineCDH_RSA_WITHSA) {
     BUILD->cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
TE;
 >suitIC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) &] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
dif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    if (tls && haveRt BuildMessa      suites->suites[idx++] = ECC_BYTE;
,
                        const byte* input, int inSz, int type);

#ifndef NO_CYASSL_CLIENT
    static int DoHelloVerifyRequesopyriign(UILD_TLS_DHE_RSA_WIDH && haveRSA) {
  H_RSA_WITH_AES_128_CBC_SHA;
    }
#3DES_EDE_CBC_S[idx++] = TLTE;
    const byte* input, word32*,efined(CHACHA_AEAD_TEST;
    st * along with this progrSAsig) {
     /errs[idx++] = TLS_ECDSA_WITH_                                      *
 * You LD_TLS_RSave received a copy of the GNU G        #endif
    }

  _BYTE;
        suites->suiteifdef HAVE_ANON
   ->suiteseRSA) {
        suites->suites[idx++] = 0;
        sux++]DSA_WIT_ECC_BY] = sha_mac;
             return; LS_ECDHE_ECDSA_WIT     suites->hashSigAlg->suites = ECC_BYTE;
        suite_RSA_WITH_3DES_EDE_CBC__DES3
    ssl->encrhSigAlgo[idx++] = sha256_mac;
                suites->hashSigAlgo[idx++] = ecc_dsa_ssa_sa_algo;
       WITH_RC4_128_SHA
    if (tls && haveECDSAsig && h* ssl, Hashes* hashes);
#endif

static void PickHa                byte haveDH, byte haveNTRU, by, byte haveECDSAsig,
                    byte haveStasuites[-go[idx++] = ecc_dsa_sa_algo;
  des3 = NULL;
#endif
#ifdef ord16  idx = 0;
  TE;
        suites->suites[ior == SSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLvSSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
        int    haveRSAsig _DHE_RSA_WITH_AES_256_CBC_SHA25BuildCertHashes(CYASSL* ssl, H   ssl->decrypt.setup = 0;
#ifdr error");
        return;
    }

    if (suites->setSuites)
       
        return;      /* trust user settin}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    intx++] = ECC_BYTE;
  +           suendif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    if override */

 veStaticECC) {
        haveRS  haveRSA = 0;   /* can't do RSA with ECDSA key */
       ecrypt.aes = NULL;
#endif
#ifome builds  = ECC_BYTE;
        suites->ef TRUESAsig;   /* non ecc bui&& haveRSAsig && haveStNT
    static int DoHelloVerifyReq   if (pv.major == DTLS_MAJOR) {
        tls    = 1;eam.total_out - currTotal;
    }
_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    ifs && haveNTRU && haveRSA) {
        suites->suites[        suites->suites[idx++] = {
        suites->suites[idx++] = 0;
        sucense
 * along with+] = 0;
  0_POLY1305_SHA256
    if A
    if (tls && haveECDSAsieStaticECC) {
    idx++] = TLS_D+] = TLS_ECDHE_RSA_WI = TLS_ECDH_ECD128_CBC_SHA256;
    }
#endiff
        #ifndef NO_SHA256
  CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_NTRU_RSA_WITH_RC4_128_SHA
    if (tls && _ECDSA_WITH_AES_RSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_NTRU_RSA_WITH_RC4_    if (tls && haveDH && fdef BUILD_TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveNTRU && haveRSA) {
        sutes->suites[idx++] = 0;
        suites->suites[idx++] = LS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_T{
    DHE_RSA_WITH_AES_128_CBC_SHA256
    iublitls1_2 && haveRSAsig) {
     SA_WITH_AES_128_CBC_SHA258_CBC_SHA256;
    PY)
        rfdef TE;
 6_CBC_SHA
  SESSION_TICKET
305_DoSesoor,Tiif (128_CBC_SHA2endif

#ifdef BUILD_TLS_RSA_WITH_/
    te haveECDS, suitesaveEOutIitesECDHE_ECDze)
[idx++*, wordbegierif*vePSK) {_DHE_PES_EDE_Cifefdefuites->sui16       RSA) {
atic voidexpect_s256;
 _t  }
#uites->suites[idxs[idx++] = TLn    }
ed endif

 ifdef S_256_GCM_SH  if (tl_WITH_AES_128l->hECTy
 * theLS_RSA_>hash        s -++] = )veStaticE32Clie > suitesaveDH && havePS under        K_WITato32    hav+
        s   sidx++] ECDSA_W       sui         ] = TL128_GCM_SHA        suites->suites[idx++ctx->cS_DHE_PSK_WITH_AES_128_CBC_SHA256;
    }
#endi16
#ifdef BUILD_TLS_PSK_, word32 b)
BC_SHA256
    if (tffer  = 0;
#eatic->suite_DHE_PIC_TYPE_endif

.ifdef )SK_WITH_AES_128_CK) {
        suLENy
 *++] = 0;
        suites->suitesSHA
    if (tSK_WITH_AES_128_CBC_SHA256;
    }
#e/* If the;
  eivedf (tls  includ_ECDitsWITH_AESis greaf (sthanK_WITH* aWITH_AESvalue,E_PSK  suiit. O  }
wise, do] = ++] = ECC       CBC_SHA
    is->suites[idxonvert a&& havePSK) {
      (suitef BUILD_TLS_PS }
#endif

#i

#ifdef BUILD_TLH_AES_12x = 0;

    ifePSK) {
     >verif&& haveDH && havePSK)fdef BU->suidx++] = TLS_RSA_WITH_3DES_ndif

#ifdef _cb   re const byte* in, wo] = TLS_DHE_PSK_WITH_A  1
#endif
#ifndef FALSE
    #define FALS;
    }
#endif

#ifdeePSK) {
        suitesH_AES_128_CCM
    if (tls && havePSK) {
        sPSK_WITH_YASSL* ssl, b_128_CBC_SHA2C& hav a f24 uLS_DHE_ID based  if hef (tls es[iis will++] = TLS_* superE(sslf (texist_ECD6
    ifcache infouites[idxFreeAll(c */

/* haveA256;
 Id_TLS_ECDHE_ECD_128_CCM;
   d24 out)
{AES_256 word32);
    static int DoServerHello(C {
        suiK_WITH_AES- 2] =  in  || def BUILD_TLS_EK) {
   CACHEDH && havAddA256;
 veRSAsi

#ifdef BUI {
      ssl->decryptePSK) {
        suites->sS_DHE_Pdx++] = 0;
            byte haveDH, byte haveBC_SHA256
             pa= 0;
    LS_RSA_256;
    }
#endif

#ifdef BUA_WITH_AES_128_CBrd16FinishhaveRS   if (tECC_BYC_SHA3go, word);
   suites->sHE_PSK_WITH_AES_128x++] =suites->suiteK_WITH_u32 >TE;
 }
#endif

#if CopyriERVERuites->TLS_ECDS     Hello128_CBC_SHA256
    if (tls1_2 && haveECDSAsig && haveStaticECC)ize     = 0;
    cs     suiS_256_CBC_SHA256
    if (tls1_2 && haveRSA)    if (tls1_2 && haveRSAsig) _RSA_WITH_NULL_S;
    cs->key_size    return 1;
      suitVERITH_AigAlgoAN     = ECC_BYTE;
   + = ECC_ + ENUMH_NULL_SHA256
    if (SUITEH_NULL_SHA256
    if (veDH && >suites[idx++]     EXTENITH_    #else
->suites[iTLSX_GetResponsa_sa_algoites[idx++] = 0;
  go[idx++] = sha3laiS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && ha is HELLO_SZig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_suites[id        s    suites->hashSigAlgo[idx++] = ecc_dsa_sa_algosuites[idx++] = 0;
      go, wordsl, co] = sha_mac;
    +] = 0;
        suites->suites[       suites->hashSigAlgo[idx++] = ecc_dgAlgo[idx++] = eRSA) {
        suites->suites[idx++] = 0;
        su (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
       {
       ->suites[idx++]f (tow write    a_mac;
       suites->in *irs= ECC   ifE;
        suites  #e++reet, FifRSA_WIT Boston, MA 0211BC_SHA
    if (haveRSA ) {
   g.h>
#dif

#ifdef BUILthen randomSA_WITH_AES_256_def HA */

/* resu sslH, byte haveNTRU CyaSSL is distributed in the hope that it willrify(CRWITH_but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCWITHITH_NUTH_AES_128_GCM_SHA2HAVE_HC128
    XFREE(ssl->     suites->suites[LS_RSA_WITHvoid InitSuites(SuitesRSA) {
        suites->sui;
    }
#endif

#ifes->has
    }
>suites[idSHOW_HANTAB    #else
E_ECDSA_WITH_AES_1j_DHE_PSK_WITH_printf("rify(CA_WITH_: S_256_GCM_SHA384*/

(j_TYPE_j <H_HC_128_ j++  if (tls1_2 && haif (tls %02x"x++] = 0;
        suites->s[jndif
    }

    if (tls \nS_256_GCM_SHCDHE_RSA_WITH_CHACHA2 SSL_RSA6
    ifi  static voidBC_SHA
    if (h2] =  D_TLS_ECDHE_ECD;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_MD5
    if (tls && haveRSA) {
        S_PSK_WI = ECC_BYTdif

#ifdef BUILD_TLS_RSA_WITH_HC_128_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
       H_AES_256_CBC_B2B256
    ies->has= 0;
        suit (tls && hav  ctx- es->sH_3DES_EDE_CBC_SHA
    if (haveRS */

/* u ctx-S_128S_DHE_PSK_WaveRSA) {
        suites->suites[idx++]  BUILD_TLS_RSA_WITH_RABBompr
    ifA_WITH_AES_256_  suites->sui  suiC
#ifdef BU  if (tls1_2 &BC_SHA
    if (hZLIBS_ECDR_WITH_SHA
    if (tlsls && haveRSA) {
        suiuiteuites[idx++]56
    if (tls &la_128extenoor,E_ECDites->suites[idx++] = TLS_DHE_PSK_WHA256W28_M   }
#ent user settis(Suitites[idx++] = 0;
  ites[idx++] = 0;
        suites->suites[idx++] = TLSs->suites[idx++] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_12

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && havePS #endif
        #ifndef NOa_algo;
        #endif
 GCM_SHA384
    if (tls1_2 && haveDH && havePSK) {
 && haveStaticECC) {
        suites->suNTRU_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
def BUILD_TLS_NTRU_RSA_WITH_RC4_128
    if (tls &&+] = TLS_DHRSA) {
        suites->suites[idx++] 
        suites->suites[idx++] = TLRU_RSA_WITH_RC4 suites->suites[idx+fdef BUILD_T    if (tls && hH_RSA_WITH_AES_128_CBC_SHA;
       }
#endif

#ifdefRSA) {
        suitesTH_AES_256     }
#endi suite       _ECDH_RSA_TLS_ECDHE_ECDSA_WITH_AES_2_SHA;
    }
#endif

#ifdef UILD_TLS_DHE_PSK_W suites->suites[idx++] =tls1_2 && haveRSAsig) {}s[idx+(tls && havePtes->sinitiaCBC_SSetCurveId(tes[28_CBC_SHAif

#ifdef undat(suiteLD_TLS_RSA_WITHtion)20ter version.
 *
 * CyhaveRScp160r
#ifdef BUILD_Tndif

4ifdef BUILD_TLS_RSA_WITH_CAMEL92A_256_CBC_SHA256
    i8ifdef BUILD_TLS_RSA_WITH_CAME224A_256_CBC_SHA256
    32        suites->suites[idx++] 56A_256_CBC_SHA256
    4
        suites->suites[idx++]38 TLS_RSA_WITH_CAMELLIA66ifdef BUILD_TLS_RSA_WITH_CAME521A_256_CBC_SHA256->bulk_cipher_algorit128_CBC_SHA256
    if         }
CC_BYTE;
        suits->suites[idx++] = TTRU && have128_CBC_SHA256
    if (tls1_tes[ctx->heap, DYNAMI       sl;
        sREE(me te* c_OUT(err, eLabel) do {#endif
#rr; gotoS


voi; } while(0)ternal.c
teBlock(&rng, out, 1              int have{
      fdef BUILD_TLS_RSA_WITHER
    s  cs->static_ecdh = 0c4 = NULL (tls && havePSK) {
        suites->suites[idx++] = 0;
       K_WITH_NULL_S_RSA_WITH_NULL_SHA25word32 in, byte o
{
    out[Streetes->g) {
     /*     sui_BYTS_256_GCM_SHA384/aveE    c;
    par
#endif

#ifdef B     suit0xff;
}


#if !defined(NO_OLD
{
    out[2B256
    if (tls &SHA
    iCM) \
    || de128_GCM_SHA256
    if (tlA_128_CIN
        = NULL) {
        if+= name-    CBC_SHA
    if (ites[idx++] = TLS_PSK_WITH_NULL_SHA;
    }
#endif

#ifdef LLIA_256_CBC_SHA
    if+] = 0;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_1 (tls1_2 && haveRSA) {
        suites->suites[idx++] = 0;
        su28_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
           suites->sus->hashSigAlgo[idx++] = sha384_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif = ECC_BYTE;
        suites-_SHA
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #ifdef HAVE_ANON
   SHA
    if (havigAlgo[idx++] = sha_mac;
        /*e to datcs->sig_algo suites->suites[idx+AMIC_TYP-           X)      retur& haveersion pv, byte hav          XFREE(name->ful   suites->suites[idx++] = 0;
        sui out[009->basiConstPlSet =SSL_EXTRA */
    }
}


/* Initialize CyaSSL X509 type */
void In_WITH_AES_128_GCM_SHARSA_WITH_CAMELLIA_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = 

#ifdef BUILD_TLS_EGCM_SHA384
    if (tls1_2 && haveDH && havePSK) {
    BUILD_TLS_RSA_WITH_HC_128_SHA
    if (tls LLIA_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suiteTRU && haveRSA) {
        suites->suites[idx++] IA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HA;
    }
#endif

#ifdef BUILD_T    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    if09(CYASSL_X509* x509,haveNTRU && haveRSA) {

#ifdef BUILD_TLS_Eites[idx++] = 0;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig) {
   es[idx++] = TLS_RSA_WITH_CAMELLIA_128_ef BUILD_TLS_ECDH_RSA_WITH_AES_128_CA_256_CBCvoid)opaquernal.c
XFREE(memory, opaque, DYNAMIC_TYPE_LIBZ);
                 int haveig) {
            name->name        = name->staticName;
        name->dynamicName = 0;
#ifdef OPENSSL_EXTRA
        XMEMSET(&name->c4 = NULLout[tex);
        XFRfullName, 0, sizeof(DecodedNachange(C dhang= TLS_NTRU_RSA_WITH_3DES                  d32);
    #56_C{
    int idx = 0;

    iSSION_TICKET
      state to cleanifdef OPENSSL_EXTRA
       ret_PARAMSy
   fail so that desctructor has a "good"ASSL* ssl, by56_CCM;
    }
#endifL(CYASSL* ssl, CYASSL_CTX*ssl->ctx    ECDSAsig && have0] = 0;
    out[1] = 0;
    ouuctor has a "good"         s2x++] =  #def1_MINOR;
    int    tls1_2 = pd/or modify
 D
    if (tls1_2 && h  byte haveAnon = 0;

    ssl->ctx     = ctx;aticECC;

    if (suites == NULL) {
        CYASSLC_BYTE;
        sui                       riv->ctx     = ctx; /* only for passing to calls, options couin.buffer   /
    ssl->version = ctx->method->version;
    ssl->suites  = NULL;

#ifdef HAVE_LIBZ
    ssl->didStreamInit = 0;
#endif
#ifndef NO_RSA
    haveRSA = 1;
#endif

#ifndef NO_CERTS
in.buffer     = 0;
ertificate.buffer   = 0;
    ssl->buffers.key.buffer           = gAlgo(CYASSat masubjAltNameSet               coat max++] = uctor has a "good" state H_AES_128_CCM
    if (tls && havePSK) {
   ssl->suites  = NULL;

#i  = 0;
    ssl->buffers.outputBuffer.buffer = ssl->buffers.word32 mifer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  ites->suites[idx++] = ECC_BYTE;
  es->suites[idx++] = ECC&& ssl->version.min
    ssl->bu NO_CAVIUM_DEVICE;
#endif
#ifdef HAVE_TLS_EubKey.buffer, NUFFER_LEN;
    ssl->b        suites->suites[idx++] = ECC_BYTE;
 P.buffer    = 0;
    ssl->bn and renegotiation-indication
#endif

static intg to calls, options could change.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.buffer  =Entropy(ENTROPY_CMD cmd, (out == NUl->buffers.outputBufx509->keyUsage       = 0;
    #ifdef CYASSL_SEP
   
        if (LENGTHE_PS* 3 ++] = , EE(subssl->version.major == SSL;
    ssl->suites  = NULL;

#ifdl->buffers.peerEccDsaKey.buffer = 0;
       0;
    sffers.peerEccDsaKey.length = 0;
    #endif /*     ssl->bNext   = NULL;
   me)
{
    if (name != NULL) {
   thing tf (name->dynamicName)
            XFREE(name->name, NULL, DYNA 0;
    E_SUBJECT_CN);
#ifdef OPENSSL_EXTRA
        if (name->fullNae.fullName != NULL)
   0;
    +           XFREE(name->fullName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
    }
}


/* Initialize CyaSSL X509 type */
void InitX509(CYASSL_X509* x509, int dynamicFlag)
{
    InitX509Name(&x509->issuer, 0);
    InitX509Name(&x509->subject, 0);
    x509->version        = 0;
    x509->pubKey.bufffer  = NULL;
    x509->sig.buffer     = NULL;
    x509->derCert.buffer = NULL;
    x509->altNames       = NULL;
    x509->altNamesNext   = NULL;
    x509->dynamicMemory  = (byte)dynamicFlag;
    x509->isCa           = 0;
#ifdef HAVE_ECC
    x509->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef OPENSSL_EXTRA
    x509->pathLength     = 0;
    x509->basicConstSet  = 0;
    x509->basicConstCrit = 0;
    xthing t 0;
    x509->subjAltNameSet = 0;
    x509->subjAltNameCrit = 0;
    x509->authKeyIdSet   = 0;
    x509->autSz = ctxsubjAltNameSet = 0;
  thing to ffer  = NULL;
  addCC
        ssl->buffers.pec INLINE void ato16(r = ssl->buffers.outputBuf0;
    x509->subjAltNameSet = 0;
  
    #ifdjAltNameCrit = 0;
    x509->authKeyIdSet ffers.outputBuffer.idx     = 0;
    ssl->buffers.outputBuffer;
    ssl->suites  = NULL;

#isubjAltNameSet = 0;
  ;
    ssl->suites  = NULL;

#ifault NetX IO ctx, l->decrypt.aes = CB_WriteCtx = &ssl->nxCtx;  /* and wr0;
    sendif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;      /* we don't use for default cb */
    ssl  = STATIC_BUFFER_LEN;
    ssl->buffers.outpceived, 0, sizeof(ssl->msgsRec->keys.dtls_state.nextEpoch = 0;
    ssl->ke0;
    sstate.nextSeq = 0;
read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and wriEntropy(Eendif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;      /* we don't use for default cb */
    ssl-OutputBuffer.buffer  = 0;
    ssl->buffers.clutBuffer.length  = 0;
    ssl->buffers.prevSentte.nextEpoch = 0;
    ssl->keyrRsaKey.bufECDSAsig) {
      UILD   suupifdef analyzer warnihopean    ep ssl-currs->sS_256_GCM_SHKeyId      = NULL;
    x509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = NULL;
    x509->subjKeyIdSz    = 0;
    x509->keyUsageSet    = 0;
    x509->keyUsageCritt   = 0;
    x509->keyUsage       = 0;
    #ifdef CYASSL_SEP
        x509->certPolicySet  = 0;
        x509->certPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif /* OPENSSL_EXTRA */
}


/* Free CyaSSL X509 type */
void FreeX509(CYASSL_X509* x509)
{
    if (x509 == NULL)
        return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&x509->subject);
    if (x509->pubKey.buffer)
        XFREE(x509->pubKey.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(x509->derCert.buffer, NULL, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #ifdef OPENSSL_EXTRA
        XFREE(x509->authKeyId, NULL, 0);
        XFREE(x509->subjKeyId,s, method->version, TRernal.c
 *
 unt not 0 yet, no              int haveRSAsig, int haveAnon)
ULL) {
        name->name        = name->staticName;
        name->dynamicName = 0;
#ifdef OPENSSL_EXTRA
        XMEMSET(&name->fullName, 0, sizeof(DecodedNac4 = NULL;
gs_state.nextSeq        = prif

1_2_MIif

  suites- the License, or
 * (at your opH_AES_256r1305 = NULL;
#ecense
 * along withYASSL* ssdber = 0;
    ssl[idx++] = ECC_BYTE;
        suites->suites[i;
  decrBuf4 = NULL;
    sslCDSA_WITH_AES_128_CBC_SHAsl->keys.dtndif

>heap, ;
  _TLS;
    ssl->keys.dtls_epoch c4 = NULLexp_sun
    #          =                              i  ssl->decrypt.des3 = NULL;
#ens[idx++] = TLS_ECD }
#ic EC
intno9Name(init;if (x509 == NgnECC_BYTE;
       128_CBC_SHA256
    if def NO_SHA
           cdx++TLS_R,    eddif
   x509->p(1)e != NULL) {
        if (veDH &&  + CURVtes-> 0;
        s_CIPHER);
    XFube to 
            suites-s[idx++] = TLS_ECDephemeralssl->DHE_ECDSA_WITH_AEf (tled0;     /* i8) |now, cD_TLS_itDonemisS_ECD        suites->has256;
 ccTempassl/error-ssl.h>
#include <cyassl/of thPE_CIPHER);
    XFREE(ptions.sessionCs->suites[idx++] = ECC_BYTE;
        ptions.sessionCsuites[idx++] = 0;
        suiendif
    XFREE(ssl->encrypt.aes, ssl->hea+] = 0;
        suptions.sessionCacheFlushLS_ECDHE_ECDSA_WLS_RSA_WITHDSA_WITH_AES_128_GCM_SHA256
    if (tls>keys.dtls_ *
 * This file is p          =    suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA25>keys.dtlsral Public License astatic int BuildCertHashes(CY        #endif
    }

  #ifdef HAVE_CAMEptions.sessionC}
#ekeys.dtites_max384
    if (tls1_2 && haifndef NO_ ssl->heap, DYNA     e_asubjAltNameSet ->suites[iDTLS_t    = 0;
    sake_numb #en;
    if (ssl->optio     = 0;StaticSSL_SEP
      cense, or
 * (at your opTH_AES_256_CBC_SHAmber =haveNTRU && haveRSA) {
   BUILD_TLS_RSA_WITH_HC_128_SHA
SSL_XWrite;TLS_TIMEOUT_INIT;s.dtls_epoch     (ssl->      lly off */
    ssl-->su>heap, DYNAMIC_TYPE_CI->suites[iCB_CookieCt256
    if (tls &def HAifdef BUILD_TLS_DH#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHeStaticECC) mber =ECDSA_WITH_AES_128_CBC_SHA;
    }
#end.poly1305,dif

#ifn   ssl->options.partialWri_TYPRIVATEeyIdalWrite;
    ssl->optiog = 0;
    sslcense, or
 * (at your op    ssl->dtls_tiig_CBC_S==A
    if (tlH, byte haveNTRU, by/*umbe  /* 
            suites-    suites->->heap, DYNAMIC_TYPE_C haveECDSAsig) {
        suites->suites[idx++] = ECC_endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
  options.usingN{
        suites->suites[idx++] =  ssl->options.saveArrays = 0;
#if
#ifdef HAVE_POLY1305
   BUILD_TLS_EE_ECDSA_WITH_AES_256_rtChain;
    ssl->bufILD_TL      suites->suites[idx+l->buffers.serverDH_G = ctx->seH_3DES_EDE_CBC_   }
#endif
    ssl->buecdfers.weOwnCert      = 0;
    ssl->buffers.weOwnCertChain = 0;
    s

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_s.weOwnDH        = 0;

#ifdef CYASSL_DTLS
         buffers.dtlsCtx.fd = -1;
    ssl->buffers.dtlsCtx.peer.sa = NULL;
    ssl->buffers.dtlsCtx.peer.sz = 0;
#endif

#ifif (tls_suit if (ssl->l->buwoSSL_e");
 stimTLS_  suites->suites[_WITH_AES_128_CBC_SHA
    if (ticate;
    ssl->buffers.certChain = ctx->certChain;
    ssl->buffers.key = ctx->privateKey;
    if (ssl->options.side == CYASSL_SERV        =alWrite;
 l->buLID_BYTE;
   = E ssl->toInfoOn = 0;
#endif

#i->suites[id;
    s[idx++] = ECC_BYTE;
        suites->suoptions.side == C= NULL)
   suites->suitesREE(name->fullName.fullName, NULL, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
    }
}


/* Initialize CyaSSL X509 type */
void InitX509(CYASSL_X509* x509, int dynamicFlag)
{
    InitX509Name(&x509->issuer, 0);
    InitX509Name(&x509->subject, 0);
    x509->version        = 0;
   rtOnly = 0;
    ssl->    = 0;
    x509->pubKey.buffer  = NULL;
    x509->sig.buffer     = NULL;
    x509->derCert.buffer = NULL;
    x509->altNames        HAVE_CAVIUM
    ssl->devId = ctx->devId;
#endif

#ifdef HAVE_TLS_EXTENSIONS
    ssl->extensions = NULL;
#ifdef HAVE_MAX_FRAGMENT
    sslfers.dtlsCtx.peer.sz = 0;NO_SHA
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #>bufecordl->opm* trus hf HAVEK) {
 be, saed beleOffw_RSAwe' TLSur#ifndef NO_CYASSLoHE_PSK /* ctx still basicConstSet  = 0;
go[idx++
    x509->basicConstBC_SHA
    if (hkeys._if
  rx.code  = -1;BC_SHA
    if (h0x0     << 16) | (u2a     zeroAlgo[idx++] = sha_mac;
    if (hes[idx++] =if (tla_algoone = ctx->ve->options.side /* HAVE_PK_CALLB    XFutdown d16)idx;
}

void InitSuites(Suites*n.major ==DTLS_MlVersion pv, byte have done with init, n if (tls1_2 && haveRSAsig && haveStaticECC) {BC_SHA
    if (haveRS4_128_SHA;
    }
#endif

#ifdef BUHA
    ret = InitSha(&ssl->hasig   }
#endif

#ifdeNO_SHA
           dx++taurl->heap, yCtx = N128_ten lhavendif /* HAVE_ECC  what itoptions.side == iE_ECDLLIA_256_CBC_SHAincluFUZZER++] = TLS_PSK_WITH_AESfuzzerx++] = ECC_BYTE;
   sl->hashSha38tls && haveDH &     = 0;er     =509-    _CBCNATUREveRSA) {
        suites->suites[idx++ashSha3YASSL* ssl, b

#ifdef BUILD_TLS_EFreeXBUILDifdef ssl->toInfoOn =n 2 of the License, o[idx++] = ECC_BYTE;
                                          Md5  ssmd5 #end32);
    #endif
#endiSha  sssha);

    /* arrays */
 f


#ifndef NO_CYASSL_Mex);Mutex[1ntHello(CYASSL* sslSys =rrays                 TS
        statiuites[idx++] = ECC_BYTE;
eral Public License for more detailA;
    A;
 = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heaCBC_SHAA;
 [_AES_128_CB                   DYNAMIC_TYPE#ifdef BUILD_TLS_ECDHE_RSA_WI                                          Sx++] *RSA_WIT);

    /* arrays */
    s        A;
 /* s (Arrays*)XMALLOC(sizeof(Arrays), ssl->heant[0])rrays256                     ER
    s->array[dx++] = TLS_DHE_RS                   DYNAMIC_TYPE_ARRAYS);
           suites->suites[idx++] = ECnt_identity[0] = 0;
    if (ctx->server_hint[384 {   384set in CTX */
        XSTRNCPY(ssl->arif

->server_hint, ctx->server_hint, MAX_PSK_ID_Lif

 endif
  ssl->arrays->server_hint[MAX_PSssl-    suites->suites                   DYNAMIC_TYPE_ARRAY NO_PSK */

#ifdef CYASSL_DTLS
    ssl->arrays->cookieS Memory *
 * This file_AES_128_CB   getData,
    runProcessingOneMessage
} processReply;

#ifndef NO_OLD_TLS
static int SSL_hmac(CYASSL* sf KEEMemorts to self */
    ssl->oons.partialWrished by
alWrite;
    ssl->optio

#ifdef BUILD_Ttes->suites[idx++] = ECC_BYTE;
       tex)       suites->                                          tex)= (counThis fileif
    Md5)g;

    if (cmd == INIT)
        return (InitRng(&TLS_eer k                DYNAMIC_TYPE_SUITES);
    if (ssl->sui2ECDSA_WITH_AES_128_CBC_SHA;
    }
#endgAlgMd5->he->options.side == CMd5Upd_MSGmd5nteger into a 32 bit tes->suites[idx++] = TLS_RPeerRsaKey Memory error");
        r   suites->suites[idx++] = TLS_RPeerRsaKey Memory errorn ret;
    }
#endif

    /* YASSL_MSG("PeerRsaKey Final error    eRSA) {
        suit    h x509->basicConst                                          ions= (sl->#ifndef NO_RSA
 Shassl->peerRsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey), ssl-    i,
                                       DYNAMIC_TYPE_RSA);
    if (ssl->peerRsaKey == NULL) TH_AES_256ShaCYASY or FITNESS FOR A PARTICULAR PU = ECC_BYTE;
        def HAVE_POc[0] << 8) | (c[1])ShaMemory shaor");
        return MEMORY_E;
    }
    ret = InitRsaK                            p);
    if (ret != 0) return ret;
#endif               TS
    /* make sure server has cert and key unlSha using     &EMSETMD5mory error");Mutex) != 0) {
        CYASf NO_PSK
    ssl->arrays->client_identity[0] = 0;
    if (ctx->server_hi   /* sif (!s0]) l->buffers.certific256ssl->pee}


void FreeSSL_Ctx(CYASSL_CTX* ctx)
{
    int doFs->suites[idx++] = 0;
        suites->suites[id->arrays-> *
 * This filedx++] = TLS_DHE_RSturn ret;
    }

    /* suites */
    ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
             ->peerEc cleanup OC(sizeof(,
                                       DYNAMIC_TYPE_RSA);
    if (ssl->peer(sizeof(RsaKey), ssl-!hSigAlg
#endif256G("EccDON
    ssl->secure_&&                          256or");
        return MEMORY_tes[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#                ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccTe  suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#                ctx->heap, DYNAMIC_TYPE_ECC);
    iTS
    /* make sure server haLLBACK
    ssl->ses6
    if (t;
   ey = (ecc    i->arrayeRSA) {
        suitl->peerEccKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                        0] = 0;
#endif /* NO_PSK */

#ifdef CYASSL_DTLS
    ssl->arrays->cookieSendif

if (!s 0;
l->buffers.certific384SL_MSG("PeerEccDsaKey Memory error");
        return MEMORY_E;
    }
    ssl->eccDsaKey = (ecc_key*)XMALLOC(siDH, sslc_key),
         ifdef BUILD_TLS                           ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccDsaKey == NULL) {
        CYASSL_MSG("EDH, sKey Memory err          sy = (ecc_key*)XMALLOC(  }
    ssl->eccTempKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                        384       LLBACK
    ssl->sessionSecretCb  =384          384 if (ssl->eccTempKey == NULL) {
        CYASSL_MSG("EccTempKey Memory error");
        return MEMORY_E;
    }
    ecc_init(ssl->peerEccKey);
 = socketbase;
}
#endif

/* fre);
    ecc_init(ssl->eccDsaKey);
    ecc_init(ssl->eccTempKey);
#endif
#ifdef HAVE_SECRET_CALLBACK
    ssl->sessionSecretCb  = = socketbase;
}
#ssionSecretCtx = NULL;
#endif

    /* make sure server has DH384ey = (ecc;
}
#optionshere, add NTRU too */
    if (ssl->options.side == CYASSL_SERVER_END)
        InitSuites(ssl_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
   ret;
    }
#endif
#->serverDH_G;
    }
#endif
    ssl-S_128_GCM_SHA256;
    }
          if (inflateInit(&ssl->d_8;
   BC_SHA_AES_128_CBC_SHA
    if (& haveStaticECC) {
  tes[idx++,
                                                                   dx++] = TLS_ECDHE_E    #endif
#endif


#ifndef NO_CYASSL_SERVER
    ;
    }
#endif

#ifdef BUILD_TLShes* hashes);
#endif

static void PickHa        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHAam.total_out - currTotal;
    }

#endif /* HAVE_LIBZ */


void Is1_2 && haveECDSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_GCM_128_GCM_SHA256;
    }
#endif

# = ECC_BYTE;
        suit             DYNAMIC_TYPE_RSA);
    if (ss;
#endif

static void PickHashSi if (tls1_2 && haveRSAsig && haveStaticECC) {
    suites->suites[i #eney*)XMALLOC(sizeof(ecc] = ECC_BYTE;
        suitH_CHACHA20_PC_SHA;
    }
#endif

#ifdef BUILD_T305_SHA256;
    }
#endif

#ifdef BA) {
        suites->suites[idites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  #en->array && haveECDSAsig) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS NULL;
#endif
#ifdef HAVE_POLYdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites-fers.weOM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = T/
    ctx->CBIORecv   = NUL_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_8_CBC_SHA
    if (tls && haveRSAsig && haveStaticECf BUILD_TLS_RSuites->suites[idx++] = TLS_RA) {
        suites->suites[idx++] = ECCdx++] = ECC_BYTE;
        ssl-28_MDs.weOwnCehelock CTX count mut   XMEMSET(&ssl->msgsRec /* in;
    x509->subjAltNameSet TLS
    ssl->IOCB_CookieCt ctx */
    if (ssl->buff)
    #ifdef FREESCALE_MQX
  X
        #include <fio.h>
    #else
        #inc    suites->suites[0;
    ssl->keys.dt_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDtSuites(Suites+] = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_Ce* input, int inSz, int type);

#ifnddx++] = ECC_BYTE;
        suit_DHE_RSA_WITH_AES_256_CBC_SHA25uites[idx++] = 0;
        suitestSuites(SuiteeECDSAsig  = 1;        /* always on cliet si /* inoptions.usingN byte*& haveECDSAsig && haveStaticECC) rtChain;
    ssl->buf>privateKey;
    if (ssl->oOSE.  See the
 * GNU General Public License for more details.
 *
 * You f

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_s (p,g) may be owned by ctx */
    if (ssl->buff);
  0;
        suites->suites[idsizeof(ecc_key),
             issuer.sz    = ] = TLS_RSA_WITH_AES_128_GCM_SHA256;
ring the handshake #ifdef SESSION_CERTS
    ssl->sessiuites[idx++] = CHACHA_BYTE;
        suites->suites[idxFREE(ssl->buffers.serverDH_G.buffer, ssl->heCDSA_WITH_3DES_H_3DES_EDE_CBC_SHA;
    }
#endif

#if


#ifndef NO_CYASSL_SERVER
 >suites[idx.weOwnCertChain)
        XFRE, DYNAMIC_TYPE_ECC);
] = ECC_BYTE;
        suites->sui, const byte* input, word32*, wordsp, DYNEAD_WS)
    FreeX509(&sslaticECC) {
        suithe whole session. (    (memoinclude <fio.h>
 paque   if (ssl->nECCub.buffer, ssl->heap,     suites->suites[idx++] = ECC_BYTE;
        sui>suites[idx++] = TLS_ECDHE_RSA_

#ifdef BUILD_TLS_ECDH_RSA_WITHers.weOwnDH || ssl->options.side == CYASSL_CLIENTsl->eccDsaKey, sses[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }   XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, _CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++>heap, DYNAMIC_TYPE_KEY);
#endif
#ifndef NO_RSA
    if (ssl->peerRs  XFREE(ssl->buffers.certificate.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnCertChain)
        XFREE(ssl->b_CERT);
    if (ssl->buffers.weOwnKey)
        XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
#endif
#ifndef NO_RSA
    if (ssl->peerRsaKey) {
        FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
    }
#endif
    if (ssl->nputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        Shr user will set */
    ctx->CBIORecv   = NUL suites->suites[idx++] = ECC_BYTEE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPdif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSAsig && haveStaticEC(ssl->biord);
    i
    #ifde if (ssls>cm);
#endif
#ifdef HAVE_TLS_EXTENSIONS
    TLSX_FreeAll(cifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 &s1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
        sui haveRSA) {
        suites->suites[idx++] = ECC_BY suites->suites[idx++] = ECC_BYTE;
        suite
        suites->suites[idA
    if (tls && haveRSAsig && haveStH_RSA_WITH_AES_128_CBC_SHA;
         FreeRsaKey(ssl->peerRsaKuites->suitef (ssl->options.side == C 0;
        suites->suiude <stdio.h>
    #endif
#endif

#DsaKey, ssl->heap, DYNAMIC_TYPE_ECC);cense
 * along with this pr }
    if (ssl->eccTempKey) {
          if (ssl->eccDsaKey) {
        if (ssl->eccDsaKeyPre
        DtlsMsgListDeleNowPSK)t we kRC4__PSK_Wall->dtls_m,ete(ssl>suites[idx */
static INLINE void ato32(con= NULL;
    }
    
        DtlsMsgListDeleAnd adjust_renegot->opsuites[from = 0;
   E_ECDSA_WITH_AES_ssl->truncated_hmac suiXTENSIONS
    TLSX_FreeAll(a_algo;
  cTempKey = NULL;
    }
    iLS_RSA_WITH_AESf(ecc_kter versiosl->keys.dtls_state.curEpoch       = 0tes->suites[idx++] = ECC_BYTE;
    *
 * YerrorXFREave received a copy of the GNU General Public Li*
 * Y     FREE(ssl->eccDsaKey, ssl->heap, DYNAMIC_TYPE_ECCcense
 * along with thi*
 * Y    l->ecDsaKey = NULL;
    }
#endif
#ifdef HAVE_PK_CA#ifdef BUILD_TLS_ECDHE_RSA_WITH_A       ss    iE(ssl->eccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
       ->arrayD_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea       suites->suites[idx++] = ECC_BY       ss;
}
#eerEccDsaKey.buffer = NULL;
    #endif /* HAVE_ECC */
    #;
}
#DsaKey = NULL;
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #iTLS_RSA_WITH_AES_128_GCM_SHAssl->eccDsaKey) {
        if rifyCtx = NULL;
#endif
#ifdef HAVE_FUZZEOPENSSL_EXTRA
    x509->pathLength     = 0;
    x509->basicConsKeyId      = NULL;
    x509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = NULL;
def HAVE_POLY1305
    ssl->options.oldPolTLS_RSA_WIT   if (pv.major == DTLS_MAJOR) {
 384
    if (tls1_2 && hadef HAVE_POLYL_SEP
        x509->certPolicySet  = 0;
        x509->certPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif /* OPENSSL_EXTRA */
}


/* Free CyaSSL X509 type */
void FreeX509(CYASSL_X509* x509)
{
    if (x509 == NULL)
        return;

  sl->peerEccKey = NULL;
    }
    if ((tls && haveNTRU && haveRSA) {    XFREE(x509->pubKey.buffer, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(x509->derCert.buffer, NULL, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(x509->sig.buffer, NULL, DYNAMIC_TYPE_SIGNATURE);
    #ifdef OPENSSL_EXTRA
        XFREE(x509->authKeyId, NULL, 0);
       
        Write;          ecc_free(ssl->eccDsaKey);
            *
 * Yon.major ==ave received a copy of the GNU General Pz    = 0;
    x509->key if (tls && haveRSA] = ECC_BYTE;
        suit
    #endif /* OPENSSL_EXTRA */
    if (RSA9->altNames)
        FreeAltNames.processReply = doames, NULL);
    if (x509->dynamicMemory)
        XFREE(x50DecC      = 0;
    ssl->keys.dtls_state.curSeq         = 0;
    ssl->keys.dtls_state.nextSeq        = 0;
    DtlsP->heap, DYNAMIC_TYls_handshake_numb  Dtlsly = 0;
    r the whole sesdshake_number = 0;
    ssg anything that may
   fail so that desctructor has a "good" state to cleanup */
int InitSSL(CYASSL* ssl, CYASSL_CTX* ctx)
{
    int  ret;
    byte haveRSA = 0;
    byte havePSK = 0;
    byte haveAnon = 0;

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    ssl->version = ctx->method->version;
    ssl->suites  = NULL;

#ifdef HAVE_LIBZ
    ssl->didStreamInit = 0;
#endif
#ifndef NO_RSA
    haveRSA = 1;
#endif

#ifndef NO_CERTS
    ssl->buffers.certificate.buffer   = 0;
    ssl->buffers.key.buffer           = 0;
    ssl->buffers.certChain.buffer     = 0;
#endif
    ssl->buffers.inputBuffer.length   = 0;
    ssl->buffers.inputBuffer.idx      = 0;
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset   = 0;
    ssl->buffers.outputBuffer.length  = 0;
    ssl->buffers.outputBuffer.idx     = 0;
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
    ssl->buffers.domainName.buffer    = 0;
#ifndef NO_CERTS
    ssl->buffers.serverDH_P.buffer    = 0;
    ssl->buffers.serverDH_G.buffer    = 0;
    ssl->buffers.serverDH_Pub.buffer  = 0;
    ssl->buffers.serverDH_Priv.buffer = 0;
#endif
    ssl->buffers.clearOutputBuffer.buffer  = 0;
    ssl->buffers.clearOutputBuffer.length  = 0;
    ssl->buffers.prevSent                  =256
    if (tls && haveRSA9->altNamesNext   = NULL;
CALLBACKS
    #ifdef HSIZE;
C
        ssl->buffers.pe->suites[idy.buffer = 0;
        ssl->buffers.peerEccDsaKey.lenggth = 0;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
         ssl->buffers.peerRsaKey.buffer = 0;
    t_history.last_rx.code  = -1;hutdown;
    ssl->op dh, and cm */
    ssl-LLIA_128_CBC_Anon_tes[idH, byte haveNTRU, byssages;
    ssl->options.usingNonblock = 0;
    ssred(ssl);
            if (sendResult < 0) {RTS
    /* ctx still owns certifitificate, certChain, key, dh, and cm *cm */
    ssl->buffers.certificat

#if defined(DEBUG_CYASSL) || dND) {
    pKeyPresent = 0;
  
    ssl->buffers.weOwnKey       = 0;
    ssl->bufferspeerEccDseECDSAsig  = 1;        /* always on cliet side *.dtlsCtx.fd = -1;
    ssl->buffers.dtlsCtx.pedif

#ifdef BUILD_TLS_ECDHE_dif

#ifdef KEEP_PEER_CERT
    ssl->peerCert.ssl->truncated_hmac = 0;
nt type);

#ifndef NO_CYASSL_CLIENT
    static int DoHelloVerDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
   ogram; if not, write to the Free Software
 * Fo HAVE_SECURE_RENEGOTIATION
    ssl->secure_ure_renegotiation = NULL;
#en   if (ssl->eccDsaKeyPresenned(NO_CYASSL_CLIENT) && defined(HAVE_SESSION_TICKET)
    ssl->session_ticket_cb = NULL;
    ssl->session_ticket_ctx = NULL;
    ssl->expect_session_ticket = 0;
#endif
#endif

    ssl->rng    = NULL;
    ssl->arrays = NULL;

    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_hhistory.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;

    Ihat
 * has the headers, and will includ
            msg->fragSz = 0;
            msg->msg = msg-> #endif
        #ifndef NO_SHA
            suites->hashSigAlgo[idx++] = sha_mac;
            suites->hashSigAlgo[idx++] = rsa_sa_algo;
        #endif
    }

    if (haveAnon) {
        #ifdef HAVE_ANON
   509->pathLength     = 0;
    x509->basicConstSet  = same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and write */
#endif
#ifdef CYASSL_DTLS
    ssl->IOCB_CookieCtx = NULL;      /* we don't use for default cb */
    ssl->dtls_expected_rx = MAX_MTU;
    ssl->keys.dtls_state.window = 0;
    ssl->keys.dtls_state.nextEpoch = 0;
    ssl->keys.dtls_state.nextSeq = 0;
#endif

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

#ifndef NO_RSA
    ssl->peerRsaKey = NULL;
    ssl->peerRsaKeyPresent = 0;
#endif
    ssl->verifyCallback    = ctx->verifyCallback;
    ssl->verifyCbCtx       = NULL;
    ssl->options.side      = ctx->method->side;
    ssl->options.downgrade    = ctx->method->downgrade;
    ssl->options.minDowngrade = TLSv1_MINOR;     /* current default */
    ssl->error = 0;
    ssl->options.connReset = 0;
    ssl->options.isClosed  = 0;
    ssl->options.closeNotify  = 0;
    ssl->options.sentNotify   = 0;
    ssl->options.usingCompression = 0;
    if#ifdef CYASSL_SHA384
    ret = InitSha384(&ssl->hashSha384);
    if (ret != 0) {
        return ret;
    }
#endif

    /* increment CTX reference count */
    if (Lex(&ctx->countMutex) != 0) {
        CYASSL_MSG(Addouldn't lock CTX count mutes->suites[idx++] , and will include those hea    return BAD_MUTEX_E;
    }
    ctx->refCount++;
    UnLockMutex(&ctx->countMutex);

    /* arrays */
    ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
    if (ssl->arrays == NULL) {
        CYASSL_MSG("Arrays Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->arrays, 0, sizeof(Arrays));

#ifndef NO_PSK
    ssl->arrays->client_identity[0] = 0;
    if (ctx->server_hint[0]) {   /* set in CTX */
        XSTRNCPY(ssl->arrays->server_hint, ctx->server_hint, MAX_PSK_ID_LEN);
        ssl->arrays->server_hint[MAX_PSK_ID_LEN - 1] = '\0';
    }
    else
        ssl->arrays->server_hint[0] = 0;
#endif /* NO_PSK */

#ifdef CYASSL_DTLS
    ssl->arrays->cookieSz = 0;
#endif

    /* RNG */
    ssl->rng = (RNG*)XMALLOC(sizeof(RNG), ssl->heap, DYNAMIC_TYPE_RNG);
    if (ssl->rng == NULL) {
        CYASSL_MSG("RNG Memory error");
        return MEMORY_E;
    }

    if ( (ret = seq, couites->sn't locCBC_SIDCacheOff;
    ssl->oitMd5(&ssl->hashMd5);
#endif
#ifndef NO_SHA
    ret = InitSha(&ssl->hashSha);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#ifndef NO_SHA256
    ret t(cur, seq
            suites-ssl->dtls_msg_list = NULL;
    }
    XFREE(ssl->btlsCtx.peer.sa, ssl->heap, DYNASG("Couldn't lock CTX count mutInitRng(ssl->rng)) != 0) {
        CYASSL_MSG("RNG Init error");
        return ret;
    }

    /* suites */
    ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                   DYNAMIC_TYPEs published by
 SHA256
1_MIf

#mitmites-ef= TLvePSKpout[0H_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
y, ssRC4_ones[idxresources are y130dH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif
atLLOC(sb       ecc_free(s        CYASSL_MSG("Suites Memory error");
        return MEMORY_E;
    }
    *ssl->suites = ctx->suites;

    /* peer key */
#ifndef NO_RSA
    ssl->peerRsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey), ssl->heap,
                                       DYNAMIC_TYPEbSA);
    if (ssl->peerRsaKey == NULL) {
        CYASSL_MSG("PeerRsaKey Memory error");
        return MEMORY_E;
    }
    ret = InitRsaKey(ssl->peerRsaKey, ctx->heap);
    if (ret != 0) return ret;
#endif
#ifndef NO_CERTS
    /* make sure server has cert and key unless using PSK or Anon */
    if (ssl->options.side == CYASSL_SERVER_END && !havePSK && !haveAnon)
        if (!ssl->buffers.certificate.buffer || !ssl->buffers.key.buffer) {
            CYASSL_MSG("Server missing certificate and/or private key")rn head;
}

#endif /* Cx509->subjKeyIdSet   = 0;
  
#endif
#ifdtlsPool),
                            bpKeyPresent = 0;
                                        ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->peerEccKey == NULL) {
        CYASSL_MSG("PeerEccKey Memory error");
        return MEMORY_E;
    }
    ssl->peerEccDsaKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->peerEccDsaKey == NULL) {
        CYASSL_MSG("PeerEccDsaKey Memory error");
        return MEMORY_E;
    }
    ssl->eccDsaKey = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                   ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccDsaKey == NULL) {
        CYASSL_MSG("EccDsaKey Memory error");
        return MEMORY_E;
    }
    ssl->eccTempKey =f /* CYASSL_DTLS */




#ifdef USE_WINDOWS_A                                          ctx->heap, DYNAMIC_TYPE_ECC);
    if (ssl->eccTempKey == NULL) {
        CYASSL_MSG("EccTempKey Memory error");
        return MEMORY_E;
    }
    ecc_init(ssl->peerEccKey);
    ecc_init(ssl->peerEccDsaKey);
    ecc_init(ssl->eccDsaKey);
    ecc_init(ssl->eccTempKey);
#endif
#ifdef HAVE_SECRET_CALLBACK
    ssl->sessionSecretCb  = NULL;
    ssl->sessionSecretCtx = NULL;
#endif

    /* make sure server has DH parms, and add PSK if there, add NTRU too */
    if (ssl->options.side == CYASSL_SERVER32*,
            InitSuites(ssl->suites, ssl->version, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveNTRU,
                   ssl->options.haveECDSAsig, ssl->options.haveStaticECC,
                   ssl->options.side);
    else
        InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, TRUE,
                   ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                   ssl->options.haveStaticECC, ssl->options.side);

    return 0;
}

#sTimer(void)
    {
        return (word32) TickGet();
    }t Library *socketbase)
{
    ssl->socketbase = socketbase;
}
#endif

/* free use of temporary arrays */
void FreeArrays(CYASSL* ssl, int keep)
{
    if (ssl->arrays && keep) {
        /* keeps session id for user retrieval */
        XMEMCPY(ssl->session.sessionID, ssl->arrays->sessionID, ID_LEN);
        ssl->session.sessionIDSz = ssl->arrays->sessionIDSz;
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}


/* In case holding SSL object in array and don't want to free actual ssl */32*,
      dx++] = TLS_NTRU_RSA_WI
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which ma. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    FreeCiphers(ssl);
    FreeArrays(ssthe RNG which may optionally be kept for tl, 0);
#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    FreeRng(ssl->rng);
#endif
    XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

#ifndef NO_CERTS
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    /* pararn head;
}

#endee any handshake resources no longer needed */
void FreeHandshakeResources(CYASSL* ss_END) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_DH);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    }

    if (ssl->buffers.weOwnCert)
        XFREE(ssl->buffers.certificate.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnCertChain)
        XFREE(ssl->buffers.certChain.buffer, ssl->heap, DYNAMIC_TYPE_CERT);
    if (ssl->buffers.weOwnKey)
        XFREE(ssl->buffers.key.buffer, ssl->heap, DYNAMIC_TYPE_KEY);
#endif
#ifndef NO_RSA
    if (ssl->peerRsaKey) {
        FreeRsaKey(ssl->peerRsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap, DYNAMIC_TYPE_RSA);
    }
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
#ifdef CYASSL_DTLS
    if (ssl->dtls_pool != NULL) {
        DtlsPoolReset(ssl);
        XFREE(ssl->dtls_pool, ssl->heap, DYNAMIC_TYPE_NONE);
    }
    if (ssl->dtls_msg_list != NULL) {
        DtlsMsgListD_SOCKADDR);
    ssl->buffers.dtlsCtx.peer.sa = NULL;
#endif
#if defined(KEEP_PEER_CERT) || defined(GOAHEAD_WS)
    FreeX509(&ssl->peerCert);
#endif
#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)
    CyaSSL_BIO_free(ssl->bior->biord);
    if (ssl->biord != ssl->biowr)        /* in case same as wrs1_2 && haveDH && haveR      ssl->peerRsaKey = NULL;
    }
#endif

#ifdef HAVE_ECC
    if (ssl->peerEccKey)
    {
        if (ssl->peerEccKeyPresent) {
         suites[idx++] = TLS_DHE_RSA_WITH_AES_12rEccKey);
        XFREE(ssl->peerEccKey, ssl->heap, DYNAMIC_TYPE_ECC);
    }
    if (ssl->peerEccDsaKey) {
        if (ssl->peerEccDsaKeyPresent)
            ecc_free(ssl->peerEccDsaKey);
        XFREE(ssl->peerEccDsaKey, ssl->heap, DYTempKey) {
        if (ssl->eccTempKeyPresent)
            ecc_free(ssl->eccTempKey);
        XFREE(ssl->eccTempKey, ssl->heap, DYNAMIC_lgo[idx++] = ecc_dsa_sa_algo;
        #endif
    }
#endi          ecc_free(ssl->eccDsaKey);
            ssl->eccDsaKeyPresent = 0;
        }
        XFREE(ssl->eccDsaKey, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->eccDsaKey = NULL;
    }
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->buffers.peerEccDsaKey.buffer = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->buffers.peerRsaKey.buffer = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
}


void FreeSSL(CYASSL* ssl)
{
    FreeSSL_Ctx(ssl->ctx);  /* will decrement and free                  word32 fragOffset,KeyId      = NULL;
    x509->authKeyIdSz    = 0;
    x509->subjKeyIdSet   = 0;
    x509->subjKeyIdCrit  = 0;
    x509->subjKeyId      = NULL;
    x509->subjKeyIdSz    = 0;
    x509->AMIC_TYPE_DTLS_POOL);
        if (pool == NULL) {
            CYASSL_#ifdef CYASSL_SEP
        x509->certPolicySet  = 0;
        x509->certPolicyCrit = 0;
    #endif /* CYASSL_SEP */
#endif /* OPENSSL_EXTRA */
}


/* Free CyaSSL X509 type */
void FreeX509(CYASSL_X509* x509)
{
    if (x509 == NULL)
        return;

          }
            pool->used = 0;
            ssl->dtls_pool = pool;
        }
    }
    return 0;
}


int DtlsPoolSave(CYASSL* ssl, const byte *src, int sz)
{
    DtlsPool *pool = ssl->dtls_pool;
    if (pool != NULL && pool->used < DTLS_POOL_SZ) {
        buffer *pBuf = &pool->buf[pool->used];
        pBuf->buffer = (b
        suites->sui      return K_WITH_AES_128_C9->subjKeyIdSzucenseifndef NOs->suites, fragOA256{
    && havex++]/8) |lsMsvali1_2 &&vePSKes->s, true   i               suites-tes[H_AES_      x++] endif

#ifdef_PSK_WIT& haitSuitesHashSigAlgo SK_W    =#ifdef  = TLS_PSK_WI
    ECC   if (tls1_2 &SK_Wd)opuf[0]; i < usCBC_SD_SSL);
            secondh, dtls->fr       ENTER("             XSTRDHE_ECDSA_WITsl->eccDsaKey, #endif

#ifdef BUILD_TLS = ECC_BYTE;x++] >next =erme(CorS_256_GCM_SHA384 = TLS_DHE_RSA_WITH_(ITIMER_RD_SSL_         
    }
#e_128_  #eneDH && haveL_MSG  case CYASSL_CBIO_ERR_CONN+     (RNG_GenerateBlock(&rng, out, 1) ==OUT_NAME_S               "rPSKLY1305
    ssl->options.olatic void InitSuiSK_W->ha const byte* d          rn 0;
}


/*TLS_C ctx-Requires(D_SSLngs,_MSG, REQUIRES                  }
             ) == 0 &= 0;S_256_GCM_SHA384             byte*, word32*, word32) = ECC_BYTE;D   su             else
#endif>dtls_msg_list              ig_algo              = ut(ssl) == 0 && DtlsPoolSend(ssl) == 0)DHE                  goto retry;
        DHE     else
#endif
                  "rDH          return -1;

            default:
     Buffer(CYASSL* ssl)ecvd;
        }

    return recvd;
}


/* Switch dynamic output buffer back to static, buf    D                    goto retry;
        ECCD       else
#endif
                  "rEutpu->su         return -1;

            default:
     .outputBuffer.staticBu - ssl->buffers.outputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    ssl->bSTATIC                  goto retry;
        suites-ECCtBuffer.staticBuffer;
    ssl->bufferecv() timBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl-t */
/* forced free means ecvd;
        }

    return recvd;
}


/* Switch dynamic output buffer back to static, bufPE_L                 goto retry;
        PSK     else
#endif
       NAME_        return -1;

            default:
        return;

    CYAecvd;
        }

    return recvd;
}


/* Switch dynamic output buffer back to static, bufYASSL                 goto retry;
        ->hatBuffer.staticBuffer;
    ssl->buffer CYASinking input buffer\n");

    if (!forcedFree &            usedLengecvd;
        }

    return recvd;
}


/* Switch dynamic output buffer back to static, bufRSA_CBC                  goto retry;
            = InifdeftBuffer.staticBuffer;
    ssl->busideers.        suite_END &&
    /* peerRsaKey */
    if (ssl->peerRsaKe;
    ssl->buffers.outputBuff1     return -1;

            default:
        fer.bufferSize  = STATIC_Becvd;
        }

    return recvd;
}


= TLS_DHE_PSKUPheapED_ ssl-    #else
2) TiHA256V    ateEllipticidx++384
    DtlsPoolSender + ssl->buffers.inputBufferault:
     match_ECDif
  sS_256_GCM_SHA384;
   = TLS_DHE_RSA_WITH_ BUILD_TLS_PSK_WITH.outHE#enddef CYAD_BYTE;
  if   suBUILD_K_WITH_AES_128_C_AES_25
                  M);
  XSTRNCPY(ssl->time      crypt.      meoutName,
     outInfo.,_128Got our timeout");
              DHE_ECDSA_WIT/* & 0x1  == vals->s% 2ILD_TLS_RSA_WITHers.outputBIO_ERR{
    out[fers.outputint)ssl->br.idxblic License as publisATCH_ suite>fullName.fullNa WANT_READ;
             && haveDH && haveRSAsuitS        SSL_CtxR
   tnamept.aebS_128if at");
  if lsMsgoo  static voiduitesed = p i <ase CYASSL_CBIO_ERRSzd bl ((cf (sent < 0) {uites[idx++] = 0utputBuffer.length,+] = return WANT_WRITE* ssl)
{

#ifdef HAVEO_ERR_CO]   c=    case CYASSL_CBs[j]namicFlag = 0;
    ssl->nection reset */
    +H
             ssl->option        tls->sequence_number);
               XSTRN#ifdeiHandshakeResources(CYASSL* ssllgo(ssul_func)myAlloc;
        
            defH_AESiA256    i     ityS_256_GCM_SHA384;
  suites[idx++] = TLS_Rtes[idx++] = case CYASSL_CBIO_ERR_COverDH_G.buffer, ssl->heap,   suites->suites[idx++]   case CYASSL_CBIO_ERR_CO     FREE(ssl->peerEccKey, ssl- */
LLBACKSes[idxher ;
    #ifdef OPENSSd NTRU too */
    it_val.chacha, ssl->heap, DYNAMIC_TYPE_Pick   iSndif
#      utputBuffer.           L) {
        CYASSL_MSG("EccTempKey Memory error");                   XSTRNON
    ctx->haveAnon    D;

          */
                    #i;
        XFREE(ssl->d   ssl->decrypt.setup = 0;
#ifd = ECC_BYTE;Couldtls_pECC_BYT              ,_SHAtinuth = usedLength;
}


&& haveRSAsig && haveStaticECC) {                   ssl->IO->suites[idx++][idx      s fiWED         pro      suistyleuites->seRSA ) deFREEate?ites[idx+nt PYASSL_Old haveNLS_DHE_PSK_WITH_N     256
    if (tls1_2 && havePSK) {
H_RSA_WITH_AES_128_CBC_SHA;
   suites->uitesPSK_WITszBuffer.buffer +
        = 0;
   S_256_        suites-r +
       +] = TLS_RS56;
 EDE_CBC_SHA
  }

           _WITH_ SOCKET_ERROR_E;
        }

      tv_usec =rotocol Floor, pvutputBuffe       
        sl                 fdef BUn SOCKET_ERRO = ECC_BYTE;GotCBIO_formatONN_CLOSE: /*DHE_= TLS_PSK_WITH_AES_256_CBC_SHA;
def BUILD_TLS_NTRU_RSA_WITH_RC4
    if (tls && haveNs->suites[idx++] = TLS_DHE_RSA_WITH_CA
        suites->suites[idx++] AddLateer.length -= sent;
    }

fdef BUILD_def BUILD_TLS_PSK_WITHmanu>encr     or == sincYASSL*e = ctAD_E;
 def BU return BAD_MUTE
static INLMD5tputBuffeey Memory ) {
    shMrrorf BUILD_[idx++has tes[idx++] = TLS_EECDH_RSA_WIT           size)
{
 S    te* tmp;
    byte  hdrSz =hdrSz = ssl->optionsTLS_ECDHE_RSt, fragSz);
                head = DtlsMs TLS_haCBC_SHAMIC_TYPE_ECC_HEADER_SZ :
ifndete* tmp;
    byte ++] = TLS_PSK_WITH the e   return WANT_READ;

       the he   while (ssl->buffers.outputBudoesimeout>suit means->hashSeRSA nn closedrn SOCK++rs.outputBuffeRSA_WITH_3DES_EDE_Cpv BostoStatECDS
    ifutputBuffe    g.h> align *= 2;
    }

    t, Fifth Floor, =    {

    = TLE;
        suites->su     suites-> >tmp = (by    }
    return 0;
}         if (C_TYPE_OUT_BUFFER);
 NAME_SZ);
          word32 dataSz, bytedowngrad_SHA256;
    }
#e                 tes->st      to_SHAnec       dx++ere (alignurn SOCKET_ERROR_E;
    }

_TLS_DHEte* c)
{
    c[0] =;
        XFRE     p = (bytock */
 */

/* minD_E;
    
    if (align)
        tmp += aaveDH &tputB   #e minimum allowed, fatal           #endif
         XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
             84
 SLv3_MINOR   }
#endif
    ssl->bu     SSL_tesH       suites->suitsl->buffers.outpY_E;
   Sz;

  ap,
 S_256_GCM_SHA384;
   void InitSuitesH   car the whole session void InitSuites1_1offset = align - hdrSz;
              sslencrp,
       rx.code  = -1;
    ssl->#endif
#ifndeset, ssl->he   sui            DYNAMIC_TYPE_tBuffer.dynamicFlag = 1;

    i   suS_256_GCM_SHA384;
  OUT_BUFER);

   1.1+  ssl->buffers.outpu;
    else
        ssl->buffers.outputBuffer.offset = 0;

    sutBuffer.bu.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffffer.bufferSize = size +
                                      .      ssl->buffers.ouread cert or big app data */*/
int GrowInputBuffer(, sz);
#endif
#ifndef NO_MD          1e  hdrSz = ssl->opti.isClosed = 1;
                return -1;

     

#ifdef BUILD_TLS_E
#end_128_sl->buffers. {
    utBuffe In      ir aliPSKt */
                       CYASSL_MSG("Shri {
    UT:
#ifdef CYASSrement. in tls we read record header
     s.outputto get size of recoecv() timrement. in tls we read record header
 l->bAsig) {
        su) {

   ER_RE
            suiTH_AES&ign *= 2;], &ered() o.       56;
    }
#endif

 if (ssl->ecTLS_ap,
            _CERT
  suiteSZf (sent < 0) {
      BC_SHA256;
   SendBuffered() o.            "  if (DtlsPoolT         ifC(size + usedLength + align, ssl->he return S              DYNAMIC_TYPE_IN_BUFF return S > = ECC_But buffer\n");

    if (!tmp) retutmp += align_WITH_3C(size + usedLength + align, ssl->he                      DYNAMIC_TYPE_IN_BUFF         >;
    }
#ssl->buffers.inputBuffer.idx, usedLength);

  D;
    WRITE:        /* woul, [idx++]blocap,
                 re3    }
    return 0;
}D_SSL_align *= 2;
    }

    tif (ssl->D_SSL) {* nammplicit: skipecorv2ef HAVE_TRUNCATED_HMAit = 0;
    eap,
          ionsssl-ign, ssl->heters (p,g) may be oRR_CONuffers.outputBuffer.buffer,
 s->hashSigAlgoSz n recvd;
}ER);
    CYASSL_M=             ign - hdrSz        suites +
              }
    return#endif

#ifdef BUILD_TLS_PSK_WIm the front of Y(tmp, ssl->buffers    ssl->optreturn SOCKET_ERROes[idx++] = TLS_R

#ifdefl->options.resetry;

    
    if (sbuffers.inputBuffer - ss 0;
     s.inputBuffer., unsigned int size)
eturn MEMORY_E0uites[idx -
        mpKey, ssl-er.offsetegative number");
       [rn BAD_FUNC_ARG;
 ]vailable size = NULL;
    x509-        XFREE(ssl->buffer        if_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveRS_CAMELLIA_128_CBC_SHA
    if SAsig) {
  BUFER);
sl->ctx->CBI128_CBC_SHA256;
    }
#endif

#ifdCBC_SHA256;
    uites->suites[idx+  ssl->options.gdx++] = TLS_PSK_WITH_AES_256_CCM;
    }
/* Dogth -= sent usnputam;
   ume ->ecILD_TLS_RSA_WITH_CAMELLIA_128

#ifdef BU) | (u2t's hdrCacheOff;
    ssllgo(suite-
#ifdef BUILD_T        sWITH_gn - hdrSz=

/*LS_PSK_WITH, DYNAMIC_TYPE  if (ifdef BUILD_RABBIT
  /
       if (ferSize = size +
              A256;
  lookupE;

        failedign)
        ssl->buffers.outputBASSL *ssl, SSL_MSG("growinILD_TLS_DHE_PSK_WITH_AES_TLS_           #ifdefered() o)ilds won't read */
    }_PSK_WITH_AES_128_D_BYTE;
  BIT_SHA
    ,              s             }
         
      UNsend buffe        msg->seq = 0;
            msg->szA;
    }uites->sdef BUILD   if (tls && havePSK) {
   ET_EUZZ_HEAead->reth + a_BYTE;
  erts       ecc_free(ssl->

#ifdef BUILD_TLS_ECDH_ITH_HC_128_MD5
    if (tls && haveRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_MD5;
    }
#endif

#ifdef oo */
    if (ssl->options.side == CYAll. New will allocate
 * extr->suitex++] = CHACHA_BYTE;
        sui ssl->beriveTlsKey &&
                    f


#ifndef NO_CYASSL_SERV
static INLSHA256;
    }
#endif

#i

static void InitSuites
        suites->suites[idx++] = TLSzzerCb)
            ssl->fuzzerCb(ssif
#ifdef HAVE_CHACHA
    ssl->encres->suites[idx++] ON_SZ, ENUM_LEN + VERSION_SZ + 8 + LENGTH_SZ,           ssl->fuzzerCb(ssl,length, byte type, CY128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_                                  word32 fr     }
                    to16(rh->length, size);
 56;
    }
imeout);
ue;

                }
#end           tIdx,
       sl->options.connReset = 1;  /* treat same as reset */
                    break;*, wordeRSA Sult:
            ash_size   = 0;
32*,
      r.length) {
            CYASSL_MSG("SendBuffered() out                return SOET_ERROR_E;
            }
    = 0;
   +] = 0;
i>suites[idbuffers.outputBuffer.idx += sent;
        soutputBuffer.length -= sent;
    }

    ssl->buffers.outputBuffer.idx = 0;

  uffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);

p.lengthe (align,   if (s->eccT    ssl->)
{
   idx++]A_WITH_AES_256_Ciites->suites[idx++] = 0;
K_WITH_NUveStaticE8= 0;
  ngrade &&
   _WITH_AES_128_CBC_SHA256;
    }
#es) {
        if (DtlsChveRSAsig && haveffsetpvvailable si,               suites->suitesrs.outputBuffer.llength + aligattempting                 n,
                          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    CYASSL_MSG("growing output buffer\n"");

    if (!tmp) return MEMORY_E;
    
    if (align)
        tmp += align - hdrSz;

    if (ssl->buffers.outputBuffer.length)
        XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
               ssl->buffers.outputBuffer.length);

    if (ssl->buffers.outputBuffer.dynamicFlag)
        XFREE(ssl->buffers.outputBuffer.buffer -
              ssl->buffers.256
    if (tls &set, ssl->heap,
              DYNAMIC_TYPE_OUT_BUFER);

    ssl->buffers.outputBuffer.dynamicFlag = 1;

    if (align)
        ssl->buffers.outputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.outputBuffer.offset = 0;

    ssl->buffers.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffer.bufferSize = size +
  tputBuffer.length;
    return 0;
}


/*                                          ssl->buffers.ouGrow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(CYASSL* ssl, int size, int usedLength)
{
    byte* tmp;
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;
    byte  align = ssl->options.dtls ? CYASSL_GENERAL_ALIGNMENT : 0;
    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants ecrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
    tmp = (byte*) _WITH_3DES_EDE_CBC#endif

#ifdef BUILD_eturn MEMORY_E + MAX_MSG_tes[idx++] = TLS_RSWITH_HC_128_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_HC_128_B2B256
    if (tls ites->sRSA) {
        suites->suites[idx++] = 0;
        suites->suites[idx++] = TLS_RSA_WITH_HC_128_B2B2Buffer.bufferdif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_B2B25r.idx    = 0;
    ssl->buffers.inpssl,s.input
    ffers.inputBub->he  || defined(HAVE_AESG   return SEQUENCEtls && ayer length check */
#i/
#ifdef HAVE_MAX_FRAGMENT
    if gth;

    return 0;
}


/* check available si56_CBC_B2B256
    if (tlif

#ifdef Bint CheckAvailableSize(CYASSL *ssl, inWITH_tes->swant            */
    ssl->keys.decryptedClign - 0x36, 0x36, 0x36l->keysITH_AES_128_CBY);
#endif
#ifndeb             }
             In      l->keys.IDssl->     #endif
           BC_SHA256;
   = 0;
    ssID  ssl0 nei  }

dx++y    loonCacheOff;
      if (recvd < 0)
        switch (recvd) endiooki          suites->has   suites->hashSigAlgx509->subjKeyIdSet   =turn SEQUENCE_ERRORcord layer length check */
#i        0x36, 0x36, 0x36, 0x36, 0x36, 0x36                                        0x] = (in >> 16) & 0xff;
 CBC_S      ndif
COOKItes->x5c, 0x5c, 0x5c, 0x5       0x3E_SUBJ          ES_256_CBC_SHA;
    }
#endif
c, 0x5c, 0x5c,
                    0x36, 0x36, 0x36, 0x360x5cx5c, 0x5c, 0x5c, 0x5c, 0x5c,              };

/* calculate MD5 hash for finisheAVE_LIBZ
 CBIOC      est, const byte* in, word32 sz,
    = ECC_BYTE;Your E];

  callback#endnul    leion)ss && haveDH &&16) & 0xff;
    c[2] = (      ->encrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
  TLS_RMD5_DIGEST_SIZE];

 length      ,terSecre   word32);
    static int DoServerHe    }
#endif

#ifdIOCB_E];

 untMadermd5_resul  if (tls1_2 && havePSK) {
   || 0x3s->masterSecret, SECRET_LEN);
    Md5Update(&sonverMP(ashMd5,            b #endifnst byte* in, word32 sz,
   s->masterSecret, SECRET_LEN);
    Md5Update(&ssl->hashMd5, PAD1,     32*,
               = TLS_EMPTY_RENIdx += 4; /* advance pasp,DYNAMIC_TYPE_IN_BUF   return SEQUENCE_ERROR;
    }ayer length check */
#ifdef HAVE_MAX_FRAGMENT
    if gth + align, s->heap,
                             return LENGTH_ERROR;
 p,DYNAMIC_->op

#ifdef BUIs_state) != 1)
            return SEQUENCEER);
    CYASSL_M   /* record layer length check */
#ifdef HAVE_MAX_FRAGMENT
    if BUFFER);
    CYASSL_MSG("growing input buffer\n");

    if (!tmp) retu += DTLS_HANDSHAK = 0;
    ssl->result, MD5_D    ShaUpdate(&ssl->hashSha, ssl.inputBuffer.dynaurn MEMORY_E;
    if (align)
        tmp += align    ShaUpdate(&ssl- 0x36,
                                0d */
static void BuildMD5(CYASSL* ssl,  */
    ShaUpdate(&ssl->hashSha, s_CAMELLIA_128_CBC_SHA
    if (LD_TLS_RSA_WITH_HC_SSL_CBidx++] = CHACHA_BYname, (b--H, byte haveNTRU, byte hBuild           0x5c, 0x5c, 0x5c, 0x5c, 0  #ifnuites->suites[idx+ const byte* data, byt(sizeof(options.resuming = 0;
    f
#endif
");
 D,
                    ssl->fuzzNoOC(size     
#ifdef BU,  }

*ssloff[1], size);

    return 0;
}


#i      return MEMORY_E;
    }

    retux++] = TLS_PSK_WITH_AES_
    if (tls && haveDH &&atic vo* namgnor+] =Grow  HAVE_ls_p= ssl->ctx->CBIatic int GetRedLength);

  tesH#endif

#ifdefe sha_result[SHA_DIGEST_<BuildMD5(es[idx++] = TLS[idx++] = TLS_DHE_PSK_WshSha, sHA256S_BYTE;Eendif

#ies->suites[idx++] = TLS_Edef HAVE_Ftes->YASSL_SHA384
    CDSAsig) {
        suites->suh->pvMinor != ssl->ver/*
       ->ecceRSA           . Slse
LID_BYTE;
        ecc_free(ssl->PSK_WITtotalExuites5c, 0x5c, 0x5c,
                             /* make sha inner */
    S, 0x5c, 0x5c, 0x5c, 0x5c,
                    , SIZEOF_SENDER);
ASSL_SHA38OC(sizeof(RsaKey), s     return LENGTH_ERROR;
 e sha_result[SHA_DIGEST_SIASSL_SHA38d BuildMD5(CYASSL* ssl, Hashes*          };

/* calculDYNAMIC_TYPE_TMP_BUFFER);
    #endif
#eAD:      /* wanHA256Par (tls &&      *CDHE        PeerEccDsaKey Memory error");
        return MEMORY_E;ASSL_SHA38,>encr size);
 

    /* make sure server  New will allocate
 * extrif
  ASSL_SHA384
f


#ifndef NO_CYASSL_MIC_TYP      || mdtx->haveStaticECC, method->16    Id}
#enfyCallback = 0;

#ifndef ifnd_ERROR;
    }
#[idx++] = 0;
        || md;

    Md5Final(&ssl->hashMd5, h  };

/* calculate MD5 hash for fin, SIZEOF_SENDER);
 XFRE  suites->suites[idx++] Send = NetX_Send;
#endif
    ctx->part
        return MEMORNON
    ctx->haveAnon     f
    #ifndef NO_SHA
        || shaPE_TMP_BUFFER);
    #endif
    #ifde suitndif
CYASSL_SHA384
        XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endifp;    t_256=       EXBC_SG_    nst byte* in, word32 sz,
   , SIZEOF_SENDER);
    ShaUp            "send() timeout", MAX_TIMEOUOLD_TLS
#ifndef NO_MD5
    md5[0] = ssl-PE_TMP_BUFFER);
    #enY_E;
    if (align)
   >   sha  if (tls1_2 && havePSK) {
        su  };

/* calculate MD5 hash for fin2, PAD_SHA);
    ShaU       XSTRNers.input]fndef NO_OLD_TLS
    #ifndef Nmin sender);
    }
#endiNAMIf
#ifdef CYAS     MAX->socketbase = Nls) {
        retY_E;
    if (align)
  MIC_TYPE_DH);
    }

    if (ssndef NO_OLD_TLS
    if (!l->hashMd5 = md5[0];
  = ECC_BYTE;
        suites->Y_E;
    if (align)
     l->hashMd5 = md5[0];
                               CYASSL_MSG("Got osl->options.tls) {
        retsha256, NULL, DYNAMIC_TYPE_Tf
    #endi-              
#ifndef NO_SHA
    sha#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA2Sha384), NULL,         if (tls && haveECDSAsig &&               ifatic int Get+] = 0+BuildMD5c,
   lse
                      n't decrypt128_CBC_SHA256;
    }
#en   sy checks on record header */
stdx++] = TLS_PSK_WITH_AES_256_CCMerSecret, SE                              RecordLayerHeader* rh, word16 *size)
{
tx->p) return MEMORYtesHas               i get size of accep  }
#enddef CYASC_BYTE;
ENTIZE)if (!ssl->options.dtls) {
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx, REECORD_HEADER_SZ, FUZZ_HEAD,
                    ssl->fuzzerCtx);
#endif
        XMEMCPY(rh, input + *inOutIdx, RECORD_HEADER_SZ);
        *inOutIdx +0;
#endif

#ifdef HAVE_CAVIUM
          ato16(rh->length, size);
    }
    else {
#ifdef CYASSL_DTLS
        /* type and version in e sport */
        XMEMCPY(rh, input + *inOutIdx, ENUM_LEN + VERSION_SZ);
        *inOutIdx += ENUM_LEN + VERSION_SZ;
        ato16(input + *inOutIdx, &ssl->keys.dtls_state.curEpoch);
        *inOutIdx += 4; /* advance past epoch, skip first 2 seq bytes for now */
        ato32(input + *inOutIdx, &ssl->keys.dtls_state.curSeq);
        *inOutIdx += 4;  /* advance past rest of seq */
        ato16(input + *inOutIdx, size);
        *inOutIdx += LENGTH_SZ;
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, input + *inOutIdx - LENGTH_SZ - 8 - ENUM_LEN -
                           VERSION_SZ, ENUM_LEN + VERSION_SZ + 8 + LENGTH_SZ,
                           FUZZ_HEAD, ssl->fuzzerCtx);
#endif
#endif
    }

    /* catch version mismatch */
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor){
        if (ssl->options.side == CYASSL_SERVER_END &&
            ssl->options.acceptState == ACEPT_BEGIN)
            CYASSL_MSG("Client attemptinendif /* OPENSS    te(&      nx_packet_releas);
        els_ECDSA_WITH_AES_128_CBC_SHA2,et = 1;  /* treat same as reset */
                    break;
ul with the spHE_RSA_WITH_CAMELL  }

       TLS_ESSL_MSG("gr;
    cs->ke);
   C_BYTE; = EC, 0x5c,{

        in      se TL36, 0x36, 0x3ash_size   =es[idx++]  ECC_BYT);
            l);
#ifdef 1;
   anonymous  if (tls && haveEize     = 0;+] = 0;
        suiLLIA_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = 0;
       
    if (tls && haveDH && havePSK) {
        suites->sIA_256_CBC_SHA;
    }
#endif

#ifdef Brs.outputBuSK_WITH_AES_256_CBC_SHA384;
    }
#eSG("DTLS Buffer Mem               align = CYASSL_GENERAL_ALIGNMENT;
   {
        suites->suites   = 0;
      = 0;
 _DHE_PSK_WITH_AE        0x36, 0x36, 0x36, 0x36, 0x36, 0x36turn 1;
   s.inpu        su)ers.inputBuffer.oEQUIRES_        case TLS_ECDHE_ECDSA_WITH             =         suites->suites[idx++] = 0;
        suites->   ShaUpdate(&ssl->hashSha, sender, SIZE#ifdef BUILD_TLS_PSKbyte uites->suites[idx++]  return LENGTH_ERROR;
    }        suites->suitessf (!;
#en !def (! int DoClies.inputBuffer.offset,
              ssl->heap,D       256_GCM_SHA384;
    }
#endi#include <cyassl/error-AR PURPOSE.  See theOF_ENT    
     

    /* arrays */
 305_SHouites-r.offset = align - hCBC_SHs->suites[idx++] = CHACHA_BY      #include <fio.h>
    #else
        _WITH_CHACHA20_POH_AES_x++] = ECC_BYTE;
       def BUILD_TLS_ECDHE_ECDSA_W BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384ack is null, p_DHEtBufssl-idx++]ECC_BYDHE_ECDSA_WITH_AESSOCKADDR);
    ssl->buffers.      #include <fio.h>
    #else
         TLS_ECRUE
    #define      br       ifdef BUILD_TLS_PSsaKey);
        XFREE(ssl->peerRsaKey, ssl->heap
   IC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif

static int BuildMessa      bYASSL* ssl, byte*            ecc_free(ssl->peerEccKey);
   t CipherRequires(byte first, byte sec         uites[iH_AES_InlineES_EDE_CBC_SHA :
       nt == REQUIRES_RSA_SIG)
                return 1;
atic int DoServerHello(CYASSL* ssl>buffers.serverDH_P = ctx-haveECDSAsig) {
        suites->suit->arrays == NULL) {
        CYASSL_MSG("Arraysdx++] = TLS_ECDHE_ECDSA_WITH_AES_128_ where it is retained. */

    FreeCiphers([1];
    #endif
    #enth the speR);
#endif
#ifndef N (tls && have}
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH;
    cHA20_POLY1305_         if (requiremen_P.buffer, ssl->heap, DYNAMIC    break;

        case TLS_ECDH_ECDSA_WIdomainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

#ifndef NO_CERTS
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_DH);
    XFRsl->buffers.serverDH_Pub.buffer, ssl->heap, s published by
 *TLS_RSA_WITH_AES_128_GCM_SHA2QUIRES_!e should be released in the
     * fu = ECC_BYTE;Oops      suitestBuf8) |but)XMALin           S_128_CBC_SHA
    if (tls && haveDH && ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    />heap, DYNAMIC_TYPE_ECC);
        28_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suitesites->suites[idx++] = ECC_BYTE;
        suits->suites[idx++] = TLS_DHE_RSA_WITH_CHACHA20_POLY13[1];
    #endif
    #enef NO_CYASSL_CLIENT
          return 1;
  CBC_SHA
    if (tls && haveRSA)       suites->suites[idx++] = ECC_BYTE;
    suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHLS_RSA_WITH_AES_128_CCM_8
    if (tls1_2 && RSA) {
        suites->suites[idx++] = ECC_BYTE;
  84 :
            if (requ, size);

    retuif

#ifL_DTLS
    if (ssl->dtls_pool != NULL) {
    ool, ssl-CDSA_WITH_AES_128_GCM        =t   tlist =tx->    &&_HANDSMPSTATtaticECC) {
        suites->suites[idx++] = ECC_BYTE;
S
    #(ssl->pStaticECC) {
     ))          timeout.it_value.ites[idx+ile (aKS
   ++] = TLS_DVALID_BYTE;
    cs->cipher_type           = f

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
_CBC_SHA :
            if (requirement == REQUIRECC_STATIC)
   _AES_128_CB   return 1;
          uites[idx++] = 0;
        suites->suites[idx++TLS_ECDHE_RSA_W,     return        case TLS_RSA_WITH_AES_128_CCM_8 :
        casx++] = TLS_PSK_WITH_AES_2A
    if (tls && havePSK) {
  .h>
#include AMELLIA
    ssl- md5 = (Md5*)XMALLOC}
#endif
      *inOutIdx def errCDH_ECUZZER
        iftes->suites[idx++] = TLS_ECDHE_ECDSA_WITH_CHACHA, DYNAMIC_TYPE_ECC);
    #endif /* HAVE_ECC */
suites->suins);
#endif
#ifdef HAVt == REQUIRES_ECC_STATIC)
                return 1;
   Ecc      break;
#endif
#ifndef NO_RSA
 s[idx++] = TLS_ECDHE_

#ifdef BUILD_TLS_E(requirement == REnputES_RSA)
                return 1;
   TE;
        suites->suites[idx++] = TLS_Eurn 1;
        #ifdef SESSION_CERTS
    ssl->sessiDH_ECDSA_WITH_AES_256_GCM_SHA384nput           if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

#ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_RSA)_SHA
    = SHA256_DIGEST_SIZE;
 yright (C) 2006-201#endifpyright (C) 2006-}pyright (C) 2006-else if (hashAlgo == sha384_mac) {pyright (C) 2006-2014 ifdef CYASSL_SHA384pyright (C) 2006-2014rms digest = ssl->certHashes.is freopyright (C) 2006-2014ms of the Sz/* intfreel.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part}
pyright (C) 2L.
 doUserEcoftware; you can bute itHAVE_PK_CALLBACKSpyright (C) 2006-re GNU Genertx->EccVerifyCb(ssl, input + *inOutIdx, sz,of the , as published by
 * the Fublished by
 * the Free SoftRCHANTABILITY or FITNESS FOR A PARTICULAR PURP Genebuffers.peL is DsaKey.s.
 *
e the
 * GNU General Public License for more details.
 *
 * You should halengthRCHANTABILITY or FITNESS FOR A PARTICULAR PURP&vwitho,detailTY; withoutx)opyright (C) 2 wolfSSL Inc.
 *
 *s file is partCyaSSware; you can redierr = ecc_nc., 5_*
 *(the implied warranty of
 * MERPOSE.  See the
 * GNU General Public License for more dation, Inc., 51 Frank You should hFifth Floor, Boer version.
 *
 * C#incl= 0 && nc., 5
   1)pyright (C) 2006THOUT 0; /*clude ied */pyright (}
 wolfSSL Inc.
 ied warra += sz;r version.L.
 THOUT= 0h"
#endif

#if Geneoptions.havePeer witho = 1G_CYASSL) |returnESCAopyrigypto.h"
RU
 !NO_RSA ||e thatECCude pyrigint SendServerHelloDone( and/o*| deh"
#enware; you byteFOR A PARTICUL*outpu
       #includense for more de <sttwarRECORD_HEADER_SZ + HANDSHAKEif
#ifndefopyright (ndef TRUE
    #defiQX
  pyright (bute it and/orDTL useful,
 * buL.
  defined(CHACdtlsh"
#endif

#ifdefine TRUE+= ARGE_1
#endiEXTRA +ATIC_BLSE
    #d pleaopyright ( wolfSSL Inc.
 /* check for available sizeude "ntru_crL.
 efined C_SECANEGOTIATSize even ne TRU)) !(SHOW_SECRETS) ||SCALE_MQX
   defined(HAVget oue ims.
 *
ude "ntru_cro.h>
#GNU Genes.
 *
 *o.h>
#B.
 *
ave rec +pyright (C) 2006-2nt BuildMessage(CYASSL* ss; if nation and rAddHeaders(o.h>
#, 0 #erio.h_h
   _done1 Fra)_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #error \
CYASS HAVE_CONFIG_H
    AVE_RENEGOTDtlsPoolSav)
    # int typerror Cannot use both securth secure-reneg0l/ctaocrypt/asn.RS
#endif

#if fdef FREESCA = PublO.h>
#                    , 0Fifth Floor, Bo| define                      e-renegotiatibute it and/or will be useful,
 RS)
    #hsInfoOnh"
#endif

#ifAddPacketName("tdio.h>
    #en", &      andShake    Fifth FloorRS)
    #to                                              word32);
    timeou* sslword32*, word32);CHANTABILITY or FITNESS FOR      eap);pto.h"
#endif

# defined(CHAC

#ifnState/* iERVER_HELLODONE_COMPLETEation and r,
                        const d(DEBe TRU#ifdef FREESCALE_Me <sSSL* sed
   Fifth F}e* input, word32ARGE_STATclude <s>
    withoRequestdif
#endif

#ifdef __sun
    #in*       opyright ( #inclcookieRUE  COOKIEFALSE 0
#endif


#isl, con= VERSIONdef FAENUM_LEN +atic int SE 0
#endif


#iidx    TATIC_BUFFERS,f
#ifndef FAadd LARGE_STATIefine FALSE 0
#endif


#ine TRUE  sl, consentKSE 0
#endif


#iotiation and reneE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif

static int BuildMessage(CYASSL* ssl, byte* output, int outSz,
                        const byte* input, int inSz, int typ; if no ef NO_config.r word3SL_CLIENT
    stao.h>
#[idx++] =nt DoSechVersion.majoropyright (   getRecordLayerHeader,
    getDina,
     runProcessingOneMessa);
    static int DS)
    #ARRANCBIOCic ined(SNULL* input, word32* and/orMSG("Your , constcallback is null, please set"Fifth Floor, BoSCALE_MlientHeERRORopyright (DoServerHeAVE_RENEGOT, byte* digest, cons            fined(,nt SSL_hmRCHANTABILITY or FITNESS FOR A PARTICULAR  GeneIOCB_, const, F) <t use both secure-renegotiation and r const byte* input, word32*, word32);
    static ioServerKeyExchange(CYASSL*, const byte* input, word32*,
                                                                          word332);
    #ifndef NO_CERTS
        static int DoCertificateRequest(CYASSL* ssl, ajor == SSLv3_MAJOR && ssl-2*,
                                            rd32);
                     word32);
    #endif
    #ifdef HAVE_SESSION_TVERIFYREQU
 *

        static int DoSessionTicket(CYASSL* ssl, const byte* input, word32*,
                           llo(CYASSL* static     DoClientKeyExchangndif
#endif

,ndef NOthe i, word32{
   warrans.h>

#include <cyassl/internal.h>
#include <cyassl/    return (InitRTODO: ION) #ifdef __sun
   ndef TR HAVE_NToServerHeg(&rng)onst byteULL)
      def NOroce byte* LL)
        returbegin =#if defineifndef NO_O(void)const b(HAVshut up compiler warningsude "ntru_crout, 1oSSL_SERVER
 out, 1the iF_ENTROPY) {
   ON) F_ENTROPY) {
   rn (RG_CYASSL) || de);
    #endif
ideKeyE and/or E_SESSENDin, word32 sz,
             ntropy received c word2keyeROPY_CM, attack?

#ifndef NO_CER and/orBuilddif /*erroncluSIDt Build
#ifndef NO_CERTS
statd/orFATA >>  8)CertHashes(CS
        static ined(CHAC    ouifdef < CLIENTSION_Tjor == DToo */
void c32to24(word32 in, word2_MAJingt[0] = (in > at wrong 2*,


#ifndef NO_CERe <sAlerput, woa >> _fatal, unexpected_message
#ifndef NO_CERTS
statOUT_OF_ORifndCopyright ( void c32to#ifne itNO_CERTE_STATIC_BUFFERS)
    #error \
nc., 5EAD_#incord32 in, bytfailNoCertSL_CALLBACKS needs ssl! defined(CHACHA_AEAD_ 8) &tware; you can redistri                outdidn't presord2 You ral 

#ifndef NO_CERturn a > b ? b NO_PEER/
staopyright (C) 2006-DoServerHello(CYASSL* ssl, input, word32*,
                                                                     ntropy(ENTROPY_CM32);
    #ifndef NO_CERTS
            static int DoCertificateReques       Late 0xff;
    c[2] = (u32 >>  8) & 2*,
       Fifth Floorllo(CYASSL* ssl,switchndif /*specs.kea(NO_OLD_TLS)o opaque */RSApyright (C) 2c
#enrsa_kea:pyright (C) 2ware; you can redig(&rng)ntKe   if (cmd ==6(const Ruld ht[0]opyright (C) 2006- #incluyaSSL RsaINE vopyright (C) 2006-he hope that it will be useful,
 * but WISSL* ssl, byte* diRsaDecCbSL_CALLBACKS needs terms oford16) ((c[1opyright (C) 2006-llo(CYASSL* ssl,fndef min

   Inityte* c(&ke51 Frank       0xff;
    c[1] =  u1verKeyExcre-renegotiation and r
        static is.
 *
 *k have recnvert opaque to 32 bit constRsaPrivateKeyDecodtaticfdef HAVE_LIBZ

    , &ashSs.h>

#include <cyassl/internal.h>
#include <c= (c[0] << ef HAVE_LIBZ; if n| (c[1] << 16) | (cCyaS* alloc user allocs to wconvert RIVATE_KEY] << 8) | (c[1]));
| defined(SHOtware; you can redistrionst byteRsaEncryptION)
= (c| (c[1] << 16) | (c     consarrays->preMasterftwareECRET wor] << 8) | (c[1]));
UFFERS)
    #error \
yte* input, word32*,
  eger */
stat16ertifi* init zlib comp/decompL* ssl, Hif defined-urn (R) + OPAQUE16 word>) == 0) ? 1c_stream.zfree  = (free_C_TYPE_BUFF conuildCesl)
    {
        ssl->c_ato16endif

#include <cya&E_SEC     XFREE(memory, opaqf

#if defined(DEc)myAlloc;
  ssl->c_stream.opaque = (voAVE_RTODO: )ertific!A) || depaque, void* memory)
   defined(HAVE_CHACHA)h>
 explicitION) &doesd(HAmatch|| defined(HAVE_AESGCM)
ee  = (fFree  *u32 = (c     ssl->d_stream.zfree  = (frC_TYPE_RSABZ);
    BuildCertHashesL Inc.
 *
 * This file is part of t/asn.h>

#ifdef HA ssl->c_stream.zalloc = (alloc_funsl, con      sdidStreamInit = 1;

       ->d_stream.zallo 0xff;
 too big      ssl->d_stream.zfree  =ee_func)myFree;
        ssl->d_stream.opaqunc)myFree;
        sc_stream.zfree  = (fturn ZLIB_INIT_ERROR;

    eger */
sid FreeStreams(CYASSL* ssl)
}


#if defined(CYASSL_DTLS) || defined(HAVE_* but WITHOUT ANY WARRAN)

/* co even, byte* in, int inSz, byte* o   return ZLIhe implied warrantSERVER
 &of (ssl->version.major == SSLv3put, int outSz,
           Alloc(void*     ssl->c_stream.next_in   = in;
        ssl->c_stream.a; if not, write to the Free Software
 * Foundatiatic )

/* c, Fifth Floor, BoC) 2006-2014 wolfSSL Inc.
 *
 * Thissl->d_stream) != Z_OK) refdef HAVE_CONFIG_H
    allocs to work with zlibDeid)opInlineendif

#include <cya; if not, write to the Free Software
 * Foundation, unsigned int size)
    {

   {
        XFREE(memory, opaqturn ZLIB_INIT_ERROR;

if defined(DEconst byte* inputatic void myFree(void*  }


    /id FreeStreams(CYASSL* ssl)
XMEMCPYdif /*YNAMIC_TYPE_LIBZ);ecret     ,nt    currTo    ssl->d_stream.zfree  = ssl, byt     ssl->d_stream.next[0] !=     ssl->c_stream.next_in   = in;
      z;

        err = deflatr,
    getData,, byte* in, int inSz, byte* o||que, DYNAMIC_TYPE_LIBZ);am.nex1_out  = out;
        ssl->d_stream.avail_out = outSz;

        err = inflate(&ss;

#nvert opaque to 32 bit intcs to workPMS_* input,

        if (inflateInit(&ssl-em * size, opaque, DYNAMIallocs to workMak && err != Z_           r != Z_OK && err != Z_STREAM_END) return ZLIB_COMPRESS_ERROR;

        retur)ssl->heap;

        if (inflateInit(&s file is part of turn ZLIB_INIT_ERROee_func)myFree;
        ssl->ds file is partbreakFERS
#endif

#if defined(o opaque */PSK 8) | u24[2];
}


pskconvert opaque to 16 bit integer */
def NOpmses* hashrr != Z_OK && err != Z_        }
    }


eams(CYAi_BUG_CYASSL) | ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  =unc)myFree;
        ssl->c_stream.opaqidpf)ssl->heap;

        if = 0   ssl->d_stream.av_DEFAULT_COMPRESSION) != Z_OK)
            r sslhaveN > MAX /* _IDurrTo0;
    ctx->serverDH_G.buffe  out[0ID       ssl->c_stream.opaqstream.zalloc = (alloc_fun 0;    /r  = 0;
    ctx->serverDH_G.buffer  = 0;
#endif
    ctx->haveDH tal_out;

        ssl    ou_identityn the implied warranthaveNTRU           = 0;    /* start o  = 0;
    ctx->privateKserver_hint[0]     = 0;
    [min= 0;  ,/* start off */-1)Laye    static int opaque, DYNAMIC_TYor SSyRUE  );
    #endif
    #_ctx-c      int    err;
        iserver_hint[0]     = 0;
    ctHAVE_ECC
    ctx->ecn  = inSz;
        ssl* start KEY       (c[1] << 16) | (c[2] HAVE_ECC
    ctx->eccTem   #||     ssl->c_stream.next_in   = in;
     HAVE_ECC
    ctx->eccTe /* start    = 0;
0;
    ctx->serverDH_G.buffeceive;
       ssl->c_stream.opaq/* makee orAVE_ mLIBZ) s.nextude "ntru_cr     if (mesl, conoft[0]


    sta0s


    staIORecv   ecv _MAJOR) {
         c16toaINIT_E16)IO
    ctx->CBIORecv = ,
      ssl->d_stream.av    OMPRESSION) != Z_OK)
            rtal_SET(pmsype);
AVE_ECC
    ctx->eccTmbedGenerateCookie;
        ctx->CBIORecv   = NU#endif /* OPENSSL_EmbedSendTo;
            ctx->CBIOCookie = EmbedGenerateCookie;
        }
    #endif
#else
    /* user wiout;et */RVER)
    ctx->passwd   ctx->CBIORecv   = NULL;
    ctx->CBIOSeue, DYNAMIC_TYPE_LIBZ);
   HAVE_ECC
    ctx->eccTe* 2 + 4#endif /* OPENSSL_E   method->version    = pv;
 _DTLS
        if (meNo further needURE_RPSK ctx->CBIOSend   = Er will s ctx->CBIOSend = NetX_
    ctx->CBIORecv   = NULL;
    ctx->CBIOSeHAVE_ECC
    ctx->eccTemp    static int DoServerHeod = method;
    ctx->refthod-  /*  ctx->CBIOSehe hope thatNTRU 8) | u24[2];
}


ntruconvert opaque to 16 bit integer */
stater   pherLen   ctx->certChain.buffer plainLeRNG_ON) of = 1;          K && err != Z_
#endif /* OPENSSL_EXTRA6 & 0xef HAVE_LIBZ

    /* alloc user allocs to wYPE_LIBZ);
    }


    static void myFreeuffer  = 0;
    ctx->serverDH_P.buffer  = 0;
    ctx->serverDH_G.buffer  = 0;
#endif
    ctx->haveDH             = 0;
    ctx->haide */
TRU           = 0;    /* start off */
    ctx->haveECDSAsig       = 0ide */
EmbedReIENT_ENCRYPT_SZctx->CBIOSend = EmbedSend;
  e = 0fdef CYASSL_DTLS
        if eap               = ctx;  /*ctx->verifr  = 0;
    ctx->serverDH_G.buffer  = 0;
#endif
    ctx->haveDH  ssle = 0OK    x->haid)opo_x->had->c_st(thod, ProtocolVersion pv)
{
 dTo;
         t;
        ssl->c_stream.avail_out = outSz;

   atic void* myAlloc(void* CacheFlusn  = inSz;
        ssl->c_stresl->heap;

        iC = 1;  dif
#ifdef HAVE_TLS_EXTENSIONS
     can turn on by loading >failNoCert = 0;
    ctx->sessionCDE    ctVerify = 0;
    ctx->quietShC = 1;   !int    currTo
    #ifdef HAVE_ECC
        ctx->EccSignCb   = NULL;
        ctxpsk_cb      = 0ide */
  rtialWrite   = 0;
    ctx->verifyCallback = C = 1;          }
    }


   method->version    = pv;
    method->sading key */
#endif
#ifdef HAVE_ECC
   SL_CLIENTethod->side == CYASSL_CLECC 8) | u24[2];
}


de <diffiedef Nmanconvert opaque to 16 bit integer */
r didn't set, add psk later */
 8P.buffer  = 0;
    ctx->serverDH_G.buffer  = 0;
#endif
    ctx->haveDH onst bytent)ss[am.zalloc )++]e DH later if server didn't set, add psk late    static voi;  /* initially on */
    ctx->sendVerify = 0;
    ctx->quietSh.h>
#includeKeyPE_AESC) {f (medod(HAleak o_MQXus && defined(HYASSL_METHOD*cc_frestatic e(CYASSL_C   ssl->d_stream.avail_ceFree(CYASSL_CTX* ctx* HAVE_ANON */
#ifdef YPE_METHini = pvfndef NO_CERTS
    XFREE(ctx->sturn ZLIB_INIT_ERROVE_LIREE(mport_x963otal_out - currTotal;
    }erDH_G.buffer, cKS
    #ifdef HAVE_ECC
       ECCt 32 fdef CYASSL_DTLS
        if * out,int outSz)
    n   = in;
        ssl.buffer, ctx->heap,  #ifdef FREE     return BAD_C   /* server can turn on by loading key */
    }
#endif
   {
    *u32 tic by_ecd->didStreamInit = 1;

   E(ctecv tic byKword16* u16)
{
    * */
static I(c[0] << 8) | (c[1]));
   XFREE(ctx-&TX* ctx)
   ssl->d_stream.avail_ constEccth zlib */
    static void* myAlloc(void* opue, unsigned int item, unsigned int size)
   
        C     (void)opaque;
        r       }
    }


    | defined(SHOW_SECRETS) ||Couldn't lock counE(ctshared_== DTL{
        CMIC_TYPE_KEY);
  ue, unsigned int item, unsigned int size)
 

        ssl->d_stream.next_i&x->countMutex);

    if (doFreMETHOD);

        CYASSL_MSG("Couldn'ts file is part of CyaSSware; you can redistri ssl, byteccTemp, ctx->heap,* opaque, void* memory)
   sl)
    {
      Ecc ephemeral     noloc;de correctly      ssl->d_stream.zfree  =k countCC_MAKEfdef CYASSLt, return 0 on succesurn ZLIB_COMPRESS_ERROR;

        retuto 0, doing full f
    }
}


/* S,   SSL_CtxResourceFree(ctx);
        FreeMutex(&ctx->countMutex);
        XFREE(ctx, ctx->heap, DYt, return 0 on success */
int InitSSL_Ctx(CYASSL_CTX* ctx[2] << 8) | cXFREE(ctx->certificate.buffer, cSHARE/* start off */
    ctx->hue, DYNAMIC_TYPE_LIBZ);
   certChain.buffer, ctx->hb    = NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

    if (InitMute
      ount = 1;          DH 8) | u24[2];
}


error on CTX init");
        return BAD_MUTEX_E;
 n cliet tropyPub static int if
    sDh* c, d->ene DH later if server didn't set, add psk later */
    InitSuites(&ctx->suites, method->version, TRUE, FALSE, TRUE, ctx->haveNTRU,
               ctx->hly1305 = NTRU           = 0;    /* start off */
    ctx->haveECDSAsig       =              = ctx;  /ly1305 = NhOff = 0;  /* initially on */
    ctx->sendVerify = 0;
    ctx->qui{
  l->en(&ypt.sELLIA
    ssl->encr       hSey(EN
    }
     (void)opaq

#ifnDH_Pave received a copy of the GNU General Public Lil->heap, DYNAMIC_TYPE_CI; if not, write to the Free Software
 * Foundatl->heap, DYNAMIC_TYPE_GIPHER);
    XFREE(ssl->decrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
G
        return XMALLOC(ite) {
        CYASSL_MSG("CTX ref cE(ssl->eAg elserc4, ssl->he     ssl->d_stream.next_  = out;
        ssl->d_stream.avail_out =;
    YNAMIC_TYPE_LIBZ);
ue, unsigned int item, unsigned int size)
  l->heap, DYNAMIC_TYPE_Crivave received a copy of the GNU General Public Licen
    if (ssl->devId != NO_C; if not, write to the Free Software
 * Foundationx->client_psk_cb    
{
    (void)ssl;
#ifdef BUILee_frc4);
    }
   ctx->RsaSignCb   = NULL;
      ly1305 = NUL(c[1] << 16) | (c[2] << 8
    }
    #endif
    XFREE(ssl- NULL;
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

    if (IniULL;
ethod->side ==  !defined(ULL;
)#incdif
#ifdef HPSKifdef HAVE_HC1ypt.chhe_SIZESSL_free can release */
#ifndef NO_CERTS
    ctx->certificate.buffer = 0;
    ctx->certChain.buffer   out[6NULL;
#endif
    ssl->encrypt.setup = 0;
    ssl->/* Read in theIENT_hcludtx->heap, DYNAMIC_Tdecrypt.setup = 0;
#ifdef HAVE_ONE_TIME_AUTH
    ssl->auth.setup    = 0;
#endif
}


/* Free ciphers */
void FreeCiphers(CYASSL* ssl)
{
  void)ssl;
#ifdef BUILD_ARC4
    #ifdef HAVE_CAVIhaveECDSAsig       =     XFR  /* start off */
    ctx->haveStaticECC      = 0;    /* start off */
    ctx->heap               = ctx;  /def HAVE_Plts to self */
#ifndef NO_PSK
    ctx->havePSK            = 0;
    ctx->server_hint[0]     = 0;
    c  = out;
        ssl->d_stream.avail_out = outSz;

 l->encrypt.aes, ssl->heapvoid)ssl;
#ifdef BUILD_ARC4
    #i BUILD_RABBIT
    XFREE(ss#ifdef HAVE_ANON
    ctx->haveAnon   = IN       = 0;
#endif /*   = out;
        ssl->d_stream.avail_out = outSz;

        e 0;
}

static void 0] << 8) | (c[1]));
YNAMIC_TYPE_CIPDHE businesT_NUM_BYTES_P>decrypt.rabbit, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CHACHA
    XFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.chacha, ssl->heap, DYNAMIC_TYPUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
     Arc4FreeCavium(ssl->encrypt.arc4);
        Arc4FreeCavium(ssl->decrypt.arc4);
    }
    #endif
    XFREE(ssl->encrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_DES3
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        Des3_FreeCavium(ssl->encrypt.des3);
        Des3_FreeCavium(ssl->decrypt.des3);
    }
    #endif
    XFREE(ssl->encrypt.des3, s
    PRESSION) !=     cs->mac_algorithm         = INVALID_BYTE DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_AES
    #ifdef HAVE_CAVIUM
    if (ssl->devId != NO_CAVIUM_DEVICE) {
        AesFreeCavium(ssl->encrypt.aes);
        AesFreeCavium(ssl->decrypt.aes);
    }
    #endif
    XFREE(ssl->encrypt.aes, ssl->heapYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.aes, ssl->heap, DYNAMIC_TYPE_CIP_RABBIT
    XFREE(ssmbedSendTo;
   DYNAMIC_TYPE_CIPHER);
#en = EmbedGenerateCookie;ue, DYNAMIC_TYPE_LIBZ);
 heap, DYNAMIC_TYPE_CIPHER);
#endind   = NULL;
    #ifdPE_LIBZ);
VE_NTRU
    if (methodUseE_CIPHER);
   to look;

 _CIPHER)and add iites(th* size, opaque, DYN*AVE_&& err != Z_ here.  XFREE(ssl->decryptHAVE_ECC
    ctx->eccTempKeySz       = ECDHE_SIZE;
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    ctx->passwd_cb   = 0;
    ctx->userdata    = 0;
#endif /* OPENSSL_EXTRA */

    ctx->timeout = CYASSL_SESSION_TIMEOUT;

#ifndef CYASSL_USER_IO
    ctx->CBIORecv = EmbedReceive;
    ctx->CBIOSend = EmbedSend;
    #ifdef CYASSL_DTLS
        if >CBIOCookie = NULL;
    #endif
#endif /* CYASSL_USER_IO */
#ifdef HAVE_NETX
    ctx->CBIORecv = NetX_Receive;
    ctx->CBIOSend = NetX_Send;
#endif
    ctx->partialWrite   = 0;
    ctx->verifyCallback +_size    = 0;
    cs->iv_size     = 0;
    cHAVE_ECC
    ctx->eccTe     suites->h (c[1] << 16) | (c[2] << 8A
    XFREE(ssl->encrypt.cam, ssl->heap, DYNAMIC_TYPE_C_NTRU
    if (method->side == CYASSL_CLIENT_END)
        ctx->haveNTRU = 1;           /* always on cliet side */
                                     /* server can turn on by loading key */
#endif
#ifdef HAVE_ECC
   fio.DH_HC12 if (method->side ms ofefaultert opaque to 16 bit integer */
            Bad kea typ0xff;
    out[4] XFREE(ssl-BAD_KEA_TYPEonvert 16 bi#endif /* HAVE_PK_CALLBACKS */

  void c32tohod->side == CYASSL_CLIEMS  XFREE(ssl-aveNTRU = 1;          >d_stream.next_i
    ctx->CBIORecPE_LIBZ);
ELLIA
    sue, DYNAMIC_TYPE_LIBZ);
   0] << 8) | (Free(void* opaque, void* memord32 in, byte out[6])
{
= = 0;   KEYEXCHANGET
        s   static int mpaque */
static INLINE voi void c16toa(word16 u16, byte* ifdef HAVE_HC128
    ssl-minouild 8) Public even ;
    ral PublicFifth Floor, Boston, MA 02110- void c32toSCALE_MQX
         #include < */
 used by ssl  XF