/* ssl.c
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

#ifdef HAVE_ERRNO_H
    #include <errno.h>
#endif

#include <cyassl/ssl.h>
#include <cyassl/internal.h>
#include <cyassl/error-ssl.h>
#include <cyassl/ctaocrypt/coding.h>

#ifdef __MORPHOS__
#include <proto/socket.h>
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    #include <cyassl/openssl/evp.h>
#endif

#ifdef OPENSSL_EXTRA
    /* openssl headers begin */
    #include <cyassl/openssl/hmac.h>
    #include <cyassl/openssl/crypto.h>
    #include <cyassl/openssl/des.h>
    #include <cyassl/openssl/bn.h>
    #include <cyassl/openssl/dh.h>
    #include <cyassl/openssl/rsa.h>
    #include <cyassl/openssl/pem.h>
    /* openssl headers end, cyassl internal headers next */
    #include <cyassl/ctaocrypt/hmac.h>
    #include <cyassl/ctaocrypt/random.h>
    #include <cyassl/ctaocrypt/des3.h>
    #include <cyassl/ctaocrypt/md4.h>
    #include <cyassl/ctaocrypt/md5.h>
    #include <cyassl/ctaocrypt/arc4.h>
    #ifdef CYASSL_SHA512
        #include <cyassl/ctaocrypt/sha512.h>
    #endif
#endif

#ifndef NO_FILESYSTEM
    #if !defined(USE_WINDOWS_API) && !defined(NO_CYASSL_DIR) \
            && !defined(EBSNET)
        #include <dirent.h>
        #include <sys/stat.h>
    #endif
    #ifdef EBSNET
        #include "vfapi.h"
        #include "vfile.h"
    #endif
#endif /* NO_FILESYSTEM */

#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */

#ifndef max
#ifdef CYASSL_DTLS
    static INLINE word32 max(word32 a, word32 b)
    {
        return a > b ? a : b;
    }
#endif
#endif /* min */


#ifndef CYASSL_LEANPSK
char* mystrnstr(const char* s1, const char* s2, unsigned int n)
{
    unsigned int s2_len = (unsigned int)XSTRLEN(s2);

    if (s2_len == 0)
        return (char*)s1;

    while (n >= s2_len && s1[0]) {
        if (s1[0] == s2[0])
            if (XMEMCMP(s1, s2, s2_len) == 0)
                return (char*)s1;
        s1++;
        n--;
    }

    return NULL;
}
#endif


/* prevent multiple mutex initializations */
static volatile int initRefCount = 0;
static CyaSSL_Mutex count_mutex;   /* init ref count mutex */

#ifdef __MORPHOS__
struct ExecBase *SysBase = NULL;
#endif

CYASSL_CTX* __saveds CyaSSL_CTX_new(CYASSL_METHOD* method)
{
    CYASSL_CTX* ctx = NULL;

    CYASSL_ENTER("CYASSL_CTX_new");

    if (initRefCount == 0)
        CyaSSL_Init(); /* user no longer forced to call Init themselves */

    if (method == NULL)
        return ctx;

    ctx = (CYASSL_CTX*) XMALLOC(sizeof(CYASSL_CTX), 0, DYNAMIC_TYPE_CTX);
    if (ctx) {
        if (InitSSL_Ctx(ctx, method) < 0) {
            CYASSL_MSG("Init CTX failed");
            CyaSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }
    else {
        CYASSL_MSG("Alloc CTX failed, method freed");
        XFREE(method, NULL, DYNAMIC_TYPE_METHOD);
    }

    CYASSL_LEAVE("CYASSL_CTX_new", 0);
    return ctx;
}

#ifdef __MORPHOS__
void CyaSSL_set_socketbase(CYASSL* ssl, struct Library *socketbase)
{
    SSL_set_socketbase(ssl, socketbase);
}
#endif

void CyaSSL_CTX_free(CYASSL_CTX* ctx)
{
    CYASSL_ENTER("SSL_CTX_free");
    if (ctx)
        FreeSSL_Ctx(ctx);
    CYASSL_LEAVE("SSL_CTX_free", 0);
}


CYASSL* CyaSSL_new(CYASSL_CTX* ctx)
{
    CYASSL* ssl = NULL;
    int ret = 0;

    (void)ret;
    CYASSL_ENTER("SSL_new");

    if (ctx == NULL)
        return ssl;

    ssl = (CYASSL*) XMALLOC(sizeof(CYASSL), ctx->heap,DYNAMIC_TYPE_SSL);
    if (ssl)
        if ( (ret = InitSSL(ssl, ctx)) < 0) {
            FreeSSL(ssl);
            ssl = 0;
        }

    CYASSL_LEAVE("SSL_new", ret);
    return ssl;
}


void CyaSSL_free(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_free");
    if (ssl)
        FreeSSL(ssl);
    CYASSL_LEAVE("SSL_free", 0);
}

#ifdef HAVE_POLY1305
/* set if to use old poly 1 for yes 0 to use new poly */
int CyaSSL_use_old_poly(CYASSL* ssl, int value)
{
    CYASSL_ENTER("SSL_use_old_poly");
    ssl->options.oldPoly = value;
    CYASSL_LEAVE("SSL_use_old_poly", 0);
    return 0;
}
#endif

int CyaSSL_set_fd(CYASSL* ssl, int fd)
{
    CYASSL_ENTER("SSL_set_fd");
    ssl->rfd = fd;      /* not used directly to allow IO callbacks */
    ssl->wfd = fd;

    ssl->IOCB_ReadCtx  = &ssl->rfd;
    ssl->IOCB_WriteCtx = &ssl->wfd;

    #ifdef CYASSL_DTLS
        if (ssl->options.dtls) {
            ssl->IOCB_ReadCtx = &ssl->buffers.dtlsCtx;
            ssl->IOCB_WriteCtx = &ssl->buffers.dtlsCtx;
            ssl->buffers.dtlsCtx.fd = fd;
        }
    #endif

    CYASSL_LEAVE("SSL_set_fd", SSL_SUCCESS);
    return SSL_SUCCESS;
}


int CyaSSL_get_ciphers(char* buf, int len)
{
    const char* const* ciphers = GetCipherNames();
    int  totalInc = 0;
    int  step     = 0;
    char delim    = ':';
    int  size     = GetCipherNamesSize();
    int  i;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimitted by a : */
    for (i = 0; i < size; i++) {
        step = (int)(XSTRLEN(ciphers[i]) + 1);  /* delimiter */
        totalInc += step;

        /* Check to make sure buf is large enough and will not overflow */
        if (totalInc < len) {
            XSTRNCPY(buf, ciphers[i], XSTRLEN(ciphers[i]));
            buf += XSTRLEN(ciphers[i]);

            if (i < size - 1)
                *buf++ = delim;
        }
        else
            return BUFFER_E;
    }
    return SSL_SUCCESS;
}


int CyaSSL_get_fd(const CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_fd");
    CYASSL_LEAVE("SSL_get_fd", ssl->rfd);
    return ssl->rfd;
}


int CyaSSL_get_using_nonblock(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_get_using_nonblock");
    CYASSL_LEAVE("CyaSSL_get_using_nonblock", ssl->options.usingNonblock);
    return ssl->options.usingNonblock;
}


int CyaSSL_dtls(CYASSL* ssl)
{
    return ssl->options.dtls;
}


#ifndef CYASSL_LEANPSK
void CyaSSL_set_using_nonblock(CYASSL* ssl, int nonblock)
{
    CYASSL_ENTER("CyaSSL_set_using_nonblock");
    ssl->options.usingNonblock = (nonblock != 0);
}


int CyaSSL_dtls_set_peer(CYASSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef CYASSL_DTLS
    void* sa = (void*)XMALLOC(peerSz, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    if (sa != NULL) {
        if (ssl->buffers.dtlsCtx.peer.sa != NULL)
            XFREE(ssl->buffers.dtlsCtx.peer.sa,ssl->heap,DYNAMIC_TYPE_SOCKADDR);
        XMEMCPY(sa, peer, peerSz);
        ssl->buffers.dtlsCtx.peer.sa = sa;
        ssl->buffers.dtlsCtx.peer.sz = peerSz;
        return SSL_SUCCESS;
    }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}

int CyaSSL_dtls_get_peer(CYASSL* ssl, void* peer, unsigned int* peerSz)
{
#ifdef CYASSL_DTLS
    if (peer != NULL && peerSz != NULL
            && *peerSz >= ssl->buffers.dtlsCtx.peer.sz) {
        *peerSz = ssl->buffers.dtlsCtx.peer.sz;
        XMEMCPY(peer, ssl->buffers.dtlsCtx.peer.sa, *peerSz);
        return SSL_SUCCESS;
    }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}
#endif /* CYASSL_LEANPSK */


/* return underlyig connect or accept, SSL_SUCCESS on ok */
int CyaSSL_negotiate(CYASSL* ssl)
{
    int err = SSL_FATAL_ERROR;

    CYASSL_ENTER("CyaSSL_negotiate");
#ifndef NO_CYASSL_SERVER
    if (ssl->options.side == CYASSL_SERVER_END)
        err = CyaSSL_accept(ssl);
#endif

#ifndef NO_CYASSL_CLIENT
    if (ssl->options.side == CYASSL_CLIENT_END)
        err = CyaSSL_connect(ssl);
#endif

    CYASSL_LEAVE("CyaSSL_negotiate", err);

    return err;
}


#ifndef CYASSL_LEANPSK
/* object size based on build */
int CyaSSL_GetObjectSize(void)
{
#ifdef SHOW_SIZES
    printf("sizeof suites           = %lu\n", sizeof(Suites));
    printf("sizeof ciphers(2)       = %lu\n", sizeof(Ciphers));
#ifndef NO_RC4
    printf("    sizeof arc4         = %lu\n", sizeof(Arc4));
#endif
    printf("    sizeof aes          = %lu\n", sizeof(Aes));
#ifndef NO_DES3
    printf("    sizeof des3         = %lu\n", sizeof(Des3));
#endif
#ifndef NO_RABBIT
    printf("    sizeof rabbit       = %lu\n", sizeof(Rabbit));
#endif
#ifdef HAVE_CHACHA
    printf("    sizeof chacha       = %lu\n", sizeof(Chacha));
#endif
    printf("sizeof cipher specs     = %lu\n", sizeof(CipherSpecs));
    printf("sizeof keys             = %lu\n", sizeof(Keys));
    printf("sizeof Hashes(2)        = %lu\n", sizeof(Hashes));
#ifndef NO_MD5
    printf("    sizeof MD5          = %lu\n", sizeof(Md5));
#endif
#ifndef NO_SHA
    printf("    sizeof SHA          = %lu\n", sizeof(Sha));
#endif
#ifndef NO_SHA256
    printf("    sizeof SHA256       = %lu\n", sizeof(Sha256));
#endif
#ifdef CYASSL_SHA384
    printf("    sizeof SHA384       = %lu\n", sizeof(Sha384));
#endif
#ifdef CYASSL_SHA384
    printf("    sizeof SHA512       = %lu\n", sizeof(Sha512));
#endif
    printf("sizeof Buffers          = %lu\n", sizeof(Buffers));
    printf("sizeof Options          = %lu\n", sizeof(Options));
    printf("sizeof Arrays           = %lu\n", sizeof(Arrays));
#ifndef NO_RSA
    printf("sizeof RsaKey           = %lu\n", sizeof(RsaKey));
#endif
#ifdef HAVE_ECC
    printf("sizeof ecc_key          = %lu\n", sizeof(ecc_key));
#endif
    printf("sizeof CYASSL_CIPHER    = %lu\n", sizeof(CYASSL_CIPHER));
    printf("sizeof CYASSL_SESSION   = %lu\n", sizeof(CYASSL_SESSION));
    printf("sizeof CYASSL           = %lu\n", sizeof(CYASSL));
    printf("sizeof CYASSL_CTX       = %lu\n", sizeof(CYASSL_CTX));
#endif

    return sizeof(CYASSL);
}
#endif


#ifndef NO_DH
/* server Diffie-Hellman parameters, SSL_SUCCESS on ok */
int CyaSSL_SetTmpDH(CYASSL* ssl, const unsigned char* p, int pSz,
                    const unsigned char* g, int gSz)
{
    byte havePSK = 0;
    byte haveRSA = 1;

    CYASSL_ENTER("CyaSSL_SetTmpDH");
    if (ssl == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

    if (ssl->options.side != CYASSL_SERVER_END)
        return SIDE_ERROR;

    if (ssl->buffers.serverDH_P.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);

    ssl->buffers.weOwnDH = 1;  /* SSL owns now */
    ssl->buffers.serverDH_P.buffer = (byte*)XMALLOC(pSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_P.buffer == NULL)
        return MEMORY_E;

    ssl->buffers.serverDH_G.buffer = (byte*)XMALLOC(gSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer == NULL) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
        return MEMORY_E;
    }

    ssl->buffers.serverDH_P.length = pSz;
    ssl->buffers.serverDH_G.length = gSz;

    XMEMCPY(ssl->buffers.serverDH_P.buffer, p, pSz);
    XMEMCPY(ssl->buffers.serverDH_G.buffer, g, gSz);

    ssl->options.haveDH = 1;
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif
    #ifdef NO_RSA
        haveRSA = 0;
    #endif
    InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, ssl->options.haveDH,
               ssl->options.haveNTRU, ssl->options.haveECDSAsig,
               ssl->options.haveStaticECC, ssl->options.side);

    CYASSL_LEAVE("CyaSSL_SetTmpDH", 0);
    return SSL_SUCCESS;
}
#endif /* !NO_DH */


int CyaSSL_write(CYASSL* ssl, const void* data, int sz)
{
    int ret;

    CYASSL_ENTER("SSL_write()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

#ifdef HAVE_ERRNO_H
    errno = 0;
#endif

    ret = SendData(ssl, data, sz);

    CYASSL_LEAVE("SSL_write()", ret);

    if (ret < 0)
        return SSL_FATAL_ERROR;
    else
        return ret;
}


static int CyaSSL_read_internal(CYASSL* ssl, void* data, int sz, int peek)
{
    int ret;

    CYASSL_ENTER("CyaSSL_read_internal()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

#ifdef HAVE_ERRNO_H
        errno = 0;
#endif
#ifdef CYASSL_DTLS
    if (ssl->options.dtls)
        ssl->dtls_expected_rx = max(sz + 100, MAX_MTU);
#endif

#ifdef HAVE_MAX_FRAGMENT
    ret = ReceiveData(ssl, (byte*)data,
                     min(sz, min(ssl->max_fragment, OUTPUT_RECORD_SIZE)), peek);
#else
    ret = ReceiveData(ssl, (byte*)data, min(sz, OUTPUT_RECORD_SIZE), peek);
#endif

    CYASSL_LEAVE("CyaSSL_read_internal()", ret);

    if (ret < 0)
        return SSL_FATAL_ERROR;
    else
        return ret;
}


int CyaSSL_peek(CYASSL* ssl, void* data, int sz)
{
    CYASSL_ENTER("CyaSSL_peek()");

    return CyaSSL_read_internal(ssl, data, sz, TRUE);
}


int CyaSSL_read(CYASSL* ssl, void* data, int sz)
{
    CYASSL_ENTER("CyaSSL_read()");

    return CyaSSL_read_internal(ssl, data, sz, FALSE);
}


#ifdef HAVE_CAVIUM

/* let's use cavium, SSL_SUCCESS on ok */
int CyaSSL_UseCavium(CYASSL* ssl, int devId)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->devId = devId;

    return SSL_SUCCESS;
}


/* let's use cavium, SSL_SUCCESS on ok */
int CyaSSL_CTX_UseCavium(CYASSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->devId = devId;

    return SSL_SUCCESS;
}


#endif /* HAVE_CAVIUM */

#ifdef HAVE_SNI

int CyaSSL_UseSNI(CYASSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size);
}

int CyaSSL_CTX_UseSNI(CYASSL_CTX* ctx, byte type, const void* data, word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size);
}

#ifndef NO_CYASSL_SERVER

void CyaSSL_SNI_SetOptions(CYASSL* ssl, byte type, byte options)
{
    if (ssl && ssl->extensions)
        TLSX_SNI_SetOptions(ssl->extensions, type, options);
}

void CyaSSL_CTX_SNI_SetOptions(CYASSL_CTX* ctx, byte type, byte options)
{
    if (ctx && ctx->extensions)
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
}

byte CyaSSL_SNI_Status(CYASSL* ssl, byte type)
{
    return TLSX_SNI_Status(ssl ? ssl->extensions : NULL, type);
}

word16 CyaSSL_SNI_GetRequest(CYASSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data);

    return 0;
}

int CyaSSL_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz, byte type,
                                                     byte* sni, word32* inOutSz)
{
    if (clientHello && helloSz > 0 && sni && inOutSz && *inOutSz > 0)
        return TLSX_SNI_GetFromBuffer(clientHello, helloSz, type, sni, inOutSz);

    return BAD_FUNC_ARG;
}

#endif /* NO_CYASSL_SERVER */

#endif /* HAVE_SNI */


#ifdef HAVE_MAX_FRAGMENT
#ifndef NO_CYASSL_CLIENT
int CyaSSL_UseMaxFragment(CYASSL* ssl, byte mfl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ssl->extensions, mfl);
}

int CyaSSL_CTX_UseMaxFragment(CYASSL_CTX* ctx, byte mfl)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ctx->extensions, mfl);
}
#endif /* NO_CYASSL_CLIENT */
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_CYASSL_CLIENT
int CyaSSL_UseTruncatedHMAC(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ssl->extensions);
}

int CyaSSL_CTX_UseTruncatedHMAC(CYASSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ctx->extensions);
}
#endif /* NO_CYASSL_CLIENT */
#endif /* HAVE_TRUNCATED_HMAC */

/* Elliptic Curves */
#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_CYASSL_CLIENT

int CyaSSL_UseSupportedCurve(CYASSL* ssl, word16 name)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (name) {
        case CYASSL_ECC_SECP160R1:
        case CYASSL_ECC_SECP192R1:
        case CYASSL_ECC_SECP224R1:
        case CYASSL_ECC_SECP256R1:
        case CYASSL_ECC_SECP384R1:
        case CYASSL_ECC_SECP521R1:
            break;

        default:
            return BAD_FUNC_ARG;
    }

    return TLSX_UseSupportedCurve(&ssl->extensions, name);
}

int CyaSSL_CTX_UseSupportedCurve(CYASSL_CTX* ctx, word16 name)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    switch (name) {
        case CYASSL_ECC_SECP160R1:
        case CYASSL_ECC_SECP192R1:
        case CYASSL_ECC_SECP224R1:
        case CYASSL_ECC_SECP256R1:
        case CYASSL_ECC_SECP384R1:
        case CYASSL_ECC_SECP521R1:
            break;

        default:
            return BAD_FUNC_ARG;
    }

    return TLSX_UseSupportedCurve(&ctx->extensions, name);
}

#endif /* NO_CYASSL_CLIENT */
#endif /* HAVE_SUPPORTED_CURVES */

/* Secure Renegotiation */
#ifdef HAVE_SECURE_RENEGOTIATION

/* user is forcing ability to use secure renegotiation, we discourage it */
int CyaSSL_UseSecureRenegotiation(CYASSL* ssl)
{
    int ret = BAD_FUNC_ARG;

    if (ssl)
        ret = TLSX_UseSecureRenegotiation(&ssl->extensions);

    if (ret == SSL_SUCCESS) {
        TLSX* extension = TLSX_Find(ssl->extensions, SECURE_RENEGOTIATION);
        
        if (extension)
            ssl->secure_renegotiation = (SecureRenegotiation*)extension->data;
    }

    return ret;
}


/* do a secure renegotiation handshake, user forced, we discourage */
int CyaSSL_Rehandshake(CYASSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->secure_renegotiation == NULL) {
        CYASSL_MSG("Secure Renegotiation not forced on by user");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation->enabled == 0) {
        CYASSL_MSG("Secure Renegotiation not enabled at extension level");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        CYASSL_MSG("Can't renegotiate until previous handshake complete");
        return SECURE_RENEGOTIATION_E;
    }

#ifndef NO_FORCE_SCR_SAME_SUITE
    /* force same suite */
    if (ssl->suites) {
        ssl->suites->suiteSz = SUITE_LEN;
        ssl->suites->suites[0] = ssl->options.cipherSuite0;
        ssl->suites->suites[1] = ssl->options.cipherSuite;
    }
#endif

    /* reset handshake states */
    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState  = CONNECT_BEGIN;
    ssl->options.acceptState   = ACCEPT_BEGIN;
    ssl->options.handShakeState = NULL_STATE;
    ssl->options.processReply  = 0;  /* TODO, move states in internal.h */

    XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

    ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;

#ifndef NO_OLD_TLS
#ifndef NO_MD5
    InitMd5(&ssl->hashMd5);
#endif
#ifndef NO_SHA
    ret = InitSha(&ssl->hashSha);
    if (ret !=0)
        return ret;
#endif
#endif /* NO_OLD_TLS */
#ifndef NO_SHA256
    ret = InitSha256(&ssl->hashSha256);
    if (ret !=0)
        return ret;
#endif
#ifdef CYASSL_SHA384
    ret = InitSha384(&ssl->hashSha384);
    if (ret !=0)
        return ret;
#endif

    ret = CyaSSL_negotiate(ssl);
    return ret;
}

#endif /* HAVE_SECURE_RENEGOTIATION */

/* Session Ticket */
#if !defined(NO_CYASSL_CLIENT) && defined(HAVE_SESSION_TICKET)
int CyaSSL_UseSessionTicket(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ssl->extensions, NULL);
}

int CyaSSL_CTX_UseSessionTicket(CYASSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ctx->extensions, NULL);
}

CYASSL_API int CyaSSL_get_SessionTicket(CYASSL* ssl, byte* buf, word32* bufSz)
{
    if (ssl == NULL || buf == NULL || bufSz == NULL || *bufSz == 0)
        return BAD_FUNC_ARG;

    if (ssl->session.ticketLen <= *bufSz) {
        XMEMCPY(buf, ssl->session.ticket, ssl->session.ticketLen);
        *bufSz = ssl->session.ticketLen;
    }
    else
        *bufSz = 0;

    return SSL_SUCCESS;
}

CYASSL_API int CyaSSL_set_SessionTicket(CYASSL* ssl, byte* buf, word32 bufSz)
{
    if (ssl == NULL || (buf == NULL && bufSz > 0))
        return BAD_FUNC_ARG;

    if (bufSz > 0)
        XMEMCPY(ssl->session.ticket, buf, bufSz);
    ssl->session.ticketLen = bufSz;

    return SSL_SUCCESS;
}


CYASSL_API int CyaSSL_set_SessionTicket_cb(CYASSL* ssl,
                                            CallbackSessionTicket cb, void* ctx)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->session_ticket_cb = cb;
    ssl->session_ticket_ctx = ctx;

    return SSL_SUCCESS;
}
#endif

#ifndef CYASSL_LEANPSK

int CyaSSL_send(CYASSL* ssl, const void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    CYASSL_ENTER("CyaSSL_send()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->wflags;

    ssl->wflags = flags;
    ret = CyaSSL_write(ssl, data, sz);
    ssl->wflags = oldFlags;

    CYASSL_LEAVE("CyaSSL_send()", ret);

    return ret;
}


int CyaSSL_recv(CYASSL* ssl, void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    CYASSL_ENTER("CyaSSL_recv()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->rflags;

    ssl->rflags = flags;
    ret = CyaSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    CYASSL_LEAVE("CyaSSL_recv()", ret);

    return ret;
}
#endif


/* SSL_SUCCESS on ok */
int CyaSSL_shutdown(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_shutdown()");

    if (ssl == NULL)
        return SSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        CYASSL_MSG("quiet shutdown, no close notify sent");
        return SSL_SUCCESS;
    }

    /* try to send close notify, not an error if can't */
    if (!ssl->options.isClosed && !ssl->options.connReset &&
                                  !ssl->options.sentNotify) {
        ssl->error = SendAlert(ssl, alert_warning, close_notify);
        if (ssl->error < 0) {
            CYASSL_ERROR(ssl->error);
            return SSL_FATAL_ERROR;
        }
        ssl->options.sentNotify = 1;  /* don't send close_notify twice */
    }

    CYASSL_LEAVE("SSL_shutdown()", ssl->error);

    ssl->error = SSL_ERROR_SYSCALL;   /* simulate OpenSSL behavior */

    return SSL_SUCCESS;
}


int CyaSSL_get_error(CYASSL* ssl, int ret)
{
    CYASSL_ENTER("SSL_get_error");

    if (ret > 0)
        return SSL_ERROR_NONE;
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    CYASSL_LEAVE("SSL_get_error", ssl->error);

    /* make sure converted types are handled in SetErrorString() too */
    if (ssl->error == WANT_READ)
        return SSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WANT_WRITE)
        return SSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    else if (ssl->error == ZERO_RETURN)
        return SSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
    return ssl->error;
}


/* retrive alert history, SSL_SUCCESS on ok */
int CyaSSL_get_alert_history(CYASSL* ssl, CYASSL_ALERT_HISTORY *h)
{
    if (ssl && h) {
        *h = ssl->alert_history;
    }
    return SSL_SUCCESS;
}


/* return TRUE if current error is want read */
int CyaSSL_want_read(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_read");
    if (ssl->error == WANT_READ)
        return 1;

    return 0;
}


/* return TRUE if current error is want write */
int CyaSSL_want_write(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_write");
    if (ssl->error == WANT_WRITE)
        return 1;

    return 0;
}


char* CyaSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    static const char* msg = "Please supply a buffer for error string";

    CYASSL_ENTER("ERR_error_string");
    if (data) {
        SetErrorString((int)errNumber, data);
        return data;
    }

    return (char*)msg;
}


void CyaSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    CYASSL_ENTER("CyaSSL_ERR_error_string_n");
    if (len >= CYASSL_MAX_ERROR_SZ)
        CyaSSL_ERR_error_string(e, buf);
    else {
        char tmp[CYASSL_MAX_ERROR_SZ];

        CYASSL_MSG("Error buffer too short, truncating");
        if (len) {
            CyaSSL_ERR_error_string(e, tmp);
            XMEMCPY(buf, tmp, len-1);
            buf[len-1] = '\0';
        }
    }
}


/* don't free temporary arrays at end of handshake */
void CyaSSL_KeepArrays(CYASSL* ssl)
{
    if (ssl)
        ssl->options.saveArrays = 1;
}


/* user doesn't need temporary arrays anymore, Free */
void CyaSSL_FreeArrays(CYASSL* ssl)
{
    if (ssl && ssl->options.handShakeState == HANDSHAKE_DONE) {
        ssl->options.saveArrays = 0;
        FreeArrays(ssl, 1);
    }
}


const byte* CyaSSL_GetMacSecret(CYASSL* ssl, int verify)
{
    if (ssl == NULL)
        return NULL;

    if ( (ssl->options.side == CYASSL_CLIENT_END && !verify) ||
         (ssl->options.side == CYASSL_SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
}


#ifdef ATOMIC_USER

void  CyaSSL_CTX_SetMacEncryptCb(CYASSL_CTX* ctx, CallbackMacEncrypt cb)
{
    if (ctx)
        ctx->MacEncryptCb = cb;
}


void  CyaSSL_SetMacEncryptCtx(CYASSL* ssl, void *ctx)
{
    if (ssl)
        ssl->MacEncryptCtx = ctx;
}


void* CyaSSL_GetMacEncryptCtx(CYASSL* ssl)
{
    if (ssl)
        return ssl->MacEncryptCtx;

    return NULL;
}


void  CyaSSL_CTX_SetDecryptVerifyCb(CYASSL_CTX* ctx, CallbackDecryptVerify cb)
{
    if (ctx)
        ctx->DecryptVerifyCb = cb;
}


void  CyaSSL_SetDecryptVerifyCtx(CYASSL* ssl, void *ctx)
{
    if (ssl)
        ssl->DecryptVerifyCtx = ctx;
}


void* CyaSSL_GetDecryptVerifyCtx(CYASSL* ssl)
{
    if (ssl)
        return ssl->DecryptVerifyCtx;

    return NULL;
}


const byte* CyaSSL_GetClientWriteKey(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_key;

    return NULL;
}


const byte* CyaSSL_GetClientWriteIV(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_IV;

    return NULL;
}


const byte* CyaSSL_GetServerWriteKey(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_key;

    return NULL;
}


const byte* CyaSSL_GetServerWriteIV(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_IV;

    return NULL;
}


int CyaSSL_GetKeySize(CYASSL* ssl)
{
    if (ssl)
        return ssl->specs.key_size;

    return BAD_FUNC_ARG;
}


int CyaSSL_GetIVSize(CYASSL* ssl)
{
    if (ssl)
        return ssl->specs.iv_size;

    return BAD_FUNC_ARG;
}


int CyaSSL_GetBulkCipher(CYASSL* ssl)
{
    if (ssl)
        return ssl->specs.bulk_cipher_algorithm;

    return BAD_FUNC_ARG;
}


int CyaSSL_GetCipherType(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->specs.cipher_type == block)
        return CYASSL_BLOCK_TYPE;
    if (ssl->specs.cipher_type == stream)
        return CYASSL_STREAM_TYPE;
    if (ssl->specs.cipher_type == aead)
        return CYASSL_AEAD_TYPE;

    return -1;
}


int CyaSSL_GetCipherBlockSize(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.block_size;
}


int CyaSSL_GetAeadMacSize(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.aead_mac_size;
}


int CyaSSL_IsTLSv1_1(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.tls1_1)
        return 1;

    return 0;
}


int CyaSSL_GetSide(CYASSL* ssl)
{
    if (ssl)
        return ssl->options.side;

    return BAD_FUNC_ARG;
}


int CyaSSL_GetHmacSize(CYASSL* ssl)
{
    /* AEAD ciphers don't have HMAC keys */
    if (ssl)
        return (ssl->specs.cipher_type != aead) ? ssl->specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#endif /* ATOMIC_USER */

#ifndef NO_CERTS

CYASSL_CERT_MANAGER* CyaSSL_CertManagerNew(void)
{
    CYASSL_CERT_MANAGER* cm = NULL;

    CYASSL_ENTER("CyaSSL_CertManagerNew");

    cm = (CYASSL_CERT_MANAGER*) XMALLOC(sizeof(CYASSL_CERT_MANAGER), 0,
                                        DYNAMIC_TYPE_CERT_MANAGER);
    if (cm) {
        XMEMSET(cm, 0, sizeof(CYASSL_CERT_MANAGER));

        if (InitMutex(&cm->caLock) != 0) {
            CYASSL_MSG("Bad mutex init");
            CyaSSL_CertManagerFree(cm);
            return NULL;
        }
    }

    return cm;
}


void CyaSSL_CertManagerFree(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerFree");

    if (cm) {
        #ifdef HAVE_CRL
            if (cm->crl)
                FreeCRL(cm->crl, 1);
        #endif
        #ifdef HAVE_OCSP
            if (cm->ocsp)
                FreeOCSP(cm->ocsp, 1);
        #endif
        FreeSignerTable(cm->caTable, CA_TABLE_SIZE, NULL);
        FreeMutex(&cm->caLock);
        XFREE(cm, NULL, DYNAMIC_TYPE_CERT_MANAGER);
    }

}


/* Unload the CA signer list */
int CyaSSL_CertManagerUnloadCAs(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerUnloadCAs");

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (LockMutex(&cm->caLock) != 0)
        return BAD_MUTEX_E;

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, NULL);

    UnLockMutex(&cm->caLock);


    return SSL_SUCCESS;
}


/* Return bytes written to buff or < 0 for error */
int CyaSSL_CertPemToDer(const unsigned char* pem, int pemSz,
                        unsigned char* buff, int buffSz,
                        int type)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

    CYASSL_ENTER("CyaSSL_CertPemToDer");

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        CYASSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

    if (type != CERT_TYPE && type != CA_TYPE && type != CERTREQ_TYPE) {
        CYASSL_MSG("Bad cert type");
        return BAD_FUNC_ARG;
    }

#ifdef CYASSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

    ret = PemToDer(pem, pemSz, type, &der, NULL, info, &eccKey);

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
            CYASSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(der.buffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

/* our KeyPemToDer password callback, password in userData */
static INLINE int OurPasswordCb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;

    if (userdata == NULL)
        return 0;

    XSTRNCPY(passwd, (char*)userdata, sz);
    return min((word32)sz, (word32)XSTRLEN((char*)userdata));
}

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */


/* Return bytes written to buff or < 0 for error */
int CyaSSL_KeyPemToDer(const unsigned char* pem, int pemSz, unsigned char* buff,
                       int buffSz, const char* pass)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

    (void)pass;

    CYASSL_ENTER("CyaSSL_KeyPemToDer");

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        CYASSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

#ifdef CYASSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    if (pass) {
        info->ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
        if (info->ctx == NULL) {
        #ifdef CYASSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return MEMORY_E;
        }

        CyaSSL_CTX_set_default_passwd_cb(info->ctx, OurPasswordCb);
        CyaSSL_CTX_set_default_passwd_cb_userdata(info->ctx, (void*)pass);
    }
#endif

    ret = PemToDer(pem, pemSz, PRIVATEKEY_TYPE, &der, NULL, info, &eccKey);

    if (info->ctx)
        CyaSSL_CTX_free(info->ctx);

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
            CYASSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(der.buffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


#endif /* !NO_CERTS */



#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)

void CyaSSL_ERR_print_errors_fp(FILE* fp, int err)
{
    char data[CYASSL_MAX_ERROR_SZ + 1];

    CYASSL_ENTER("CyaSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    fprintf(fp, "%s", data);
}

#endif


int CyaSSL_pending(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_pending");
    return ssl->buffers.clearOutputBuffer.length;
}


#ifndef CYASSL_LEANPSK
/* trun on handshake group messages for context */
int CyaSSL_CTX_set_group_messages(CYASSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 1;

    return SSL_SUCCESS;
}
#endif


#ifndef NO_CYASSL_CLIENT
/* connect enough to get peer cert chain */
int CyaSSL_connect_cert(CYASSL* ssl)
{
    int  ret;

    if (ssl == NULL)
        return SSL_FAILURE;

    ssl->options.certOnly = 1;
    ret = CyaSSL_connect(ssl);
    ssl->options.certOnly   = 0;

    return ret;
}
#endif


#ifndef CYASSL_LEANPSK
/* trun on handshake group messages for ssl object */
int CyaSSL_set_group_messages(CYASSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return SSL_SUCCESS;
}


/* Set minimum downgrade version allowed, SSL_SUCCESS on ok */
int CyaSSL_SetMinVersion(CYASSL* ssl, int version)
{
    CYASSL_ENTER("CyaSSL_SetMinVersion");

    if (ssl == NULL) {
        CYASSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#ifndef NO_OLD_TLS
        case CYASSL_SSLV3:
            ssl->options.minDowngrade = SSLv3_MINOR;
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        case CYASSL_TLSV1:
            ssl->options.minDowngrade = TLSv1_MINOR;
            break;

        case CYASSL_TLSV1_1:
            ssl->options.minDowngrade = TLSv1_1_MINOR;
            break;
    #endif
        case CYASSL_TLSV1_2:
            ssl->options.minDowngrade = TLSv1_2_MINOR;
            break;
#endif

        default:
            CYASSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }


    return SSL_SUCCESS;
}


int CyaSSL_SetVersion(CYASSL* ssl, int version)
{
    byte haveRSA = 1;
    byte havePSK = 0;

    CYASSL_ENTER("CyaSSL_SetVersion");

    if (ssl == NULL) {
        CYASSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#ifndef NO_OLD_TLS
        case CYASSL_SSLV3:
            ssl->version = MakeSSLv3();
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        case CYASSL_TLSV1:
            ssl->version = MakeTLSv1();
            break;

        case CYASSL_TLSV1_1:
            ssl->version = MakeTLSv1_1();
            break;
    #endif
        case CYASSL_TLSV1_2:
            ssl->version = MakeTLSv1_2();
            break;
#endif

        default:
            CYASSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    #ifdef NO_RSA
        haveRSA = 0;
    #endif
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif

    InitSuites(ssl->suites, ssl->version, haveRSA, havePSK, ssl->options.haveDH,
                ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                ssl->options.haveStaticECC, ssl->options.side);

    return SSL_SUCCESS;
}
#endif /* !leanpsk */


#if !defined(NO_CERTS) || !defined(NO_SESSION_CACHE)

/* Make a work from the front of random hash */
static INLINE word32 MakeWordFromHash(const byte* hashID)
{
    return (hashID[0] << 24) | (hashID[1] << 16) | (hashID[2] <<  8) |
            hashID[3];
}

#endif /* !NO_CERTS || !NO_SESSION_CACHE */


#ifndef NO_CERTS

/* hash is the SHA digest of name, just use first 32 bits as hash */
static INLINE word32 HashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % CA_TABLE_SIZE;
}


/* does CA already exist on signer list */
int AlreadySigner(CYASSL_CERT_MANAGER* cm, byte* hash)
{
    Signer* signers;
    int     ret = 0;
    word32  row = HashSigner(hash);

    if (LockMutex(&cm->caLock) != 0)
        return  ret;
    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;
        #ifndef NO_SKID
            subjectHash = signers->subjectKeyIdHash;
        #else
            subjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SHA_DIGEST_SIZE) == 0) {
            ret = 1;
            break;
        }
        signers = signers->next;
    }
    UnLockMutex(&cm->caLock);

    return ret;
}


/* return CA if found, otherwise NULL */
Signer* GetCA(void* vp, byte* hash)
{
    CYASSL_CERT_MANAGER* cm = (CYASSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row = HashSigner(hash);

    if (cm == NULL)
        return NULL;

    if (LockMutex(&cm->caLock) != 0)
        return ret;

    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;
        #ifndef NO_SKID
            subjectHash = signers->subjectKeyIdHash;
        #else
            subjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SHA_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
    UnLockMutex(&cm->caLock);

    return ret;
}


#ifndef NO_SKID
/* return CA if found, otherwise NULL. Walk through hash table. */
Signer* GetCAByName(void* vp, byte* hash)
{
    CYASSL_CERT_MANAGER* cm = (CYASSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row;

    if (cm == NULL)
        return NULL;

    if (LockMutex(&cm->caLock) != 0)
        return ret;

    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        signers = cm->caTable[row];
        while (signers && ret == NULL) {
            if (XMEMCMP(hash, signers->subjectNameHash, SHA_DIGEST_SIZE) == 0) {
                ret = signers;
            }
            signers = signers->next;
        }
    }
    UnLockMutex(&cm->caLock);

    return ret;
}
#endif


/* owns der, internal now uses too */
/* type flag ids from user or from chain received during verify
   don't allow chain ones to be added w/o isCA extension */
int AddCA(CYASSL_CERT_MANAGER* cm, buffer der, int type, int verify)
{
    int         ret;
    Signer*     signer = 0;
    word32      row;
    byte*       subjectHash;
#ifdef CYASSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    CYASSL_MSG("Adding a CA");

#ifdef CYASSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(cert, der.buffer, der.length, cm->heap);
    ret = ParseCert(cert, CA_TYPE, verify, cm);
    CYASSL_MSG("    Parsed new CA");

#ifndef NO_SKID
    subjectHash = cert->extSubjKeyId;
#else
    subjectHash = cert->subjectHash;
#endif

    if (ret == 0 && cert->isCA == 0 && type != CYASSL_USER_CA) {
        CYASSL_MSG("    Can't add as CA if not actually one");
        ret = NOT_CA_ERROR;
    }
#ifndef ALLOW_INVALID_CERTSIGN
    else if (ret == 0 && cert->isCA == 1 && type != CYASSL_USER_CA &&
                              (cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
        /* Intermediate CA certs are required to have the keyCertSign
        * extension set. User loaded root certs are not. */
        CYASSL_MSG("    Doesn't have key usage certificate signing");
        ret = NOT_CA_ERROR;
    }
#endif
    else if (ret == 0 && AlreadySigner(cm, subjectHash)) {
        CYASSL_MSG("    Already have this CA, not adding again");
        (void)ret;
    }
    else if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner(cm->heap);
        if (!signer)
            ret = MEMORY_ERROR;
        else {
            signer->keyOID         = cert->keyOID;
            signer->publicKey      = cert->publicKey;
            signer->pubKeySize     = cert->pubKeySize;
            signer->nameLen        = cert->subjectCNLen;
            signer->name           = cert->subjectCN;
        #ifndef IGNORE_NAME_CONSTRAINTS
            signer->permittedNames = cert->permittedNames;
            signer->excludedNames  = cert->excludedNames;
        #endif
        #ifndef NO_SKID
            XMEMCPY(signer->subjectKeyIdHash, cert->extSubjKeyId,
                                                               SHA_DIGEST_SIZE);
        #endif
            XMEMCPY(signer->subjectNameHash, cert->subjectHash,
                                                               SHA_DIGEST_SIZE);
            signer->keyUsage = cert->extKeyUsageSet ? cert->extKeyUsage
                                                    : 0xFFFF;
            signer->next    = NULL; /* If Key Usage not set, all uses valid. */
            cert->publicKey = 0;    /* in case lock fails don't free here.   */
            cert->subjectCN = 0;
        #ifndef IGNORE_NAME_CONSTRAINTS
            cert->permittedNames = NULL;
            cert->excludedNames = NULL;
        #endif

        #ifndef NO_SKID
            row = HashSigner(signer->subjectKeyIdHash);
        #else
            row = HashSigner(signer->subjectNameHash);
        #endif

            if (LockMutex(&cm->caLock) == 0) {
                signer->next = cm->caTable[row];
                cm->caTable[row] = signer;   /* takes ownership */
                UnLockMutex(&cm->caLock);
                if (cm->caCacheCallback)
                    cm->caCacheCallback(der.buffer, (int)der.length, type);
            }
            else {
                CYASSL_MSG("    CA Mutex Lock failed");
                ret = BAD_MUTEX_E;
                FreeSigner(signer, cm->heap);
            }
        }
    }

    CYASSL_MSG("    Freeing Parsed CA");
    FreeDecodedCert(cert);
#ifdef CYASSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    CYASSL_MSG("    Freeing der CA");
    XFREE(der.buffer, cm->heap, DYNAMIC_TYPE_CA);
    CYASSL_MSG("        OK Freeing der CA");

    CYASSL_LEAVE("AddCA", ret);

    return ret == 0 ? SSL_SUCCESS : ret;
}

#endif /* !NO_CERTS */


#ifndef NO_SESSION_CACHE

    /* basic config gives a cache with 33 sessions, adequate for clients and
       embedded servers

       MEDIUM_SESSION_CACHE allows 1055 sessions, adequate for servers that
       aren't under heavy load, basically allows 200 new sessions per minute

       BIG_SESSION_CACHE yields 20,027 sessions

       HUGE_SESSION_CACHE yields 65,791 sessions, for servers under heavy load,
       allows over 13,000 new sessions per minute or over 200 new sessions per
       second

       SMALL_SESSION_CACHE only stores 6 sessions, good for embedded clients
       or systems where the default of nearly 3kB is too much RAM, this define
       uses less than 500 bytes RAM

       default SESSION_CACHE stores 33 sessions (no XXX_SESSION_CACHE defined)
    */
    #ifdef HUGE_SESSION_CACHE
        #define SESSIONS_PER_ROW 11
        #define SESSION_ROWS 5981
    #elif defined(BIG_SESSION_CACHE)
        #define SESSIONS_PER_ROW 7
        #define SESSION_ROWS 2861
    #elif defined(MEDIUM_SESSION_CACHE)
        #define SESSIONS_PER_ROW 5
        #define SESSION_ROWS 211
    #elif defined(SMALL_SESSION_CACHE)
        #define SESSIONS_PER_ROW 2
        #define SESSION_ROWS 3
    #else
        #define SESSIONS_PER_ROW 3
        #define SESSION_ROWS 11
    #endif

    typedef struct SessionRow {
        int nextIdx;                           /* where to place next one   */
        int totalCount;                        /* sessions ever on this row */
        CYASSL_SESSION Sessions[SESSIONS_PER_ROW];
    } SessionRow;

    static SessionRow SessionCache[SESSION_ROWS];

    static CyaSSL_Mutex session_mutex;   /* SessionCache mutex */

    #ifndef NO_CLIENT_CACHE

        typedef struct ClientSession {
            word16 serverRow;            /* SessionCache Row id */
            word16 serverIdx;            /* SessionCache Idx (column) */
        } ClientSession;

        typedef struct ClientRow {
            int nextIdx;                /* where to place next one   */
            int totalCount;             /* sessions ever on this row */
            ClientSession Clients[SESSIONS_PER_ROW];
        } ClientRow;

        static ClientRow ClientCache[SESSION_ROWS];  /* Client Cache */
                                                     /* uses session mutex */
    #endif  /* NO_CLIENT_CACHE */

#endif /* NO_SESSION_CACHE */

int CyaSSL_Init(void)
{
    int ret = SSL_SUCCESS;
    CYASSL_ENTER("CyaSSL_Init");

#ifdef __MORPHOS__
    if(!SysBase)
         SysBase = *(struct ExecBase **)4L; /* tricky...but works */
#endif

    if (initRefCount == 0) {
#ifndef NO_SESSION_CACHE
        if (InitMutex(&session_mutex) != 0)
            ret = BAD_MUTEX_E;
#endif
        if (InitMutex(&count_mutex) != 0)
            ret = BAD_MUTEX_E;
    }
    if (ret == SSL_SUCCESS) {
        if (LockMutex(&count_mutex) != 0) {
            CYASSL_MSG("Bad Lock Mutex count");
            return BAD_MUTEX_E;
        }
        initRefCount++;
        UnLockMutex(&count_mutex);
    }
    return ret;
}


#ifndef NO_CERTS

static const char* BEGIN_CERT         = "-----BEGIN CERTIFICATE-----";
static const char* END_CERT           = "-----END CERTIFICATE-----";
static const char* BEGIN_CERT_REQ     = "-----BEGIN CERTIFICATE REQUEST-----";
static const char* END_CERT_REQ       = "-----END CERTIFICATE REQUEST-----";
static const char* BEGIN_DH_PARAM     = "-----BEGIN DH PARAMETERS-----";
static const char* END_DH_PARAM       = "-----END DH PARAMETERS-----";
static const char* BEGIN_X509_CRL     = "-----BEGIN X509 CRL-----";
static const char* END_X509_CRL       = "-----END X509 CRL-----";
static const char* BEGIN_RSA_PRIV     = "-----BEGIN RSA PRIVATE KEY-----";
static const char* END_RSA_PRIV       = "-----END RSA PRIVATE KEY-----";
static const char* BEGIN_PRIV_KEY     = "-----BEGIN PRIVATE KEY-----";
static const char* END_PRIV_KEY       = "-----END PRIVATE KEY-----";
static const char* BEGIN_ENC_PRIV_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const char* END_ENC_PRIV_KEY   = "-----END ENCRYPTED PRIVATE KEY-----";
static const char* BEGIN_EC_PRIV      = "-----BEGIN EC PRIVATE KEY-----";
static const char* END_EC_PRIV        = "-----END EC PRIVATE KEY-----";
static const char* BEGIN_DSA_PRIV     = "-----BEGIN DSA PRIVATE KEY-----";
static const char* END_DSA_PRIV       = "-----END DSA PRIVATE KEY-----";

/* Remove PEM header/footer, convert to ASN1, store any encrypted data
   info->consumed tracks of PEM bytes consumed in case multiple parts */
int PemToDer(const unsigned char* buff, long longSz, int type,
                  buffer* der, void* heap, EncryptedInfo* info, int* eccKey)
{
    const char* header      = NULL;
    const char* footer      = NULL;
    char*       headerEnd;
    char*       footerEnd;
    char*       consumedEnd;
    char*       bufferEnd   = (char*)(buff + longSz);
    long        neededSz;
    int         ret         = 0;
    int         dynamicType = 0;
    int         sz          = (int)longSz;

	switch (type) {
		case CA_TYPE:       /* same as below */
		case CERT_TYPE:     header= BEGIN_CERT;     footer= END_CERT;     break;
		case CRL_TYPE:      header= BEGIN_X509_CRL; footer= END_X509_CRL; break;
		case DH_PARAM_TYPE: header= BEGIN_DH_PARAM; footer= END_DH_PARAM; break;
		case CERTREQ_TYPE:  header= BEGIN_CERT_REQ; footer= END_CERT_REQ; break;
		default:            header= BEGIN_RSA_PRIV; footer= END_RSA_PRIV; break;
	}
	
	switch (type) {
		case CA_TYPE:   dynamicType = DYNAMIC_TYPE_CA;   break;
		case CERT_TYPE: dynamicType = DYNAMIC_TYPE_CERT; break;
		case CRL_TYPE:  dynamicType = DYNAMIC_TYPE_CRL;  break;
		default:        dynamicType = DYNAMIC_TYPE_KEY;  break;
	}

    /* find header */
	for (;;) {
		headerEnd = XSTRNSTR((char*)buff, header, sz);
		
		if (headerEnd || type != PRIVATEKEY_TYPE) {
			break;
		} else if (header == BEGIN_RSA_PRIV) {
	               header =  BEGIN_PRIV_KEY;       footer = END_PRIV_KEY;
		} else if (header == BEGIN_PRIV_KEY) {
	               header =  BEGIN_ENC_PRIV_KEY;   footer = END_ENC_PRIV_KEY;
		} else if (header == BEGIN_ENC_PRIV_KEY) {
			       header =  BEGIN_EC_PRIV;        footer = END_EC_PRIV;
		} else if (header == BEGIN_EC_PRIV) {
			       header =  BEGIN_DSA_PRIV;       footer = END_DSA_PRIV;
		} else
			break;
	}

    if (!headerEnd) {
        CYASSL_MSG("Couldn't find PEM header");
        return SSL_NO_PEM_HEADER;
    }

    headerEnd += XSTRLEN(header);

    /* eat end of line */
    if (headerEnd[0] == '\n')
        headerEnd++;
    else if (headerEnd[1] == '\n')
        headerEnd += 2;
    else
        return SSL_BAD_FILE;

	if (type == PRIVATEKEY_TYPE) {
		if (eccKey)
			*eccKey = header == BEGIN_EC_PRIV;		
	}

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	{
	    /* remove encrypted header if there */
	    char encHeader[] = "Proc-Type";
	    char* line = XSTRNSTR(headerEnd, encHeader, PEM_LINE_LEN);
	    if (line) {
	        char* newline;
	        char* finish;
	        char* start  = XSTRNSTR(line, "DES", PEM_LINE_LEN);

	        if (!start)
	            start = XSTRNSTR(line, "AES", PEM_LINE_LEN);

	        if (!start) return SSL_BAD_FILE;
	        if (!info)  return SSL_BAD_FILE;

	        finish = XSTRNSTR(start, ",", PEM_LINE_LEN);

	        if (start && finish && (start < finish)) {
	            newline = XSTRNSTR(finish, "\r", PEM_LINE_LEN);

	            XMEMCPY(info->name, start, finish - start);
	            info->name[finish - start] = 0;
	            XMEMCPY(info->iv, finish + 1, sizeof(info->iv));

	            if (!newline) newline = XSTRNSTR(finish, "\n", PEM_LINE_LEN);
	            if (newline && (newline > finish)) {
	                info->ivSz = (word32)(newline - (finish + 1));
	                info->set = 1;
	            }
	            else
	                return SSL_BAD_FILE;
	        }
	        else
	            return SSL_BAD_FILE;

	        /* eat blank line */
	        while (*newline == '\r' || *newline == '\n')
	            newline++;
	        headerEnd = newline;
	    }
	}
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

    /* find footer */
    footerEnd = XSTRNSTR((char*)buff, footer, sz);
    if (!footerEnd)
		return SSL_BAD_FILE;

    consumedEnd = footerEnd + XSTRLEN(footer);

    if (consumedEnd < bufferEnd) {  /* handle no end of line on last line */
        /* eat end of line */
        if (consumedEnd[0] == '\n')
            consumedEnd++;
        else if (consumedEnd[1] == '\n')
            consumedEnd += 2;
        else
            return SSL_BAD_FILE;
    }

    if (info)
        info->consumed = (long)(consumedEnd - (char*)buff);

    /* set up der buffer */
    neededSz = (long)(footerEnd - headerEnd);
    if (neededSz > sz || neededSz < 0)
		return SSL_BAD_FILE;

	der->buffer = (byte*)XMALLOC(neededSz, heap, dynamicType);
    if (!der->buffer)
		return MEMORY_ERROR;

    der->length = (word32)neededSz;

    if (Base64_Decode((byte*)headerEnd, (word32)neededSz, der->buffer,
                                                              &der->length) < 0)
        return SSL_BAD_FILE;

    if (header == BEGIN_PRIV_KEY) {
        /* pkcs8 key, convert and adjust length */
        if ((ret = ToTraditional(der->buffer, der->length)) < 0)
            return ret;

        der->length = ret;
        return 0;
    }

#if (defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)) && !defined(NO_PWDBASED)
    if (header == BEGIN_ENC_PRIV_KEY) {
        int   passwordSz;
	#ifdef CYASSL_SMALL_STACK
		char* password = NULL;
	#else
        char  password[80];
	#endif

        if (!info || !info->ctx || !info->ctx->passwd_cb)
            return SSL_BAD_FILE;  /* no callback error */

	#ifdef CYASSL_SMALL_STACK
		password = (char*)XMALLOC(80, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (password == NULL)
		    return MEMORY_E;
	#endif
	    passwordSz = info->ctx->passwd_cb(password, sizeof(password), 0,
                                                           info->ctx->userdata);
        /* convert and adjust length */
		ret = ToTraditionalEnc(der->buffer, der->length, password, passwordSz);

	#ifdef CYASSL_SMALL_STACK
		XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	#endif

        if (ret < 0)
            return ret;

        der->length = ret;
        return 0;
    }
#endif

    return 0;
}


/* process the buffer buff, legnth sz, into ctx of format and type
   used tracks bytes consumed, userChain specifies a user cert chain
   to pass during the handshake */
static int ProcessBuffer(CYASSL_CTX* ctx, const unsigned char* buff,
                         long sz, int format, int type, CYASSL* ssl,
                         long* used, int userChain)
{
    buffer        der;        /* holds DER or RAW (for NTRU) */
    int           ret;
    int           dynamicType = 0;
    int           eccKey = 0;
    int           rsaKey = 0;
    void*         heap = ctx ? ctx->heap : NULL;
#ifdef CYASSL_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

    (void)dynamicType;
    (void)rsaKey;

    if (used)
        *used = sz;     /* used bytes default to sz, PEM chain may shorten*/

    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM
                                    && format != SSL_FILETYPE_RAW)
        return SSL_BAD_FILETYPE;

    if (ctx == NULL && ssl == NULL)
        return BAD_FUNC_ARG;

    if (type == CA_TYPE)
        dynamicType = DYNAMIC_TYPE_CA;
    else if (type == CERT_TYPE)
        dynamicType = DYNAMIC_TYPE_CERT;
    else
        dynamicType = DYNAMIC_TYPE_KEY;

#ifdef CYASSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = ctx;
    info->consumed = 0;
    der.buffer     = 0;

    if (format == SSL_FILETYPE_PEM) {
        ret = PemToDer(buff, sz, type, &der, heap, info, &eccKey);
        if (ret < 0) {
        #ifdef CYASSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            XFREE(der.buffer, heap, dynamicType);
            return ret;
        }

        if (used)
            *used = info->consumed;

        /* we may have a user cert chain, try to consume */
        if (userChain && type == CERT_TYPE && info->consumed < sz) {
        #ifdef CYASSL_SMALL_STACK
            byte   staticBuffer[1];                 /* force heap usage */
        #else
            byte   staticBuffer[FILE_BUFFER_SIZE];  /* tmp chain buffer */
        #endif
            byte*  chainBuffer = staticBuffer;
            byte*  shrinked    = NULL;   /* shrinked to size chainBuffer
                                          * or staticBuffer */
            int    dynamicBuffer = 0;
            word32 bufferSz = sizeof(staticBuffer);
            long   consumed = info->consumed;
            word32 idx = 0;
            int    gotOne = 0;

            if ( (sz - consumed) > (int)bufferSz) {
                CYASSL_MSG("Growing Tmp Chain Buffer");
                bufferSz = (word32)(sz - consumed);
                           /* will shrink to actual size */
                chainBuffer = (byte*)XMALLOC(bufferSz, heap, DYNAMIC_TYPE_FILE);
                if (chainBuffer == NULL) {
                #ifdef CYASSL_SMALL_STACK
                    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    XFREE(der.buffer, heap, dynamicType);
                    return MEMORY_E;
                }
                dynamicBuffer = 1;
            }

            CYASSL_MSG("Processing Cert Chain");
            while (consumed < sz) {
                buffer part;
                info->consumed = 0;
                part.buffer = 0;

                ret = PemToDer(buff + consumed, sz - consumed, type, &part,
                                                           heap, info, &eccKey);
                if (ret == 0) {
                    gotOne = 1;
                    if ( (idx + part.length) > bufferSz) {
                        CYASSL_MSG("   Cert Chain bigger than buffer");
                        ret = BUFFER_E;
                    }
                    else {
                        c32to24(part.length, &chainBuffer[idx]);
                        idx += CERT_HEADER_SZ;
                        XMEMCPY(&chainBuffer[idx], part.buffer,part.length);
                        idx += part.length;
                        consumed  += info->consumed;
                        if (used)
                            *used += info->consumed;
                    }
                }

                XFREE(part.buffer, heap, dynamicType);

                if (ret == SSL_NO_PEM_HEADER && gotOne) {
                    CYASSL_MSG("We got one good PEM so stuff at end ok");
                    break;
                }

                if (ret < 0) {
                    CYASSL_MSG("   Error in Cert in Chain");
                    if (dynamicBuffer)
                        XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);
                #ifdef CYASSL_SMALL_STACK
                    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                    XFREE(der.buffer, heap, dynamicType);
                    return ret;
                }
                CYASSL_MSG("   Consumed another Cert in Chain");
            }
            CYASSL_MSG("Finished Processing Cert Chain");

            /* only retain actual size used */
            shrinked = (byte*)XMALLOC(idx, heap, dynamicType);
            if (shrinked) {
                if (ssl) {
                    if (ssl->buffers.certChain.buffer &&
                                                  ssl->buffers.weOwnCertChain) {
                        XFREE(ssl->buffers.certChain.buffer, heap,
                              dynamicType);
                    }
                    ssl->buffers.certChain.buffer = shrinked;
                    ssl->buffers.certChain.length = idx;
                    XMEMCPY(ssl->buffers.certChain.buffer, chainBuffer,idx);
                    ssl->buffers.weOwnCertChain = 1;
                } else if (ctx) {
                    if (ctx->certChain.buffer)
                        XFREE(ctx->certChain.buffer, heap, dynamicType);
                    ctx->certChain.buffer = shrinked;
                    ctx->certChain.length = idx;
                    XMEMCPY(ctx->certChain.buffer, chainBuffer, idx);
                }
            }

            if (dynamicBuffer)
                XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);

            if (shrinked == NULL) {
            #ifdef CYASSL_SMALL_STACK
                XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                XFREE(der.buffer, heap, dynamicType);
                return MEMORY_E;
            }
        }
    }
    else {  /* ASN1 (DER) or RAW (NTRU) */
        der.buffer = (byte*) XMALLOC(sz, heap, dynamicType);
        if (!der.buffer) {
        #ifdef CYASSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return MEMORY_ERROR;
        }

        XMEMCPY(der.buffer, buff, sz);
        der.length = (word32)sz;
    }

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    if (info->set) {
        /* decrypt */
        int   passwordSz;
#ifdef CYASSL_SMALL_STACK
        char* password = NULL;
        byte* key      = NULL;
        byte* iv       = NULL;
#else
        char  password[80];
        byte  key[AES_256_KEY_SIZE];
        byte  iv[AES_IV_SIZE];
#endif

    #ifdef CYASSL_SMALL_STACK
        password = (char*)XMALLOC(80, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        key      = (byte*)XMALLOC(AES_256_KEY_SIZE, NULL,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
        iv       = (byte*)XMALLOC(AES_IV_SIZE, NULL, 
                                                   DYNAMIC_TYPE_TMP_BUFFER);

        if (password == NULL || key == NULL || iv == NULL) {
            XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(key,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(iv,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ret = MEMORY_E;
        }
        else
    #endif
        if (!ctx || !ctx->passwd_cb) {
            ret = NO_PASSWORD;
        }
        else {
            passwordSz = ctx->passwd_cb(password, sizeof(password), 0,
                                                             ctx->userdata);

            /* use file's salt for key derivation, hex decode first */
            if (Base16_Decode(info->iv, info->ivSz, info->iv, &info->ivSz)
                                                                         != 0) {
                ret = ASN_INPUT_E;
            }
            else if ((ret = EVP_BytesToKey(info->name, "MD5", info->iv,
                           (byte*)password, passwordSz, 1, key, iv)) <= 0) {
                /* empty */
            }
            else if (XSTRNCMP(info->name, "DES-CBC", 7) == 0) {
                ret = Des_CbcDecryptWithKey(der.buffer, der.buffer, der.length,
                                                                 key, info->iv);
            }
            else if (XSTRNCMP(info->name, "DES-EDE3-CBC", 13) == 0) {
                ret = Des3_CbcDecryptWithKey(der.buffer, der.buffer, der.length,
                                                                 key, info->iv);
            }
            else if (XSTRNCMP(info->name, "AES-128-CBC", 13) == 0) {
                ret = AesCbcDecryptWithKey(der.buffer, der.buffer, der.length,
                                               key, AES_128_KEY_SIZE, info->iv);
            }
            else if (XSTRNCMP(info->name, "AES-192-CBC", 13) == 0) {
                ret = AesCbcDecryptWithKey(der.buffer, der.buffer, der.length,
                                               key, AES_192_KEY_SIZE, info->iv);
            }
            else if (XSTRNCMP(info->name, "AES-256-CBC", 13) == 0) {
                ret = AesCbcDecryptWithKey(der.buffer, der.buffer, der.length,
                                               key, AES_256_KEY_SIZE, info->iv);
            }
            else {
                ret = SSL_BAD_FILE;
            }
        }

    #ifdef CYASSL_SMALL_STACK
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(iv,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif

        if (ret != 0) {
        #ifdef CYASSL_SMALL_STACK
            XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            XFREE(der.buffer, heap, dynamicType);
            return ret;
        }
    }
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (type == CA_TYPE) {
        if (ctx == NULL) {
            CYASSL_MSG("Need context for CA load");
            XFREE(der.buffer, heap, dynamicType);
            return BAD_FUNC_ARG;
        }
        return AddCA(ctx->cm, der, CYASSL_USER_CA, ctx->verifyPeer);
                                                      /* takes der over */
    }
    else if (type == CERT_TYPE) {
        if (ssl) {
            if (ssl->buffers.weOwnCert && ssl->buffers.certificate.buffer)
                XFREE(ssl->buffers.certificate.buffer, heap, dynamicType);
            ssl->buffers.certificate = der;
            ssl->buffers.weOwnCert = 1;
        }
        else if (ctx) {
            if (ctx->certificate.buffer)
                XFREE(ctx->certificate.buffer, heap, dynamicType);
            ctx->certificate = der;     /* takes der over */
        }
    }
    else if (type == PRIVATEKEY_TYPE) {
        if (ssl) {
            if (ssl->buffers.weOwnKey && ssl->buffers.key.buffer)
                XFREE(ssl->buffers.key.buffer, heap, dynamicType);
            ssl->buffers.key = der;
            ssl->buffers.weOwnKey = 1;
        }
        else if (ctx) {
            if (ctx->privateKey.buffer)
                XFREE(ctx->privateKey.buffer, heap, dynamicType);
            ctx->privateKey = der;      /* takes der over */
        }
    }
    else {
        XFREE(der.buffer, heap, dynamicType);
        return SSL_BAD_CERTTYPE;
    }

    if (type == PRIVATEKEY_TYPE && format != SSL_FILETYPE_RAW) {
    #ifndef NO_RSA
        if (!eccKey) {
            /* make sure RSA key can be used */
            word32 idx = 0;
        #ifdef CYASSL_SMALL_STACK
            RsaKey* key = NULL;
        #else
            RsaKey  key[1];
        #endif

        #ifdef CYASSL_SMALL_STACK
            key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (key == NULL)
                return MEMORY_E;
        #endif

            ret = InitRsaKey(key, 0);
            if (ret == 0) {
                if (RsaPrivateKeyDecode(der.buffer, &idx, key, der.length) !=
                                                                            0) {
                #ifdef HAVE_ECC
                    /* could have DER ECC (or pkcs8 ecc), no easy way to tell */
                    eccKey = 1;  /* so try it out */
                #endif
                    if (!eccKey)
                        ret = SSL_BAD_FILE;
                } else {
                    rsaKey = 1;
                    (void)rsaKey;  /* for no ecc builds */
                }
            }

            FreeRsaKey(key);

        #ifdef CYASSL_SMALL_STACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif

            if (ret != 0)
                return ret;
        }
    #endif
    #ifdef HAVE_ECC
        if (!rsaKey) {
            /* make sure ECC key can be used */
            word32  idx = 0;
            ecc_key key;

            ecc_init(&key);
            if (EccPrivateKeyDecode(der.buffer,&idx,&key,der.length) != 0) {
                ecc_free(&key);
                return SSL_BAD_FILE;
            }
            ecc_free(&key);
            eccKey = 1;
            if (ctx)
                ctx->haveStaticECC = 1;
            if (ssl)
                ssl->options.haveStaticECC = 1;
        }
    #endif /* HAVE_ECC */
    }
    else if (type == CERT_TYPE) {
    #ifdef CYASSL_SMALL_STACK
        DecodedCert* cert = NULL;
    #else
        DecodedCert  cert[1];
    #endif

    #ifdef CYASSL_SMALL_STACK
        cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (cert == NULL)
            return MEMORY_E;
    #endif

        CYASSL_MSG("Checking cert signature type");
        InitDecodedCert(cert, der.buffer, der.length, heap);

        if (DecodeToKey(cert, 0) < 0) {
            CYASSL_MSG("Decode to key failed");
        #ifdef CYASSL_SMALL_STACK
            XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return SSL_BAD_FILE;
        }
        switch (cert->signatureOID) {
            case CTC_SHAwECDSA:
            case CTC_SHA256wECDSA:
            case CTC_SHA384wECDSA:
            case CTC_SHA512wECDSA:
                CYASSL_MSG("ECDSA cert signature");
                if (ctx)
                    ctx->haveECDSAsig = 1;
                if (ssl)
                    ssl->options.haveECDSAsig = 1;
                break;
            default:
                CYASSL_MSG("Not ECDSA cert signature");
                break;
        }

    #ifdef HAVE_ECC
        if (ctx)
            ctx->pkCurveOID = cert->pkCurveOID;
        if (ssl)
            ssl->pkCurveOID = cert->pkCurveOID;
    #endif

        FreeDecodedCert(cert);
    #ifdef CYASSL_SMALL_STACK
        XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    return SSL_SUCCESS;
}


/* CA PEM file for verification, may have multiple/chain certs to process */
static int ProcessChainBuffer(CYASSL_CTX* ctx, const unsigned char* buff,
                            long sz, int format, int type, CYASSL* ssl)
{
    long used   = 0;
    int  ret    = 0;
    int  gotOne = 0;

    CYASSL_MSG("Processing CA PEM file");
    while (used < sz) {
        long consumed = 0;

        ret = ProcessBuffer(ctx, buff + used, sz - used, format, type, ssl,
                            &consumed, 0);

        if (ret == SSL_NO_PEM_HEADER && gotOne) {
            CYASSL_MSG("We got one good PEM file so stuff at end ok");
            ret = SSL_SUCCESS;
            break;
        }

        if (ret < 0)
            break;

        CYASSL_MSG("   Processed a CA");
        gotOne = 1;
        used += consumed;
    }

    return ret;
}


/* Verify the ceritficate, SSL_SUCCESS for ok, < 0 for error */
int CyaSSL_CertManagerVerifyBuffer(CYASSL_CERT_MANAGER* cm, const byte* buff,
                                   long sz, int format)
{
    int ret = 0;
    buffer der;
#ifdef CYASSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    CYASSL_ENTER("CyaSSL_CertManagerVerifyBuffer");

#ifdef CYASSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    der.buffer = NULL;
    der.length = 0;

    if (format == SSL_FILETYPE_PEM) {
        int eccKey = 0; /* not used */
    #ifdef CYASSL_SMALL_STACK
        EncryptedInfo* info = NULL;
    #else
        EncryptedInfo  info[1];
    #endif

    #ifdef CYASSL_SMALL_STACK
        info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (info == NULL) {
            XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    #endif

        info->set      = 0;
        info->ctx      = NULL;
        info->consumed = 0;

        ret = PemToDer(buff, sz, CERT_TYPE, &der, cm->heap, info, &eccKey);

        if (ret == 0)
            InitDecodedCert(cert, der.buffer, der.length, cm->heap);

    #ifdef CYASSL_SMALL_STACK
        XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
    else
        InitDecodedCert(cert, (byte*)buff, (word32)sz, cm->heap);

    if (ret == 0)
        ret = ParseCertRelative(cert, CERT_TYPE, 1, cm);

#ifdef HAVE_CRL
    if (ret == 0 && cm->crlEnabled)
        ret = CheckCertCRL(cm->crl, cert);
#endif

    FreeDecodedCert(cert);

    XFREE(der.buffer, cm->heap, DYNAMIC_TYPE_CERT);
#ifdef CYASSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}


/* turn on OCSP if off and compiled in, set options */
int CyaSSL_CertManagerEnableOCSP(CYASSL_CERT_MANAGER* cm, int options)
{
    int ret = SSL_SUCCESS;

    (void)options;

    CYASSL_ENTER("CyaSSL_CertManagerEnableOCSP");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    #ifdef HAVE_OCSP
        if (cm->ocsp == NULL) {
            cm->ocsp = (CYASSL_OCSP*)XMALLOC(sizeof(CYASSL_OCSP), cm->heap,
                                                             DYNAMIC_TYPE_OCSP);
            if (cm->ocsp == NULL)
                return MEMORY_E;

            if (InitOCSP(cm->ocsp, cm) != 0) {
                CYASSL_MSG("Init OCSP failed");
                FreeOCSP(cm->ocsp, 1);
                cm->ocsp = NULL;
                return SSL_FAILURE;
            }
        }
        cm->ocspEnabled = 1;
        if (options & CYASSL_OCSP_URL_OVERRIDE)
            cm->ocspUseOverrideURL = 1;
        if (options & CYASSL_OCSP_NO_NONCE)
            cm->ocspSendNonce = 0;
        else
            cm->ocspSendNonce = 1;
        #ifndef CYASSL_USER_IO
            cm->ocspIOCb = EmbedOcspLookup;
            cm->ocspRespFreeCb = EmbedOcspRespFree;
        #endif /* CYASSL_USER_IO */
    #else
        ret = NOT_COMPILED_IN;
    #endif

    return ret;
}


int CyaSSL_CertManagerDisableOCSP(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerDisableOCSP");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspEnabled = 0;

    return SSL_SUCCESS;
}


#ifdef HAVE_OCSP


/* check CRL if enabled, SSL_SUCCESS  */
int CyaSSL_CertManagerCheckOCSP(CYASSL_CERT_MANAGER* cm, byte* der, int sz)
{
    int ret;
#ifdef CYASSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    CYASSL_ENTER("CyaSSL_CertManagerCheckOCSP");

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->ocspEnabled == 0)
        return SSL_SUCCESS;

#ifdef CYASSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(cert, der, sz, NULL);

    if ((ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, cm)) != 0) {
        CYASSL_MSG("ParseCert failed");
    }
    else if ((ret = CheckCertOCSP(cm->ocsp, cert)) != 0) {
        CYASSL_MSG("CheckCertOCSP failed");
    }

    FreeDecodedCert(cert);
#ifdef CYASSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}


int CyaSSL_CertManagerSetOCSPOverrideURL(CYASSL_CERT_MANAGER* cm,
                                                                const char* url)
{
    CYASSL_ENTER("CyaSSL_CertManagerSetOCSPOverrideURL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    XFREE(cm->ocspOverrideURL, cm->heap, 0);
    if (url != NULL) {
        int urlSz = (int)XSTRLEN(url) + 1;
        cm->ocspOverrideURL = (char*)XMALLOC(urlSz, cm->heap, 0);
        if (cm->ocspOverrideURL != NULL) {
            XMEMCPY(cm->ocspOverrideURL, url, urlSz);
        }
        else
            return MEMORY_E;
    }
    else
        cm->ocspOverrideURL = NULL;

    return SSL_SUCCESS;
}


int CyaSSL_CertManagerSetOCSP_Cb(CYASSL_CERT_MANAGER* cm,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    CYASSL_ENTER("CyaSSL_CertManagerSetOCSP_Cb");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspIOCb = ioCb;
    cm->ocspRespFreeCb = respFreeCb;
    cm->ocspIOCtx = ioCbCtx;

    return SSL_SUCCESS;
}


int CyaSSL_EnableOCSP(CYASSL* ssl, int options)
{
    CYASSL_ENTER("CyaSSL_EnableOCSP");
    if (ssl)
        return CyaSSL_CertManagerEnableOCSP(ssl->ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_DisableOCSP(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_DisableOCSP");
    if (ssl)
        return CyaSSL_CertManagerDisableOCSP(ssl->ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_SetOCSP_OverrideURL(CYASSL* ssl, const char* url)
{
    CYASSL_ENTER("CyaSSL_SetOCSP_OverrideURL");
    if (ssl)
        return CyaSSL_CertManagerSetOCSPOverrideURL(ssl->ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_SetOCSP_Cb(CYASSL* ssl,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    CYASSL_ENTER("CyaSSL_SetOCSP_Cb");
    if (ssl)
        return CyaSSL_CertManagerSetOCSP_Cb(ssl->ctx->cm,
                                                     ioCb, respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_EnableOCSP(CYASSL_CTX* ctx, int options)
{
    CYASSL_ENTER("CyaSSL_CTX_EnableOCSP");
    if (ctx)
        return CyaSSL_CertManagerEnableOCSP(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_DisableOCSP(CYASSL_CTX* ctx)
{
    CYASSL_ENTER("CyaSSL_CTX_DisableOCSP");
    if (ctx)
        return CyaSSL_CertManagerDisableOCSP(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetOCSP_OverrideURL(CYASSL_CTX* ctx, const char* url)
{
    CYASSL_ENTER("CyaSSL_SetOCSP_OverrideURL");
    if (ctx)
        return CyaSSL_CertManagerSetOCSPOverrideURL(ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetOCSP_Cb(CYASSL_CTX* ctx,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    CYASSL_ENTER("CyaSSL_CTX_SetOCSP_Cb");
    if (ctx)
        return CyaSSL_CertManagerSetOCSP_Cb(ctx->cm, ioCb, respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}


#endif /* HAVE_OCSP */


#ifndef NO_FILESYSTEM

    #if defined(CYASSL_MDK_ARM)
        extern FILE * CyaSSL_fopen(const char *name, const char *mode) ;
        #define XFOPEN     CyaSSL_fopen
    #else
        #define XFOPEN     fopen
    #endif

/* process a file with name fname into ctx of format and type
   userChain specifies a user certificate chain to pass during handshake */
int ProcessFile(CYASSL_CTX* ctx, const char* fname, int format, int type,
                CYASSL* ssl, int userChain, CYASSL_CRL* crl)
{
#ifdef CYASSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
#else
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE  file;
    void*  heapHint = ctx ? ctx->heap : NULL;

    (void)crl;
    (void)heapHint;

    if (fname == NULL) return SSL_BAD_FILE;

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        CYASSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*)XMALLOC(sz, heapHint, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }
    else if (sz < 0) {
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else {
        if (type == CA_TYPE && format == SSL_FILETYPE_PEM)
            ret = ProcessChainBuffer(ctx, myBuffer, sz, format, type, ssl);
#ifdef HAVE_CRL
        else if (type == CRL_TYPE)
            ret = BufferLoadCRL(crl, myBuffer, sz, format);
#endif
        else
            ret = ProcessBuffer(ctx, myBuffer, sz, format, type, ssl, NULL,
                                userChain);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, heapHint, DYNAMIC_TYPE_FILE);

    return ret;
}


/* loads file then loads each file in path, no c_rehash */
int CyaSSL_CTX_load_verify_locations(CYASSL_CTX* ctx, const char* file,
                                     const char* path)
{
    int ret = SSL_SUCCESS;

    CYASSL_ENTER("CyaSSL_CTX_load_verify_locations");
    (void)path;

    if (ctx == NULL || (file == NULL && path == NULL) )
        return SSL_FAILURE;

    if (file)
        ret = ProcessFile(ctx, file, SSL_FILETYPE_PEM, CA_TYPE, NULL, 0, NULL);

    if (ret == SSL_SUCCESS && path) {
        /* try to load each regular file in path */
    #ifdef USE_WINDOWS_API
        WIN32_FIND_DATAA FindFileData;
        HANDLE hFind;
    #ifdef CYASSL_SMALL_STACK
        char*  name = NULL;
    #else
        char   name[MAX_FILENAME_SZ];
    #endif

    #ifdef CYASSL_SMALL_STACK
        name = (char*)XMALLOC(MAX_FILENAME_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (name == NULL)
            return MEMORY_E;
    #endif

        XMEMSET(name, 0, MAX_FILENAME_SZ);
        XSTRNCPY(name, path, MAX_FILENAME_SZ - 4);
        XSTRNCAT(name, "\\*", 3);

        hFind = FindFirstFileA(name, &FindFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            CYASSL_MSG("FindFirstFile for path verify locations failed");
        #ifdef CYASSL_SMALL_STACK
            XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return BAD_PATH_ERROR;
        }

        do {
            if (FindFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
                XSTRNCPY(name, path, MAX_FILENAME_SZ/2 - 3);
                XSTRNCAT(name, "\\", 2);
                XSTRNCAT(name, FindFileData.cFileName, MAX_FILENAME_SZ/2);

                ret = ProcessFile(ctx, name, SSL_FILETYPE_PEM, CA_TYPE, NULL,0,
                                                                          NULL);
            }
        } while (ret == SSL_SUCCESS && FindNextFileA(hFind, &FindFileData));

    #ifdef CYASSL_SMALL_STACK
        XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif

        FindClose(hFind);
    #elif !defined(NO_CYASSL_DIR)
        struct dirent* entry;
        DIR*   dir = opendir(path);
    #ifdef CYASSL_SMALL_STACK
        char*  name = NULL;
    #else
        char   name[MAX_FILENAME_SZ];
    #endif

        if (dir == NULL) {
            CYASSL_MSG("opendir path verify locations failed");
            return BAD_PATH_ERROR;
        }

    #ifdef CYASSL_SMALL_STACK
        name = (char*)XMALLOC(MAX_FILENAME_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (name == NULL)
            return MEMORY_E;
    #endif

        while ( ret == SSL_SUCCESS && (entry = readdir(dir)) != NULL) {
            struct stat s;

            XMEMSET(name, 0, MAX_FILENAME_SZ);
            XSTRNCPY(name, path, MAX_FILENAME_SZ/2 - 2);
            XSTRNCAT(name, "/", 1);
            XSTRNCAT(name, entry->d_name, MAX_FILENAME_SZ/2);

            if (stat(name, &s) != 0) {
                CYASSL_MSG("stat on name failed");
                ret = BAD_PATH_ERROR;
            } else if (s.st_mode & S_IFREG)
                ret = ProcessFile(ctx, name, SSL_FILETYPE_PEM, CA_TYPE, NULL,0,
                                                                          NULL);
        }

    #ifdef CYASSL_SMALL_STACK
        XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif

        closedir(dir);
    #endif
    }

    return ret;
}


/* Verify the ceritficate, SSL_SUCCESS for ok, < 0 for error */
int CyaSSL_CertManagerVerify(CYASSL_CERT_MANAGER* cm, const char* fname,
                             int format)
{
    int    ret = SSL_FATAL_ERROR;
#ifdef CYASSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
#else
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    long   sz = 0;
    XFILE  file = XFOPEN(fname, "rb");

    CYASSL_ENTER("CyaSSL_CertManagerVerify");

    if (file == XBADFILE) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > MAX_CYASSL_FILE_SIZE || sz < 0) {
        CYASSL_MSG("CertManagerVerify file bad size");
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    if (sz > (long)sizeof(staticBuffer)) {
        CYASSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, cm->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else
        ret = CyaSSL_CertManagerVerifyBuffer(cm, myBuffer, sz, format);

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, cm->heap, DYNAMIC_TYPE_FILE);

    return ret;
}


static INLINE CYASSL_METHOD* cm_pick_method(void)
{
    #ifndef NO_CYASSL_CLIENT
        #ifdef NO_OLD_TLS
            return CyaTLSv1_2_client_method();
        #else
            return CyaSSLv3_client_method();
        #endif
    #elif !defined(NO_CYASSL_SERVER)
        #ifdef NO_OLD_TLS
            return CyaTLSv1_2_server_method();
        #else
            return CyaSSLv3_server_method();
        #endif
    #else
        return NULL;
    #endif
}


/* like load verify locations, 1 for success, < 0 for error */
int CyaSSL_CertManagerLoadCA(CYASSL_CERT_MANAGER* cm, const char* file,
                             const char* path)
{
    int ret = SSL_FATAL_ERROR;
    CYASSL_CTX* tmp;

    CYASSL_ENTER("CyaSSL_CertManagerLoadCA");

    if (cm == NULL) {
        CYASSL_MSG("No CertManager error");
        return ret;
    }
    tmp = CyaSSL_CTX_new(cm_pick_method());

    if (tmp == NULL) {
        CYASSL_MSG("CTX new failed");
        return ret;
    }

    /* for tmp use */
    CyaSSL_CertManagerFree(tmp->cm);
    tmp->cm = cm;

    ret = CyaSSL_CTX_load_verify_locations(tmp, file, path);

    /* don't loose our good one */
    tmp->cm = NULL;
    CyaSSL_CTX_free(tmp);

    return ret;
}



/* turn on CRL if off and compiled in, set options */
int CyaSSL_CertManagerEnableCRL(CYASSL_CERT_MANAGER* cm, int options)
{
    int ret = SSL_SUCCESS;

    (void)options;

    CYASSL_ENTER("CyaSSL_CertManagerEnableCRL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    #ifdef HAVE_CRL
        if (cm->crl == NULL) {
            cm->crl = (CYASSL_CRL*)XMALLOC(sizeof(CYASSL_CRL), cm->heap,
                                           DYNAMIC_TYPE_CRL);
            if (cm->crl == NULL)
                return MEMORY_E;

            if (InitCRL(cm->crl, cm) != 0) {
                CYASSL_MSG("Init CRL failed");
                FreeCRL(cm->crl, 1);
                cm->crl = NULL;
                return SSL_FAILURE;
            }
        }
        cm->crlEnabled = 1;
        if (options & CYASSL_CRL_CHECKALL)
            cm->crlCheckAll = 1;
    #else
        ret = NOT_COMPILED_IN;
    #endif

    return ret;
}


int CyaSSL_CertManagerDisableCRL(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerDisableCRL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->crlEnabled = 0;

    return SSL_SUCCESS;
}


int CyaSSL_CTX_check_private_key(CYASSL_CTX* ctx)
{
    /* TODO: check private against public for RSA match */
    (void)ctx;
    CYASSL_ENTER("SSL_CTX_check_private_key");
    return SSL_SUCCESS;
}


#ifdef HAVE_CRL


/* check CRL if enabled, SSL_SUCCESS  */
int CyaSSL_CertManagerCheckCRL(CYASSL_CERT_MANAGER* cm, byte* der, int sz)
{
    int ret = 0;
#ifdef CYASSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    CYASSL_ENTER("CyaSSL_CertManagerCheckCRL");

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->crlEnabled == 0)
        return SSL_SUCCESS;

#ifdef CYASSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(cert, der, sz, NULL);

    if ((ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, cm)) != 0) {
        CYASSL_MSG("ParseCert failed");
    }
    else if ((ret = CheckCertCRL(cm->crl, cert)) != 0) {
        CYASSL_MSG("CheckCertCRL failed");
    }

    FreeDecodedCert(cert);
#ifdef CYASSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret == 0 ? SSL_SUCCESS : ret;
}


int CyaSSL_CertManagerSetCRL_Cb(CYASSL_CERT_MANAGER* cm, CbMissingCRL cb)
{
    CYASSL_ENTER("CyaSSL_CertManagerSetCRL_Cb");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->cbMissingCRL = cb;

    return SSL_SUCCESS;
}


int CyaSSL_CertManagerLoadCRL(CYASSL_CERT_MANAGER* cm, const char* path,
                              int type, int monitor)
{
    CYASSL_ENTER("CyaSSL_CertManagerLoadCRL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (cm->crl == NULL) {
        if (CyaSSL_CertManagerEnableCRL(cm, 0) != SSL_SUCCESS) {
            CYASSL_MSG("Enable CRL failed");
            return SSL_FATAL_ERROR;
        }
    }

    return LoadCRL(cm->crl, path, type, monitor);
}


int CyaSSL_EnableCRL(CYASSL* ssl, int options)
{
    CYASSL_ENTER("CyaSSL_EnableCRL");
    if (ssl)
        return CyaSSL_CertManagerEnableCRL(ssl->ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_DisableCRL(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_DisableCRL");
    if (ssl)
        return CyaSSL_CertManagerDisableCRL(ssl->ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_LoadCRL(CYASSL* ssl, const char* path, int type, int monitor)
{
    CYASSL_ENTER("CyaSSL_LoadCRL");
    if (ssl)
        return CyaSSL_CertManagerLoadCRL(ssl->ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_SetCRL_Cb(CYASSL* ssl, CbMissingCRL cb)
{
    CYASSL_ENTER("CyaSSL_SetCRL_Cb");
    if (ssl)
        return CyaSSL_CertManagerSetCRL_Cb(ssl->ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_EnableCRL(CYASSL_CTX* ctx, int options)
{
    CYASSL_ENTER("CyaSSL_CTX_EnableCRL");
    if (ctx)
        return CyaSSL_CertManagerEnableCRL(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_DisableCRL(CYASSL_CTX* ctx)
{
    CYASSL_ENTER("CyaSSL_CTX_DisableCRL");
    if (ctx)
        return CyaSSL_CertManagerDisableCRL(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_LoadCRL(CYASSL_CTX* ctx, const char* path, int type, int monitor)
{
    CYASSL_ENTER("CyaSSL_CTX_LoadCRL");
    if (ctx)
        return CyaSSL_CertManagerLoadCRL(ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetCRL_Cb(CYASSL_CTX* ctx, CbMissingCRL cb)
{
    CYASSL_ENTER("CyaSSL_CTX_SetCRL_Cb");
    if (ctx)
        return CyaSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}


#endif /* HAVE_CRL */


#ifdef CYASSL_DER_LOAD

/* Add format parameter to allow DER load of CA files */
int CyaSSL_CTX_der_load_verify_locations(CYASSL_CTX* ctx, const char* file,
                                         int format)
{
    CYASSL_ENTER("CyaSSL_CTX_der_load_verify_locations");
    if (ctx == NULL || file == NULL)
        return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_TYPE, NULL, 0, NULL) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}

#endif /* CYASSL_DER_LOAD */


#ifdef CYASSL_CERT_GEN

/* load pem cert from file into der buffer, return der size or error */
int CyaSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz)
{
#ifdef CYASSL_SMALL_STACK
    EncryptedInfo* info = NULL;
    byte   staticBuffer[1]; /* force XMALLOC */
#else
    EncryptedInfo info[1];
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  fileBuf = staticBuffer;
    int    dynamic = 0;
    int    ret     = 0;
    int    ecc     = 0;
    long   sz      = 0;
    XFILE  file    = XFOPEN(fileName, "rb");
    buffer converted;

    CYASSL_ENTER("CyaSSL_PemCertToDer");

    if (file == XBADFILE)
        ret = SSL_BAD_FILE;
    else {
        XFSEEK(file, 0, XSEEK_END);
        sz = XFTELL(file);
        XREWIND(file);

        if (sz < 0) {
            ret = SSL_BAD_FILE;
        }
        else if (sz > (long)sizeof(staticBuffer)) {
            fileBuf = (byte*)XMALLOC(sz, 0, DYNAMIC_TYPE_FILE);
            if (fileBuf == NULL)
                ret = MEMORY_E;
            else
                dynamic = 1;
        }

        converted.buffer = 0;

        if (ret == 0) {
            if ( (ret = (int)XFREAD(fileBuf, sz, 1, file)) < 0)
                ret = SSL_BAD_FILE;
            else {
            #ifdef CYASSL_SMALL_STACK
                info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                if (info == NULL)
                    ret = MEMORY_E;
                else
            #endif
                {
                    ret = PemToDer(fileBuf, sz, CA_TYPE, &converted, 0, info,
                                                                          &ecc);
                #ifdef CYASSL_SMALL_STACK
                    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                }
            }

            if (ret == 0) {
                if (converted.length < (word32)derSz) {
                    XMEMCPY(derBuf, converted.buffer, converted.length);
                    ret = converted.length;
                }
                else
                    ret = BUFFER_E;
            }

            XFREE(converted.buffer, 0, DYNAMIC_TYPE_CA);
        }

        XFCLOSE(file);
        if (dynamic)
            XFREE(fileBuf, 0, DYNAMIC_TYPE_FILE);
    }

    return ret;
}

#endif /* CYASSL_CERT_GEN */


int CyaSSL_CTX_use_certificate_file(CYASSL_CTX* ctx, const char* file,
                                    int format)
{
    CYASSL_ENTER("CyaSSL_CTX_use_certificate_file");
    if (ProcessFile(ctx, file, format, CERT_TYPE, NULL, 0, NULL) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_CTX_use_PrivateKey_file(CYASSL_CTX* ctx, const char* file,int format)
{
    CYASSL_ENTER("CyaSSL_CTX_use_PrivateKey_file");
    if (ProcessFile(ctx, file, format, PRIVATEKEY_TYPE, NULL, 0, NULL)
                    == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_CTX_use_certificate_chain_file(CYASSL_CTX* ctx, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subject cert */
   CYASSL_ENTER("CyaSSL_CTX_use_certificate_chain_file");
   if (ProcessFile(ctx, file, SSL_FILETYPE_PEM,CERT_TYPE,NULL,1, NULL)
                   == SSL_SUCCESS)
       return SSL_SUCCESS;

   return SSL_FAILURE;
}


#ifndef NO_DH

/* server wrapper for ctx or ssl Diffie-Hellman parameters */
static int CyaSSL_SetTmpDH_buffer_wrapper(CYASSL_CTX* ctx, CYASSL* ssl,
                                  const unsigned char* buf, long sz, int format)
{
    buffer der;
    int    ret      = 0;
    int    weOwnDer = 0;
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;
#ifdef CYASSL_SMALL_STACK
    byte*  p = NULL;
    byte*  g = NULL;
#else
    byte   p[MAX_DH_SIZE];
    byte   g[MAX_DH_SIZE];
#endif

    der.buffer = (byte*)buf;
    der.length = (word32)sz;

#ifdef CYASSL_SMALL_STACK
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (p == NULL || g == NULL) {
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        ret = SSL_BAD_FILETYPE;
    else {
        if (format == SSL_FILETYPE_PEM) {
            der.buffer = NULL;
            ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULL);
            weOwnDer = 1;
        }
        
        if (ret == 0) {
            if (DhParamsLoad(der.buffer, der.length, p, &pSz, g, &gSz) < 0)
                ret = SSL_BAD_FILETYPE;
            else if (ssl)
                ret = CyaSSL_SetTmpDH(ssl, p, pSz, g, gSz);
            else
                ret = CyaSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);
        }
    }

    if (weOwnDer)
        XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_KEY);

#ifdef CYASSL_SMALL_STACK
    XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* server Diffie-Hellman parameters, SSL_SUCCESS on ok */
int CyaSSL_SetTmpDH_buffer(CYASSL* ssl, const unsigned char* buf, long sz,
                           int format)
{
    return CyaSSL_SetTmpDH_buffer_wrapper(ssl->ctx, ssl, buf, sz, format);
}


/* server ctx Diffie-Hellman parameters, SSL_SUCCESS on ok */
int CyaSSL_CTX_SetTmpDH_buffer(CYASSL_CTX* ctx, const unsigned char* buf,
                               long sz, int format)
{
    return CyaSSL_SetTmpDH_buffer_wrapper(ctx, NULL, buf, sz, format);
}


/* server Diffie-Hellman parameters */
static int CyaSSL_SetTmpDH_file_wrapper(CYASSL_CTX* ctx, CYASSL* ssl,
                                        const char* fname, int format)
{
#ifdef CYASSL_SMALL_STACK
    byte   staticBuffer[1]; /* force heap usage */
#else
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE  file = XFOPEN(fname, "rb");

    if (file == XBADFILE) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        CYASSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }
    else if (sz < 0) {
        XFCLOSE(file);
        return SSL_BAD_FILE;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else {
        if (ssl)
            ret = CyaSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
        else
            ret = CyaSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

    return ret;
}

/* server Diffie-Hellman parameters */
int CyaSSL_SetTmpDH_file(CYASSL* ssl, const char* fname, int format)
{
    return CyaSSL_SetTmpDH_file_wrapper(ssl->ctx, ssl, fname, format);
}


/* server Diffie-Hellman parameters */
int CyaSSL_CTX_SetTmpDH_file(CYASSL_CTX* ctx, const char* fname, int format)
{
    return CyaSSL_SetTmpDH_file_wrapper(ctx, NULL, fname, format);
}


    /* server ctx Diffie-Hellman parameters, SSL_SUCCESS on ok */
    int CyaSSL_CTX_SetTmpDH(CYASSL_CTX* ctx, const unsigned char* p, int pSz,
                            const unsigned char* g, int gSz)
    {
        CYASSL_ENTER("CyaSSL_CTX_SetTmpDH");
        if (ctx == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

        XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

        ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_P.buffer == NULL)
            return MEMORY_E;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_G.buffer == NULL) {
            XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
            return MEMORY_E;
        }

        ctx->serverDH_P.length = pSz;
        ctx->serverDH_G.length = gSz;

        XMEMCPY(ctx->serverDH_P.buffer, p, pSz);
        XMEMCPY(ctx->serverDH_G.buffer, g, gSz);

        ctx->haveDH = 1;

        CYASSL_LEAVE("CyaSSL_CTX_SetTmpDH", 0);
        return SSL_SUCCESS;
    }
#endif /* NO_DH */


#ifdef OPENSSL_EXTRA
/* put SSL type in extra for now, not very common */

int CyaSSL_use_certificate_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_certificate_file");
    if (ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 0, NULL)
                    == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_use_PrivateKey_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_PrivateKey_file");
    if (ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE, ssl, 0, NULL)
                                                                 == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_use_certificate_chain_file(CYASSL* ssl, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subject cert */
   CYASSL_ENTER("CyaSSL_use_certificate_chain_file");
   if (ProcessFile(ssl->ctx, file, SSL_FILETYPE_PEM, CERT_TYPE, ssl, 1, NULL)
                                                                 == SSL_SUCCESS)
       return SSL_SUCCESS;

   return SSL_FAILURE;
}



#ifdef HAVE_ECC

/* Set Temp CTX EC-DHE size in octets, should be 20 - 66 for 160 - 521 bit */
int CyaSSL_CTX_SetTmpEC_DHE_Sz(CYASSL_CTX* ctx, word16 sz)
{
    if (ctx == NULL || sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ctx->eccTempKeySz = sz;

    return SSL_SUCCESS;
}


/* Set Temp SSL EC-DHE size in octets, should be 20 - 66 for 160 - 521 bit */
int CyaSSL_SetTmpEC_DHE_Sz(CYASSL* ssl, word16 sz)
{
    if (ssl == NULL || sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ssl->eccTempKeySz = sz;

    return SSL_SUCCESS;
}

#endif /* HAVE_ECC */




int CyaSSL_CTX_use_RSAPrivateKey_file(CYASSL_CTX* ctx,const char* file,
                                   int format)
{
    CYASSL_ENTER("SSL_CTX_use_RSAPrivateKey_file");

    return CyaSSL_CTX_use_PrivateKey_file(ctx, file, format);
}


int CyaSSL_use_RSAPrivateKey_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_RSAPrivateKey_file");

    return CyaSSL_use_PrivateKey_file(ssl, file, format);
}

#endif /* OPENSSL_EXTRA */

#ifdef HAVE_NTRU

int CyaSSL_CTX_use_NTRUPrivateKey_file(CYASSL_CTX* ctx, const char* file)
{
    CYASSL_ENTER("CyaSSL_CTX_use_NTRUPrivateKey_file");
    if (ctx == NULL)
        return SSL_FAILURE;

    if (ProcessFile(ctx, file, SSL_FILETYPE_RAW, PRIVATEKEY_TYPE, NULL, 0, NULL)
                         == SSL_SUCCESS) {
        ctx->haveNTRU = 1;
        return SSL_SUCCESS;
    }

    return SSL_FAILURE;
}

#endif /* HAVE_NTRU */
2006-2014 woNO_FILESYSTEM.
 *
 void CyaCopyCTX_set_verify(CYACyaSSL * ctx, int mode, Ve sofCallback vc)
{ssl.cware; yENTER(" * CyaSSL is free sof");ssl.cif (ibut & CopyVERIFY_PEER)  it unSoftctx->ee sofPeer = 1ic Licoftware FoundatNone = 0; 4 woin case perviously set.
 *ersi* ssl.cense as p==blished by
 NONEe Free Software FoundatLicensether version 2 of the ion; ei, or
 * (at yourreption) any later version.
 *
 * Cyaublished by
 righ_IF_NO * th_CERT)er version 2 ofailNoCerte usefer veare Foundat/or modif= vcC) 20L.
 *
 * CyaSs free software; * ssledistribute it and/or modify
 * it under the terms of the General Public License as published by
 * the Free Softwssl->options.oundation; either versioation, Inc., 51 FraLicense, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hopeh Floor, Boston, MA 02110-treet, Fifth Floor, Boston, MAANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOation, Inc., See the
 * GNU Generaationlic License for more deta/* store useral P for ee sof cor modif*/L.
 *
 * CyaSSete
 *CbCtxhave received .
 *can r * it under the terms of the  || defined(blic Licensesslor-ssl.h>
#incllic Licned( =al Pinclude <proto/context CA Cache addiInc.if defined(OPENSSL_EXTRA)SL i || ACbtware; you can red/or modiCAnssl/hcb * it unenset.h>&&al PubcmULAR PURPOSE.  cm->canssl/cense for mcbe deta#if defined(PERSISTARTIC_CACHE)h>
   ! #include is part of )ude <Persist c
 * cssl/hto filed(OPistr * CyaSSL isave_    _* opetware; you can redconh>
 har* fname * it under the terms of the GNU Gernal headers blic   #include <== NULL ||ctaocre <cyassULAR PURPO
 *
 * BAD_FUNC_ARGh>
    
 *
 * CM_Save defiers n
    #i,ctaocryinclude </pem.h>
    /* openfroml headers end, cyassl inreprotoal headers next */
    #include <cyassl/ctaocrypt/hmac.h>
    #include <cyassl/ASSL_SHA512
      m.h>
    #include <cyassl/ctaocrypt/des3.h>
    #include <cyassl/ctaocrypt/md4.h>
    #RSSL_SHude <cyassl/ctaocrypt/md5.h>
 * This file is part of CyaSSssl/pem.h>
    /* opensslmemoryders end, cyassl inmemternal headers next */
    #inclu)
    memedistrszedist*/socd * it under the terms of the GNU 
        #include m.h>
    #include <cyassl/ctmeme <cyassl/ctEM *e <cyassl/ctsz <= 0h>
    #include <cyassl/ctaocrypt/md4.h>
    #Meminclude <cyassl/ctaocrydif /_FILEM */include <)
      <cyassl/ctaocryp       #include "vfapi.h"
  ASSL_SHA512
        #include <cyassl/ctaocif
#endif /* NO_F/

#ifndef TRUE
    #define TRUE  1
_FILESYSTEM
    #if !defined(USE_WINDOWS_API) ndif

#ifndef mNLINE word32 min(word32 a, word32 b)
    {
        retur)
        #include <dirent
#endifn */

#ifnget how big tpensdes.   /* openctao buffer needsnsslbaders end, cyassl ingetal headers   1
#iz next */
    #inc * it under the terms of the GNU  (s1[0] == s2[0])
    m.h>
    #include <cyassh>
    #include <cyassl/ctaocrypt/md4.h>
    #G|| defissl/turn    ssl/openC) 2006-2014 woe <cyasEsl/openssl/d(OP06-2014 wo!NOARTICS.
 *
 *ifndefle iSESSIONenssl/

ware; yunt_mut*d, cyass (s1sessionhave receive * it under the terms ex */

#ifdef _ef OPENSSL_EXTRA
    /* o
 *
 * GetSfdef __ived 0.h>
    
 *
 * yasse deta end, cyasss frifdef __MORPHOS__
s,nder theef count ifdef _truct ExecBase *SysBase =  NULL;

   ef OPENSSL_EX;

    i versioc
 *
 * CX_new(CYASSL_ME user noOD* method)
{
Copyright (C) 20SSL_Mutex coCLIENpenssl/ #endAssociate clie NO_fdef _ with serverID, find existing or<proto/
#ensaving lonif newnew(CYA flag on, don't reuseDYNAMIC_TYLOC(siz lonASSL_UCCESS on oed(OP end, cyasso calSL_CTXhave received de <cybyte* idedistrlenedistr      if ( * it under the_CTX_new");

    <cyassh>
    yassl/openssl/evp.h>
#en        m.h>
    #incssle <cyassl/cti
    static IlenINE word32 min(word32 a, word32 b)
    {
ense      if (I=E wolude <cyassl     CYASTX_new(CYAC) XMASSL_ME    le */
longer f; /* user no Free SoftwSSL* sslo call Init themselves * !SL is ASSL_MSt Library *socke"Alloc CTX MSG("o call Ini See edblic Lic
    CYASSL_      CYASSL_MSG
    CYASSL_}ree");
   (ctx)rsion.
 *
 def __MOR
       Free Softwd CyaSSL_CTXValid          no /* oped alreadublicr-ssl.h>
#incldef __M.idLeCYAS(word16)min(SERVER_ID_LEN,LL;
  32)etbase(CYASSL*XMEMCPY(met CYASSL* sASSL_CTX),        CYASSL* ssl = ase(CYA* ssl.c
 *
 * CopyASSL_MSC) 2006-2014 worn ctx;

    ct.
 *

    #include <cyassunt_mutex;   penssl
#enppem.h>ance,* sschangelen &layou NULednsslincremXMALandribuifyree"ctaocdef __Maders n));
  ASSL_SHA 0;
        });
         vpem.onlen oinitR #inclL_CTX_frnssl/hed _mut 2 #endee(CYASSnssl/hHeader informah>
  */
typeutexstruct Free Sistrreturn ;
    /*/* open
      return DYNAater veistrrowsASSL_LL_LEAVdef __MOLY13fdef HAVE_POcolumn305
/*  if to use es 0 tofdef HAVE_POdef __MSzASSL if izeof  }
    else {
fdef}/* ope_hSSL_f_t; #endcurrXMAL= InitSencSL_free",is:X* ct1)ENTER("SSL_use_ree"2)  CYASSL multree"3)  CyaSSold_poree"upd_CTXSSL_free(CYASSL* ssl), ctx)) <L_free",
#en(chafollow(ctx) {tatic voN (ssl)
         funcInc.,

 *
  0)
        return (chapoly */
i

    while (n >= s2_len && s1[0]) {
      /

#ifdef _== s2[0])
     .
 *>
    #in NO_F NULLint)(, int (SL_use_old_p) +l, int (NTER("SSL_use_)CTX* ctx    return ctx;

    ctxCYASSL_ENz +teCtx = &ssl->w);
    retuf (sl->op6-201 ssl.c
 *
 * sz.h>
    #include to allow IO caT
        #include "vfap
        0;
        }
rn a > b ? a : b;
    }
#IOCBisCtx;
NTER("SSL_use_AVE("SSL_set_sCtx;
new(CYARow*er foowriteC  return SS)((x);
 )ndiff CYASSL_DTLS
       f (sptions.dtls) {
            s CyaSSn SSL_SU clRow;tRefCouG("Alloc CTX failed, methodfers.dtlsCtx.fd = fd;       XFREE(mz <
    ssl->IOCB_ReadCtx  = &ssl->rf)L_LEAVE("SSL_CTX_free", M      e (n >=l;
}small ctx)
{
    clude <cUFFER_Esl;

    ssl NTER("SSL_us 51 ;
}

riteSSL_free(CYASSL* sslSL_LEAVE("SSL_set_.old p; i <= unt_muteROWSy a : */
    for (iint CyaS< size; i++S_PER) {
y a : */
    for (ipoly(CYASiteCtx = = &ssl-}
    else {
lsCtx;
TER("SSLdif /&NTER("SSL_us,(char* buf, int len)
{
 CTX_new",LockMutex(&CB_ReadCm(totbase(n ctx;
}

#ifd CyaSSL_CTX_f allow IO can) {
 lockSL_CTX* ctx)
{
    clude <cyasMUTEXFUNC_ARG;

    
#en(iWARRANi < */
    for (i = 0; ++io longer fTER("SSLrow++,SSL_use_old_p + igh and wi  return Sf (ssptions.dtls) {
            smes()NULLs = GetCip)r();

            if (i < size - 1)
                *buf++ = delimes()    );
    retu  else
      s = GetCi
{
     int  totUn  if (totalInc < len) {
 SG("Alloc CTX LEAVE   int  step     = 0;
    char ,(ssl, socketb/

    if (method  XMALLOC(siz#ifndef max
(cha= InitSSLl->buffers.dtlsCSL_DTLS
    static INLINE #ifndef CYA 0;
        }
  return a > b ? a : b;
    }
#IOCB* ssSL_LEAVE("SSL_set_fd", SSL_SUCCESS);
    return SSL_SUCCESS;
}


int CyaSSL_get_ciphers(char* buf, int len)
{
    const char* const* ciphers = GetCipherNames();
    int  totalInc = 0;
    int  step>options.usingNonbloc delim    = ':';
    int  size     = GetCipherNamesSize();
    int  i;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    TER("SSLis large enough
#endihar* buf, int len)
{
   #includ* Add each member to t!he buffer delimitted b ||ree Softwa/
    for (i = 0; i < se(se; i++) {
    XFREE(ssl->buffers.dtl(XSTRLEN(csa,ssl->he) + 1);     XFREE(ssl->buffers.dtl     total!Inc += step;

        /* ChecL_LE   XSTRNCPY(buf, ciphers[i], XSTRLESSL_us matchi]));
            buf += Xe(CYASMATCH_ERRORsl;

    ssl       if (totalInc < len) {
            XSTRNCPY(buf, ciphers[i], XSTRLEN(ciphers[i]));
            buf += XSTRLEN(ciphers[i]);

            if (i < size - 1)
                *buf++ = deli    }
        elsem;
    
            return BUFFER_E;
    }
    return SSL_SUCCESS;
}


int CyaSSL_get_fd(const CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_fd");
L_LEAVE("SSL_get_    CYASSfd", ssl->rfd);
    return ssl->rfd;
}


int CyaSSL_get_using_nonblock(CYASSL* ssl)
{
    onblock != 0);
}


intL_get_using_nonblock");
    CYASSL_LEAVE("Cy.h>
    #include <cyassl/openssl/pem.h>
>buffers.dtlsCtx; headers/* doesctx,etho
       becaethoofhmac.h>
 alt);
    etho CTX failed");s.dtlsCtx.fd = fd;
de <cyassl *taocrypt/hmacXs pa t or      ifl)
{
 rette");
#ifndef c sizYASSL_LEAVE(L* ssl)
{
    return ssl->options.dtls;
}


#ific License
 * along with th    = 0;
    char delim    head= XFOPEN(taocr, "w+bblic License   if = XBADs paL_LEAVE("SSL_CTX_free", Couldctx,open to allow IO callbac hea           buf += X if cyassILUNC_ARG;
    /* Add each member to the buffer delimitted by a : */
    for (i = 0; i < size; i++) {
        step = (int)(XSTRLEN(ciphers[i]) + 1);  /* delimiter */
        totalInc += step;

        /* Check 

#ifEAVE("SSLurn SSLater vere* GNCtx =XFWRITE_TYPE_SOCKADDR);, int vs large enough1), 0ld5.hsl;
    hers!=alue    XSTRNCPY(buf, ciphers[i], XSTRLEurn SSL headwriteSL_CTX* ctx)
{
    XFCLOSELIENT          buf += Xdef NOlse
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}

int CyaSSL_dtls_get_peer(def NO_DES3
    printf("    siSTRLEN(ciphers[i]);

   ew poly */
issl/hater ve         if (i < size - 1)
            ;
#endif
  hers));
#ifndef NO_    }
        else
            retur      = %lu\n", n", sizeof(Arc4));
#endif
  TRNCPY(buf, ciphers[i], XSTRLENemb    = %lu\n", sizeof(Aes));
#ifnERVER
   zeof des3         "    sizbreakfree");
       Freeptions.dtls) {
            s_pol) XMAL  = %lu\n", sizeof(Chacha));
#endif
    printf("sizeof cipher specs     = %lu\n", L_LEAVE("SSL_get_fd", ssl->rfd);
 zeof keys             = %lu\n", sizeof(Keys));
    printf("s CyaSSashes(2)        = %lu\n", sizeof(Hashes));
#ifndef NO_MD5
    printf("    sizeof MD5          = %lu\neof(CYASSL), ctx->heap,DYNAMICsl->rfd;
}


int CyaSSL_get_using_nonbdef NO_DES3
    prilock(CYASSL* ssl)
{
 CYASSL_ENTER("CyaSSL_rconblock");
    r#include <_get_using_nonblock", ssl->options.usingNo or accept, SSL_SUCCESS on roto//
int CyaSSL_negotiate(CYASSL* ssl)
{
    int e>options.usingNonblock;
}


  CYASSL_ENTER("CyaSSL_negotiate");
#ifndef 
    if (ssl->options.side = NO_CYASSL_SERVE= CYASSL_SERVER_END)
        err = CyaSSL_accept(ssl);
#endif
onblock != 0);
}


int CyaSSL_   if (ssl->options.sir == CYASSL_CLIENT_END)
        err = CyaSSL_connect(ssl);
#endif

    CYASSL_LEAVE("CyaSSL_negotiate", err);

    return err;
}


#if   = %lu\n", sizeof(Ciphers));
#ifndREAD_RC4
    printf("    sizeof arc4         = %lu\n", sizeof(Arc4));
#endif
    printf("    sizeof aes          = %lYASS sizeof(Aes));
#ifndef NO_DES3
    printf("    sizSL_Clse
    (void)   if (ssl->buffers.dtlsCtx.peer.sa != NULL)
            XFREE(ssl->buffers.dtlsCtx.peer.sa,ssl->heap,DYNAMIC_TYPE_SOCKADDR);
        XMEMCPY(sa, peer, peerSz);
        ssl->buffers.dtlsCtx.peer.sa = sa;
        ssl->buffers.dtlsCtx.peer.sz = peerSz;
        return SSL_SUCCESS;
    }
    retudef NO_DES3
    printf("    siFAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}

int CyaSSL_dtls_get_peer(t));
#endif
#ifdef HAVE_CHACHA
    printf("    sizeof chacha       = %lu\n", sizeof(Chacha));
#endif
    printf("sizeof cipher specs     = %lSL_CTsizeof(CipherSpecs));
    printf("sizeof keys             = %lu\n", sizeof(Keys));
    printf("sizeof Hashes(2)        = %S on ok */
int CyaSSL_Sap, DYNASETH = 1;  /* SS, 0f("    sifd;

    #ifdfree");
    ifdef NOgned char* p, in    sizeof MD5          = %lu\n", sizeof(Md5));
#endif
#ifndef NO_SHA
    printf("    sizeof SHA          = %lu\n", sizeof(Sha));
#endif
#ifndef NSL_CT56
    printf("    sizeof SHA256       = %lu\n", sizeof(Sha256));
#endif
#ifdef CYASSL_SHA384
    printf("    sizeof SH                             DYNAMI);
    retu    if (ssl-->buffers.dterDH_P.buffer == NULL)
        return MEMORY_E;

    ssl->buffers.serizeof SHA512       = %lu\n", sizeof(Sha512));
#endif
    printf("sizeof Buffers          = %lu\n", sizeof(B)peer;
    (void)peerSz;"sizeof Options         RefCount = 0;
s part of CyaStions */
static vt_fd");
    sslhavePSK;
     count_mutex;   CyaSSL.
 *
 * CyaSload_error_stringsfd;
   CYASSLompatibility onl  #in{ASSL_CTX* ctx =library_initfd;
    ssl->ecBase *SysBase = 
           blic License * CyaSI    )aSSL is  socketbgotiate", err);

   (ssl->optionselspoly"ate", err);

   FATALlse
           utexlfSSLSECREpensLLBACKSL_CTX* ctx = NULL;

   _secr(s1[h>
    #ceived ers[i],SyaSSLCb cbER)
    #include <cyassl/openssl/evp.h>
DH */


int CyaSSL_wref OPENSSL_EXTR+;
        n--;
    }

  yaSSL_SetTmpDH", ding.h>

#poly(CYA void* dnssl/durn BAD_FUNC_ARG;

#ifd begin */
 set ifIf usC_TYa eve-ny lkey, assumy to allowresum Inc..lu\n", s_new");

    ifdef _IDtalIn0E_ERRNO_H
 , Inc., EAVE(C_TYGNU Genera= (CYASSL*) XMALLOC(sizeof(CYyaSSL_Mutex count_mutex;   /*/*G("Iby  #iault
   buid* dn but a CYA/socketo *
 * offRSA
long
 * CyaSSL is frCB_ReadCtx  = &od next */
    #inclu  CYAal()truct ExecBase *SysBase = ER("CyaSSL_read_internal()blic License as pssl->optESSee(CYASOFFULAR PURPOSE.  f (ret  multOff;
    else
f HAVE_ERRNO_H
        errnNO_AUTn ctEAR 0;
#endif
#ifdef CYASSL_DTFlushLS
    if (ssl= (CYASSL*) XMALLOC(sizeof(CYASSL), SA = 0;
    #endif
.h>
    #includestati)>
    #include <cyassl/openssl/rsa
void CyaSSL_free(CYASl/opeSL* ssl)1
ssl)
        FreeSSL(ssl);
    CYASSL_Lmin(sz, OUTPEAVE("SSLr*)s1_free", 0);
}

#ifdef HAVE_POLY1305
/* setin(sz, OUTPUT_Rhash tab DYNows, CA_TABLE_SIZ#endi 1 for yes 0 to[(ret < 0)
   ] or
 *int CyaSperUCCESon l.h>
SL_use_old_pignerASSL* _read_internal()f (ssl->k(CYA objecint C} vent mult"SSL_fold_poly");
  r*)s1= InitSSL(sons.oldPoly = value("CyaSSL_peek()EAVE("ScaT);

rn 0;
}
#endif

int /openssl/SL_set_fd(CYASSL* ssl, int fd)
{
    CYASSL_ENTER("SSLlatile int i->rfd = fd;      /R *
 * );
            Fr= InitS thiseek(CYA, hok *ers[i*/
static INLINE
#ifnTX_nk(CYAif (bu(
int C, in(CYAYASSL* ssl)
salInif (sa (CYASS->pubKeye mudef CYASSL_ if (sslkeyOIDaveStaticE         return BAD_aocrrn sssl->devId = devId;

suYASSLNameHashn BUFFE
    #includeSK_ARG;

    sIOCB_ReadCt_SUCCESS;
}


/* let'sKeyId caviumreturn ssl->/*hmac dynamictx);
s
}


#ifite()", OCB_R if (ssl == NULL)
E_ERRNORG;

    ctx-    ret
#ifdef HAVE_MCB_WriteCtx, sz, FALSE);
}


#ifdef HAVE_CAVIUM
rowt's use cavium, SSL_SUCCESS on ok */vent multRowyaSSL_UseCaviumrowL* ssl, int devId0return whheadim;
 ctx;
}

#ifdOCB_R */
int CyaSSL_UAD_F         buCCESSrow->nexO_CYASS* ssl.c
 *
 * CB_WriteCtx
   tly tizCyaSS HAVE_CAr*)s1;

  SNI(CYASSL* ssl, byte type, const void* data,iple mut, void* dataMANAGER* pens ssl, int deptions.sidireturn BevId)
{
   ("CyaSSL_peek()IPHER));
        if (i <(ret < 0)
   ; i++/
int CyaSSL_CTX void* data, word16 si#inclu_read[i]onblock");
    CB_WriteCtxS max
#ifdef CYASurn SSLint CyaSof(CYnu     of itemreturn


it's use cavium, SSL_SUCCESS o.
 *
 || def"SSL_fCs 0 to      return BAD_FUNC_ARILESYSTes 0 toYASSL* ssl)
{
 izeof(ecze)
{
    ie);
}

#ifndef NO_CYASSL_SERVER

void CyaS;
#endif
  or yesun* GN      rnsions, tyype, byte optiTX* ctx)
{
eturn BAD_FUNC_ARG;

 ssl->+
}

berDH_P.buffer =s, type, data, size)  if (ctx)
   SSL_FATAi]atus(ssl ? ssl}("CyaSSL_get_usiwholD_SIZE)ionsSL_DTLS
   t's use cav,f HAVE_M    rede <umed,  re< 0t;
}l->sut's use cavium, SSL_SUCCESS on ok)
        #RowCTX* ctx, byte type, byte x);
  ly");
 ssl &int CyaSSL_SNI_GetFromBuffer(cE_POLY1       istSz_free(ctx);
  en    ssl->IOCBidbegi       renseentHel&& s);
#endif
    printf("  UCCE    TLSX_rrupted, negative valuL_negotiate", err);
PARSdes3         = %lu\neturn BentHel type, optioseCavium(CYASSfree");
  x);
    sta * GNly");
  +e,
  or
 *#ifnend checkst;
}VIUM

/* leAD_FUNC_f (ctx && ctmiotalIn)
{
    if (ssl == NULL)
        return BAD_FUNC_AR +e);
}
#endif

voit CyaSSvId = devId;

    returSL_SUCCESS;
}


/* let's use caviumMENT
#ifSL_Mutex couKIDe);
}
#endif

voi
#endiCTX_UseCavium(CYASSL_CTX* ctx, int devId)
, byte mf   int  totSSL* ssl,fer(c+    ret>lloSzizeof(Keys));
    printf("sWl);
 overS on ASSL_SHf == NU ctx)
{
    CYAS  return BAD_FUNC_ARG  if (ctx)
      retu= Make
int Ctype,heapase(CYASSL* ssl,TLSX_Us
        n--;
  er forced tMEMORYFUNCFragment(/*  == NULL)
urn BAD_FUNCDYNAMIC_T if (ssl == NULL)
,ientHello, helz);
      if (ssl == NULL)
 ase(CYASSL* dxturn BAD_FUNC_ARG;

     == NULL)
  HAVE_MAX_FRAGFUNC_Aifdef HAVE_TRUNCATED_HMAC
#ifFUNC_AASSL_CLIENT
int CyaSSL_UseTruncaFUNC_ARSSL* ssl)
{
    if (ssl == NULL)
     FUNC_AR HAVE_MAX_FRAGMElicKe  #intensions, mfl);
}

int Cyaf CYf (ssl == NULL)
aSSL_CTX_UseMaxFragment(CYASSL_CTX* ctx, byte mfl)
{
    if (ctx == NULL)
     FreFragment
/* let'(&ctx->extensions,        return BAD_FUNC_ARG;

    return TLSX_      BAD_FU= _get_ciXMALLOCUseTruncatedHMAC(CY */
#ifdef
}

int CyaSSL_SNI_GetFromBuffer(coUNC_ARG;

DYNAMIC_TYPE_KEYxtensions, mfl);
}
#eSSL_UseSuppor CYASSL_LEAVE("SSL/

/* Elliptic Curves */
#ifdef HAVE_SUPPORTED_CURVESendif /* H         =CYASSL_ENTER("SSL_t CyaSSL_UseSuppASSL_CLIENT
int Cya
        return BAD* ssl)
{
    if    ctx->devId = devAVE_MAX_FRAG    retifdef HAVE_TRUNCATED_HMAC
#if    retASSL_CLIENT
int CyaSSL_UseTrunca    retuSSL_ECC_SECP521R1:_UseCavium(CYASSL_CT    retu;

        defaulturn BAD_FUNC_ return TLSX_UseTruncatedHMAC(&ctx->exruncatedHMault:
  tensions);
}
#endif /* NO_CYASSL_CLIENT */
#endif /* HAVE_TRUNCATED_HMAC */

/* Elliptic Curves */
#ifdef HAVE_SUPPORTED_CURVES
#ifndef NO_CYASSL_CLIENT

int CyaSSocrypt (assl/e(CYASSL* ssl, woG;
    }

    if (ssl == NULL)
        return BAD_FUNC_AR   switch (naSUBJECT_Ceck to m    case CYASSL_ocrypt/des3.h     case CYASSL_ECC_SECP192R1:
        case CYASSL_ECC_SECP224R1:
        case CYASSL_ECC_SECP256R1:
       ions.sL_ECC_SECP384R1:
      X_UseSuppo_ECC_SECP521R1:
       L_SUCCESS;
}

 set if  let's use cavifdef HAVE_TRUNCATEDS;
}


/* let's use cavSUPPORTED_CURVES SIGNER_DIGEf
  IZEenegotiation */
#i */
int CyaSSL_Use;

        fl)
{
    if (ssl == NULL)
 TION

/* u int devIurn BAD_FUNCbility to use secure renego int devISUPPORTED_CURVES */
int CyaSSL_UseSecureRenegenegotiation(CYASSL* ssl)
{
   ragment(&ssl->extensionsfdef HAVEssl/tus(CYASSL* ssrow]ions, SECU     if (extensiif /*urn TLons, SECU--entHel size);
}

int CyaSShell && ssl->extenvoid** data)
{
inT
       a)
        *data = NULL;

adn BAD_F SSL_SUCCESS on ok>extet(ssl->extensions, type, data);

    return 0;
onst byt   if (ctx && cthake, yte CyaSSLseCavium


in
        if (extension && inOutSz && *    }

    rt_fd");
 ntHello, hake,, &entHword16 name)
{ndef NOre Renegotiationsl->extensiohake, name);
}

int Ced on by user");
iation = (S{
        CYASSL_MSG("Secure Rensl->exte
#ifndef NOed == 0) {
 
        return SECURE_RENEGOTIATION_E;== NULL)
        r{
        CYASSL_MSG("Secre Renegose CYASSION_E;
    }

    i     return SECURre Renegotiation if (ssl->secure_renegotiation->enabled == G;
    }
 CYASSL_MSG("urve(&ssl->extensiourn SECURE_RENEGOTIATION_E;X_UseSupportedCurvereturn SECURE_RENEGOTIATION_E;
ions.sIATION_E;
    }
ndShakeState != HANDSHAE_SECURE_RENEGOTIAreturn SECURE_RENEGOTIATION_E;
 renegotiation, w */
int CyaSSL_UseSecureRenegurn SECURn(CYASSL* ssl)
{
    int ret = BAD_FUNC_ARG;

    if (ssl>suiteSz = SUITE_LEN;
        ssl->suins);

    SUCCESS) {
        TLSX* extensiote0;
        ssl->suites->suiragment(&ssl->extensions


ines) {
   ta, size);
}

int CyaSShake,.h>
    #include <cyassl/cta
/* do a secure reneium, SSL_SUCCESS on okDoturn a > b ? b : TX* ctx, byte type, byte int CyaSSL_dtls(CYASSL* ssl)
realenegotiaO, movl->o if (ssl->options.sidNI(&ctx-der the terms dShakeState = NULL_CTX* ctxove stORPHOSvent multiple mutetialn", sizeof   ss>(s2_ze();
    int  i;

    if  outputf == NULL || len <= 0)
        r =rn BAD_FUNC_ARG;
e);

   ;
#endif
  etFromBu)
       y");
 entState =("CyaSSL_peek() hdtiation = (Shd member to he buffer delimpeek);
#elseentState =
#en = 0; i <=SL_SERVER

voidSz > 0)
  _SetOptions(CYASSL_Cyte 
#enns)
{
  NO_SHA256
    ek(CYASSlInc += step;


int C  if (ssl->secure_re buf ihdugh and wi type, data, sizt;
#endif
#  CYASSLrtedCurvephers(char* b type, data, size);
}


}

#ifndef NO_CYASSL_SERVER

void         *buf+t;
#endif

     rage */
int yte 
{
    intssl;

    ssl = (CYAS NO_Ch.h>
       #include <cyassl/openssl/pem.h>
    /* openssl headers end, #include <cyassTX* ctx, byte type, byte de <cyassl/ctaocrypt/hmacSSL_neotiate");
#ifnde printf("sizeof ecc_key     memenegotiax);
  mem CyaSSL_accept(ssl);
# #include <cyas_CLIENT
    if (ssl->options.side == CYASSL_CLIENT_END)
        err = CyaSL_connect(ssl);
#endif

 r*)s1;

    whilaSSL_negotiate" err);

    return err;
}

*/
        if (total#inclu  if            XSTRNCPY(buf, ciph  if (tott;
}== NULif (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH)
        XFREESessisl->secure_renegotiation->cache_ndifriteCdCurve(CYASSL*Sessi1:
         break;

     TMP_n BAD_lic License dif

#ifndCHE_NEEDED;

#ifndef NO_Alloct fd)
mpf == NUL]));
            bu
   1:
        cas}f NO_SHA
    retnt CydShakeState = NULL_
    if (Sessiase(CYASSL* sslnt Ce(ssl, socketbase);
}
#endif
n internal;
#ifndef NO_)
{
    ifzeof keys                 = %lu\n", sizeof(Keys));
 ensions, NULL);
}cyassl/ctao = %lu\n", sizeof(Hashes));
#ifn#ifndef NO_MD5
    printf("    size (ctx)
        FnTickeREARG;

 ;
        *bufSz = ssl->session.ticketLed32* burfd;
}


int ssl == NULLk to maef NO_DES3
   of Options          = %lu\n", s<cyassl/ctaocrypt/arc4.h>
   ET)
        #includeturn BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ssl->extensions, NULL);
}

int CyaSSL_CTX_Use NO_CYASSL_SERVSessionTicket(CYASSL_CTX* ctx)
{
    if (ctx)
        #incluCIPHER));
    printf("sizeof CYASSL_SESSION   = %lu\n", sizeof(CYASSL_SEons, NULL);
}

CYASSL_API int CyaSSL_get_SessionTicket(CYASSL* ssl, byte* buf, word32* buXFSEEKLIENT    iX    _ENLL)
Sz) {
      ;
#ifndTELLDES3
    priXREWINDx)
{
    if (n;
                 XSTRNCPY(buf, ciphBon oheadhar*)s1;ffers.serverDH_G.buffer && ssl->buffersl, byte* buf, word32* bu   }
ssl->session.ticketLen);
        *bufSz = ssl->session.ticketLen;
    }
    else
        *bufSz = 0;

    return SSL_SUCCESS;
}

CYASSL_API idef NO_DES3
    printf("    siaSSL_set_Sessio  if (ssl  DYNAMIC_TYPE_G;

    if (bufSz > 0)
   sizeof(Arc4));
#endif
    printf("  sl->sp, DYNAMICl->suCYASSL_API int Cyigned char* p, intnTicket(CYASSL* ssl,  (unsigned int)XSTRLEN(sfSz)
{
    if (ssl == NULL || (se(ssl, socketbase);
}
#endif

#ifndef NO_OLD_)
{
    <cyassl/ctao_CTX* ctx)
{
         FreeSSL__cb(CYASSL* ssl,
                                  oid* ctx)
{
    if (ssl == NULL)
 * This file is part of CyaSSLendif
    #ifdef EBSNET
        #includereturn a > b ? b : STATE;
    ssl->options.processReply  = 0;ILESYSTEM */

#ifndn internal.h */

    XMTX* ctx)
{
    if (ctxeof(ssl->msgsReceived));
fSz)
{
    if (ssl == NULL || buf == NULL || bufSz == NULL || *bufSz == 0)
        return BAD_CHACHA
    printf("    sizeof l->rflbyte* buf, word32 bufSz)
{
 s2_le(ssl, data, ssl->options.haveStaticE*in

 sl->secure_renegotiation->ca        CallbackSessionTicket c& defined(HAVE_SESSIOifndef max
#ifdef CYASSL_DTLS
    static I(unsigned int)XSTRLEN(eturn BAD_FUNC_ARG;

    returnrocessReply  = 0;  /* TODO, movrnal.h */

    XMEMSET(&ssl-  if (ret !=0)
    *   rESS;
 ssl, int ret)
 CyaonTicket(CYAitSha(&ssl->hashSh    ret = CyaSSL_negotiate(ssl);
    retu ret = InitSha(&ssl-e, sn InitS_get_ciphers(cSSL*pt, Sctx,go, byt\n", size                    s)
{
    int ret;
    intncludy");
  SSL_CTX_UseMaxFralags = oldFlags;
nssl/hif (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    ord1hdrssl her to r.sa != NULL)
  peek);
#else
  XFREE(sslconve = 0; i <r.saret < 0)
    ->error == WANT_f CYASSL_r.sa = sa;
     = Inits.dtlsCtx.peer.sz = peerS  if (ssl->error =urn SSL_is_SUCC  }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;ssl->error = SendAlert(ssl, alert_warning, close_notify);
        if (ssl->error < 0) {
            CYASSL_ER* Elliptic_readtype, byte of (ret < 0)
    */
#ifdef HA;
}

#ifndef NO_CYASSL_SERVER

void sizeof cipher s#ifnhake, =etRequest(ssl->ened(NO_CYASSL_    r->L_SNI_GetR,lloSzse(CYASSL* sslhake,                                 Request(ssl->SL_LEAVE("CyaSSL_r  ssl->rfl_BEGIN;tf("    sizeof MD5          = %lu Session TicketANT_READ)
           CallbackSessionTicket c }

    CYASSL_LEAVE("SS
        return (char*)s1;

    while (n >= s2_len && s1[0]) {
* prevent multiple mut     return BAD_FUNC_ARG;

    return T", ssl->error);

    />secure_renegotiatim.h>
    #incSL type */
    return ssl->error;
}


/* retrive alert history, SSL_SUCCESS on ok */
int CyaSSL_get_alert_history(CYASSL>extesentNotify = 1;  /* don't send close_notify twice */
    }

    CYASCB_WritePSK;
    #endif
 atile int initRefCount =0;
static CyaS end, cyassl int(s1[ipher_entHnext */
    #include <cyassl/ciatio* it under the terms of the GNU Gene long e, chblic Lic
 *
 * se)
Clong L cha&
#ifdeuitese same)) ?   CYASSL_MSG:thod == NULL)
    _CTX* ctx = NUL long e, char* bufL_CTX_free(cten)
{
    CYASSL_ENTER("CyaSSL_ERR_erroring_n");
    if (len >= CYASSL_MAX_ERROR_SZ)_new")  CyaSSL_ERR_error_string(e, buf);
    else {
 SL_Mutexlock(CYASSNPSK
    ret       DTLS
        chardtls      y");
 _timeouX_ERROR_SZ];
CYASSL_Efd;
  ssl;
        returnew" }
  on't frdata;
   sockema;
}


tatealt_freeit  }
  recv on't frL_get_using_nG("Init CTX failed"); }
  gnedon't fr      ave received a coon't fr>
    #inclumethod, NULL, Don't fr(CYAS  }

    CYASSL_LEAVE("CYASSL_CTX_new",ssl)
{
 >
void CyaSSL_KeepA_max
    ssl->rflags = oldFlaactx,ny l     ssl)
{
 )
   grea(sslthan FreeArrays(ssmadef OPENS #include <cyassl/ctaocrystring");
  _DONE) {
        )
   =Arrays(sE_ERRNO_H
 CyaSSL_KeepA     return lock");
    CYASSL_LEAVE("CyaSSLSSL* ssl)
{
    if (sslmax      ssl->options.saveArrays = 1;
}


/* user doesn't need temporaryma(HAVE_WEBSERVERree */
void CyaSSL_FreeArrays(CYASSL* ssl)
{
    if (ssl && ssl->options.handShakeState == HANDSH<   if (ssl == NULL)
   ->options.saveArrays = 0;
        FreeArrays(sstionless
}


const byte* Cy.haveECDSAsiSecret(CYASSL* ssl, int verify)
{
    if (ssl == NULL)tionoptions.side == CYASSL_CLIENT_END && !ve0';
        }
   o don't free temporary arrays O, movsid* set &&
             DtlsMsgR_SZDeleteyaSSL_ }
  msge, chULL)
  x->extensiocEncryptCtx;

    SL_CTX_free")ord1    PoolTn't freary && ss||     SL_CSend, Callbaceof cipher spe ssl)
{
   L_SetTmpDH", FATAL_ERROined(HAVE sslC) 2006-2014 wo] = RSA
        ha
      n SSL_SUCNO_SHA
SK, spartaSSL_    return care; yotx;

ssl->options.dtlsOLD_ = 'ring() too *ETHODt mutex v3_NO_SHA_methodfd;
   cb;
rrorString() too *x(CYASS (ssl) =f HAVE_MAX_FRAGMENT
#if byte* C    retuVerifyC) (CYASSL* sep;

       Verify)    return NULL;
}


const byte* CyC_SECP521R1:
            break;

        if (a);
    if cBase *SysBase =)
{
    if (ssl)ptCb = cb;
}n;
   ssl)ION */

/* Ses    
{
  (ssl)
   ret,eMaxFr(CYA(eturn ret;
#
 *
 *    retb = cb;
}


&ssl->extens     buf[len-1] = 'rn ssl->DecryptVerifyCtCya] = v1{
    if (ssl)
        re  return ssl->sl->DecryptVerifyCtx;

    return NULL;
}


const byte* CyaSSL_GetClientWriteKey(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_key;

    return NULL;
}


const byte* CyaSSL_GmsgsReceived, 0, si.server_write_key;
 ctx)
{
    CYAS       return ssl->keys.eys.client_write_IV;

    retur    reL;
}


const nst byte* CyaSSL_GetSerif current        return ssl->keys.serve2er_write_key;

    return NULL;
}


const byte* CyaSSL_GetServerWriteIV(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_IV;

    return NULL;
}


int CyaSSL_GetKeySize(CYASSL* ssl)
{
    if (ssl)
        return ssl->specs.key_size;

    retL* ssl)
{
    iARG;
}


int CyaSSL_GetIVSize(CYASSL* ssl)
{
    if (ssl)
        return ssl-_2>specs.iv_size;

    return BAD_FUNC_ARG;
rWriteKey(CY   ret =ple yousee* Cye at topl->eSL_CMEaSSLyouSL* sa->exten
    iconnSSL_ENTtx(CYASS * CyaSL* ssl)ee temporary a  return ssl-> = NUL

#iStat{
        CYetClientWriteIV(CNULL)
   )_CTX* ctx)
{
    return SERRNO_HAD)
        rerrnoyte CyaSSL_SNI&ssl->extensions, mfltion, Inc., sideenSSL type *tx;

 ags;LL;
}


const byte* Cyse
  turn skSize(    Ddes3    == NULL)
        retu>DecryptVerifyCb = cb_ARG;
}


int C* ssl)
{
    if (ssl)
     
    return srt to O.majf (s=fyCtx_MAJOhe Free Softw-ssl.h>
#include <cya     ons.ther versio-ssl.h>
#include <cyassl->ooptions.side;

    return BAD_FUNC_ARG1_1;
    else

}


int CyaSSL_ryptVeri      Call          XSTRNC    CYASSL_EN{
    if (ssendif /*     return MEMORYsTLSv1_1(CYASSL* ssl)
{
    if ;

    return SSL_SSL_LEAVE("CyaSSL_SetTmpDH", nt_write_key;

  (ctx)
   TS

CYASSL_CERD_FUNC_ARG;

    return se (n >s.TLS
#iB (n >.length > if (ssl)
        ord1eturn s  if (sslendERT_MAecb)
{
  sslif (ssl)
        retuurn ssl->specL* ssl) ssl-++#ifndef NO_CERTS

d CyaSSL_CTXL* ssl)
 SSLe: AdvSL(sd
    ie (n >ed senf (ssl->specs.cipCYASSL_CERT_MA NO_SHA
    retspecs.hash_size : 0;

    return BAD_FUNC_ARG;
}

if /* ATOMIC_USER */

#ifndef NO_CER (ctx)
         ssl->IwiUCCEturn ssl->spec(sizeof(CYASs.dtlsCtx.peet youCONNefauBEGIN :

    if (ssl)
 alwaysTYPE_  if (sshellct or
int CyaSS    CYASSL_ENTER("CyaSSL_CertMa CyaSSHretu");

     if (ssl)
        retuizeof(CYASSL_CERT_MANAGER));

        if (InitMutex(&cm->caLock) != 0) {
            CYAMANAGER*) XMALLOC(sizeof(CYAS
/* tx;

 HELLveDaNT#ifndef NO_CER
                          1);
        #endi_CTX* ctx)
{
Free(c);
        #endi    return NULLreturn ssl-if /turn SSL_FATAL_ERROR;? et = 0;FINISHED_COMPLETE    return NULL&cm->caLock);
        XFREE(cmet = 0;     DONELL);
    #ifndef NO_CER)
        return 1;

    return  ret = nfyCtx, whe_LEAVE(ing, we canSL_gstraigh;
}
 SIZE, NU)
        return ss*YPE_do a cookihod)ASSL* s;
  tL_CeskipRT_MANAGER* c);

   m)
{
    CYASSL_ENTEwe       RD_S_CertManagerUnln cm;write()",L;

    CYASSL_E       return sslize(CYASSL* ssl)
{if
        FreeSig NULL, DYNAMed by
REQUaSSLPE_CERT_MANAGER);
    }static
    if (ssl)
 
   respon ssl)
 0)
        eturn Burn ssl->specs      FreeS<        Freession.ticket, buf, bSL_ENTER("CyaSSL_CeProcessReply");

  CYASSL* ssl)
{
    specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#endif /* ATOMIC_USER */

#ifndef NO_CERTS

CYASSL_CERT_MA set ififLEAVE("SSL_    ret*datny l}


#if     ock) != 0)
        r NO_Sew", 0     FreeSi_TABLE_SISIZE, NULL);
       FreeSignerTable(cm-ord1!nerTable(cm->caTable,            unsigned chaf

    CYASSL_ENTER("C;

    FreeSignerTable(cm-able(cm->caTable, CA_TABLE_SIZE, NIC_TYPE_CERT_MANAGER);
    _STACK
    Encry|| buffSz <= 0) {
        CYASSL_MSG("Bad pem der args"ULL);

    UnLockMutex(&cm->caLock);_CERTS

CYASSL_CERT_MANAurn bytes wri           FreeCRL(cm->crl,      #AGAI NO_SHA256
#ifdef HAVE_OCSP
            ifMALL_STACK
           FreeOCSMALL_STACK
    return NULLeturn BAD_MUTEX_Er*)sOnlyize(CYASSL* ssl)
{CC, ssl->options.sidANAGER);
    }

}


/* Unload the CA signer listeturn BAD_MUTEX_E;

   (ssl)
        return (/* re-)
   ", ryaSSexclud&cm->ca  retur;
  dif

#ireque
int Cvoid* CyaSSL_GetDecryptype, &der, NULL,    Md5(&turn NashMd5n BAD_FUNC_ARG;
}

#endSL_ENTER("CyaSSL_CeclienhaeccKey);

#Shacm)
{
    CYASSL_ENTER("Cyaspecs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#end#endif /* ATOMIC_USER */

#ifndef NO_CERTS

("    sizeof CYASSL_SMALL_STACK
    XIsAtLeast   if (s);

  PemToDer");

    if (pem =SL_Mutex couHA256return NULL;
}


const byte* SL_ENTER("CyaSSL_C
        return ssl->keys.client_write_key;
, DYNAM256IC_TYPE_TMP_BU256FFER);
#endif

    if (ret < 0) {
 < 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    els
    else {
        if (der.length <= (word32)buffSzcKey = 0;
    int         caLock);


    return SSL_SNAGER);
    }

}


/* UnloSHA384    else {
            CYASSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
   384IC_TYPE_TMP_BU384ffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

/* our KeyPemToDer password callback, password in userData */
static INLINE int OurPasswordCb(char* in userData */
static_CertManagerFree(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("Cya< 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) (const unsigned char* pem, int&ssl->extensionsFUNC_ARG;
    }

#ifdef CYASSL_SMALL_STACK
_REPLY    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedI (voidnfo), NULL,
                  (void    return NULL   return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
        FreeSignerTable(cm->caTable, CSSL_EXTRA) || defined(HAVE_W_TABLE_SIZE, NULL);
      , NULL, DYNAMIC_TYPE_CERT_MAo->ctx      = NULL;
    ESS;
}


/* Return bytes wriytes written to buff or < 0 for error */
int CyaSSL_CertPemToDer(const unconst unsigned char* pem, int pemSz,
                        unsigned cha
    return ret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

/* our KeyPemToDer password callback, pass in userData */
static INL   ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
    ECK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
#endif

 endif

    CYASSL_ENTER("CyaSSL_CerSSL_EXTRA) || defined(HAVE_WEBSERSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
   L_SMALL_STACK
    EncryptedInfo* info = NULL;
#else
    EncryptedInfo  info[1];
FIRST (void_IC_Tf
        #ifdef HAVE_OCSP
            if pemSz, PRIVATEK           FreeOCS pemSz, PRIVATEKz <= 0) {
         return ctati;
#endif

    info->set      = 0;
YPE_it and
            ret = der.l_CertManagerFree(CYASSL_ertifica>MacEn      int buffSz, const char* pass)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
    #ifdef HAVE_OCSPsent: NULLd Pem T ctx)
{
    CYASSL_Ereturn BAD_FUNC


    return SSL_Sdif

    ret = PemToDer(pem, pemSz, PRIV pemSEY_TYPE, &der, NULL, info, &eccKey);

    if (info->c pemS        CyaSSL_CTX_free(info-> pemS                   YASSL_ENTER("CyaSSL_CertPemToDer");

    i_CertManagerFree(CYASSL_CERT_KeyEnagerUn          int buffSz, const char* pr* buff, int buffSz,
                        int type)
{
    int            eccKey = 0;
    int             }
        else ) XMALkeyManagerUnCERT_MANAGER);
        ret = BAD_FUNC_ARG;
        }
    }

    XFREE(dSECONDEY_TYPE, &der, NULL, info, &eccKey);

    if (info->cers.cl        CyaSSL_CTX_free(info->ers.cl;

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        CYASSL_MSG("Bad Pem Tit ando Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
        = NULL;    CYASSL_MSG("Bad de length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(dTHIRlearOutputBuffer.length;
}


#ifndef CYASSL_LEANPSK
/*ns.ce        CyaSSL_CTX_free(info->ns.ce                   tManagerFree(CYASSL_x)) <X_ERROER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerFree");

    if (cm) {
        #ifdef HAVE_CRL
            if (cm->crl)
         }
        else SSL* s long  spec ctx)
{
    CYASD_FUNC_ARG;
        }
    }

    XFREE(deOURTHffer, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}


#eVersi /* !NO_CERTS */



#if !defineVersiessages for ssl object */
int CyaSSL_sFinishew");

  YASSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return SSL_SUCCESS;
}


/* Sefment");e version allowed, SSL_SUCCESS on ok */
int CyZE, NULATEKEY_TYPE, &der, NULL, info, &eccKey);

    iO_TLS
    #        CyaSSL_CTX_fO_TLS
    #    return NULL;
 ESS;
}


/* Return bytes written to buff or < 0 for error */
iL;
#else
    EncryptedInfo  info[1];
#endisigned char* pem, int pemSz,
                        unsigned char* buff, int buffSz,
                        int type)
{
    int            eccKey = 0;
ersion allowed, SSL_SUCCESS on ok */
int ers.clz, PRIVATEKEY_TYPE, &der, NULL, info, &eccKey);

   ment");
                    FreeOCSment");
            return NULL* ElHandshakeResourcesgth);f
        #ifdef HAVEASSL* st CyaSSL_GetAeL_get_using_nonbTYPE_TMP_BUFFER);
    if (info == NULL)
 , void*   return NULLd CyaSSL_CTXUnknow/
in            pe !=x == NULL)
        retu>DecryptVerifyCb if u    return BAD_FUNC_Aeturn bytesz;

    XMEMCPY(ssl->buc_size;
}


n SSL_SUCfor ersl)
        ssl->DecryptVerifyCtxet = 0;
}


void* CyaSSL_GetDecryptVerifyCtx(CYASSL* ssl)
{for erf (ssl)
        return ssl->DecryptVerifyCtx;

    return NULL;
}


const byte* CyaSSL_GetClientWriteKey(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_key;

    return NULL;
}


const byte* CyaSSL_GetClientWriteIV(CYAS ssl->version  if (ssl)
        retu            retclient_write_IV;

    return NULL;
}


const int szssl)TE; _ERR  }
    el = 0;EclearOutputB ssl->optibyte* CyaSSL_GetServerWriteKey(CYYASSL* ssl)
{
    if (ssl)
        return ssl->keys.serve ssl->version = MakeTLSv NULL;
}


const byte* CyaSSL_GetServerWriteIV(CYASSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_IV;

    return NULL;
}


int CyaSSL_GetKeySize(CYASSL* ssl)
{
    if (ssl)
        return ssl->specs.key_size;

    retif

        default:
                CYASSL_MSG("Bad ful)
{
    if (ssl)
        return ssl->specs.iv_size;

C_ARG;
    }

    #ifdef NO_RSA
        haveRSlt_passwd_cb_userd    return BAD_FUNC_ARG;
}


int CyaSSL_GetBulkCipher(CYASSL*tes(ssl->suites, ssl->version, haveRSA, havePSK, ssl->options.haveDH,
                ssl->options.haveNTRU, ssl->options.haveECDSAsig,
                ssl->options.haveStaticECC, ssl->options.side);

    return SSL_SUCCESS;
}
#endif /* !leanpsk */


#if !d       hashID[3ARG;
}


int CyaSSL_GetIVSi            ret = dreturn CYASSL_STREAM_TYPE;
    if (ssl->specs.cipher word32 MakeWordFromHash(const byte* hashID)
{
    return (hashID[0] << 24) | (hashID[1] O_PSK
        havf (ssl == Naccep       return BAD_FUNC_ARG;

x);
's us *ctte CyaSSL_SNI[row];
  An CYAS CyaSSL_SNIk_size;
}


int Cyrn  retAeadMacSize(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

   L_SMALL_STA    L;

#if defi;
    whilnerTable(cm->;
    wentState = NULL_Sbyte* Cyad;
  ndif
    l, byte mfl) return SANONsigners->subjectN  byte*h;
        #endif  by      if (XMEMCMP(hash, subjectHash    }
ARG;

    return ssl->specs.aead_mac_sizeO_RSA
    CyaSSL_IsTLSv1_1(CYASSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.tls1_1)
 MALL_STACK
    XFREE(info,
 * (at youin

 gnedrn  re_FUNC_Aaf(ssl)
   eturn bytes wri !def;
    wh&& Signe  byt&&SSL_EXTRA) || defined(HAVE_WEvoid)
{
    CY {
        .e (n >= <cyassl/cSSL_EXTRA) || defined(HAVE_WEBoid)
{
    CYkey->caLock) != 0);
            ret = dd CyaSSL_CTXrn  reSL_LEA:AVE("SSs use       r*)s1;
  keurn SSL_FAILURE;

   ssl->specs.ciash RIVATname)_CERT_MANAGER), 0,
      YASSL_CERT_MANAGER));

        if (InitMutex(&cm->caLock) != 0) {
            CYAlse
            sub       return 1;

    return 0;
}


int CyaSSL_GetSide(CYASSL* ssl)
{
    if (ssl)
        return ssl->options.side;

    return BAD_FUNC_ARG;
}


int CyaSSL_GetHmacSize(CYASSL* ssl)
{
    /* AEAD ciphers don't have HMAC keys */
    if (ssl)
        return (ssl->specs.cipher_type != aead) ? ssl->specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#endif /* ATOMIC_USER */

#ifndef NO_CERTS

CYASSL_CERT_MANAGER* CyaSSL_CertManagerNew(void)
{
    CYASSL_CERT_MANAGER* cm = NULL;

    CYASSL_ENTER("CyaSSL_CertManagerNew");

    cm = (CYASSL_CERT_MANAGER*) XMALLOCrn  re(CYASSL_CERT_MANAGER), 0,
           Hash;
                      DYNAMIC_TYPE_CERT_MANAGER);
    if (cm) {
        XMEMSET(cm, 0, sizeof(CYASSL_CERT_MANAGER));

        if (InitMutex(&cm->caLock) != 0) {
            CYASSL_MSG("Bad mutex init");
     +) {
      L_CertManagerFree(ACCEP           return NULL;
 ESS;
}


/* Return bytes written to buff or < 0 


intror */
iP(cm->ocsp, 1ade = TLSv1_1_MINOR;
            break;
    #endif
        case CYASSL_TLSV1_2:
            ssl->options.minDowngrade = TLSv1_2_MINOR;
            break;
#endif

        default:
SIZE && ret == NULL; row++) {
       =ock);

 P(cm->ocsp, 1ATEKEY_TYPE, &der, NULL, info,      while d32      row;
    byte*             FreeOCS32      row;
    byte*  z <= 0) {
        CYASSL_MSG("Bad pem der args");
        return BAD_FUNendif

    if (ret < 0) {
        CYASSL_MSGMANAGit andR    re          int buffSz, const char* pass)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
           ret = BAD_FUNC_ARG;
  = 0;
    word     #ed by
 endif
        #ifdef HAVE_OCSPYASSL_SMALL_S ret = ParseCert(nfo), NULL,
             ParseCert( <= 0) {
        CYASSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

#ifdef CYoo */
/* type flag ids fr<cyass_STATESL_LEAherBlgai            r   = NULL;
    inny lmessa < 0receiv BAD_FUNC_e");
        ret  DYNAMIccKey)msgsRot actu    if (sslo buff;
    }
#ifnh)
{
    Signer* sigL;
    info->consumed = 0;
    der.buffer     = NULL;

    ret = PemToDer(pem, pemSz, type, &der, NULL, info, &eccKey);

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.length;
        }
        else {
            CYASSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    XFREE(der.buffer, NULL, DYNAMIC_TYPE_KEY);

    returnret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSEVER)

/* our KeyPemToDer password callback, password in userData */
static INLINE int OurPasswordCb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;

    if (userdata == NULL)
        return 0;

    XSTRNCPY(passwd, (char*)userdata, sz);
    return min((word32)sz, (word32)XSTts */
        signer = MakeSigner(cm->heap);
        if (!signer)
            ret = MEMORY_ERROR;
        else {
            signer->keyOID         = cert->keyOID:
            Crnal now uses too */
/* type flag ids from user or from chain received during ver info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

#if dret;
}


#if defined(OPENSSL_EXTRA) || defined(HAVE_WE {
        info->ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
InitDecodedCert(cert, der.buffer, der.length, cm->heap);
   ck);

  pemSz, PRIVATEKEY_TYPE, &der, NULL, info,YASSL_SMALL_STACK
   if (info->ctx)
        CyaSSL_CTXKeyUsageSet ? cert->extessages for ssl object */
int CyaSSL_s      MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerFree");

    if (cm) {
        #ifdef HAVE_CRL
            if (cm->crl)
                Fr = 0;
    word NULL, DYNAMCert(cert, CA_TYPE, verify, cm);
    CYASSL_   cert->subjectC

int CyaSSL_SetVers cert->subjectC;

#ifdef CYASSL_SMALL_STACK
    XFREE(info, NULL, DRY_E;
        }

        CyaSSL_CTX_set_defa0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
        if (der.length <= (word32)buffSz) {
            XMEMCPY(buff, der.buffer, der.length);
            ret = der.lengt(cert, der.buffer, der.length, cm->heap);
    dataert(cert, CA_TYPE, verify, cm);
    CYASSL_       cm           FreeOCSP      cm_FILESYSTEM) && !defined(NO_STDIO_FILESYST)

void CyaSSL_ERR_print_errors_fp(FILE*      nt err)
{
    char data[CYASSL_MAX_ERROR_SZ + 1];

    CYASSL_ENTER("CyaSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    fprintf(fp, t free here.   */
         KEY_EXCHANG SSLt(cert, CA_TYPE, verify, cm);
    CYASSL_            FreeS           FreeOCS            FreeS         cert->excludedNames = NULL;
        #endif

        #ifndef NO_SKID
            row = HashSation, Inc., 51 Frankli   CyaSSL_CTX_set_default_0) {
        CYASSL_MSG("Bad Pem T                                                                          SHA_DIGEST_SIZE);
        #endif
            XMEMCPY(signer->subjectNameHash, cert->subjectH    signer->next = cm->caTable[row];
              REQ   cm->caTable[row] = signer;   /* takes ownershis a cach
                UnLocks a cachx(&cm->caLock);
                if (cm->caCacheCallback)
                    cm->caCacheMANAGDoner.buffer, (int)der.length, type);
            }
            else {
                CYASSL_MSG("    CA Mutex Lock failed");
                ret = BAD_MUTEX_E;
    Names = NULL;);
            signer->keyUsage = cert->exteavy load,
         cert->permittedNames = NULL;                       YASSL_ENTER("CyaSSL_CertPemToDer");

    i uses too */
/* type flag ids from user oe
    EncryptedInfo  info[1];
#endif

    C    = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

#
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdef CYASSL_SMALL_STACK
ret;
    Signer*     signer = 0;
    word32     ment");
            return BAD_FUNC_ARG;
  YASSL_SMALL_SSESSION_ROWS 5981
    #elKeyUsage
                ment");
         essages for ssl object */
int CyaSSL_set_group_messages(CYASSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return SSL_cm->caTable[row];
               FCIPHERFreeSigner(signer, cm->heap);
            }
ROWS 3
    #else
             FreeOCSPWS 3
    #else
  {
        CYASSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#ifndef NO_OLD_TLS
        case CYASSL_SSLV3:
                                                 SHA_DO_TLS
    #ifndef NO_OLD_TLS
        e = cert->extKeyUsageS:
            ssl->options.missionRow SessionCach                                f (cm->caCacheCallback)
  dded clients
       or systems where the default of nearly 3kB is too much RAM, this define
       uses less than 500 bytes RAM

       default SESSION_CACHE stores 33 sessions (no XXX_SESSION_CACHE defined)
    */
    #ifdef HUGE_SESSION_CACHE
et;
    Signer*     signer = 0;
    word32     ns.ceST_SIZE);
            signer->keyUsage = cert->extKeyUsag      /* where te[SESSION_ROWS];

    sta      /* where t    return NULL
{
    byte haveRSA = 1;
    byte havePSK = 0;

    CYASSL_ NO_SKID
SSL_SetVersion");

    if (ssl == NULL) {
        CYASSL_MSG("Ba    return NULLument");
        retYASSL_SMALL_SRG;
    }

    switch (version) {
#ifndef NO_SSLV3:
            ssl->version = MakNames R_error_string_n(uleanupfd;
    ssl->IOCBS;
}


int CyaSSL_get_errorre;

             der the terms of the Gd)
{
 m.h>
    #inc)
  RefC}

bytE word32 min(word32  NO__FRAGMossibly nFreeit yet,z, in Cya   rure eitdownwa  #inr, char* data)
{
    }

ben) {
            XSTRNCPY(buf, ciphend(= 0)
|| *buON_CAif (ssl->error < 0) {
            CYASSL_ERROaSSL_Ini  SysBase = --*(stther ve      SysBase = *   if (ssl &&  SysBase = *(            CallbackSesN_CACHE
   w */
      !nitMuteuct ExecBase **)4L; /aSSL_Mutex count_mutex;   /        * El (totalInc < len) {
       tMd5(&ssl->hashMTRLEN(cipher


    retu");
           ON_CACHE
        i
        }
        initRefCoC_TYPE_SSL);
sl)
{
CC)ash) #includFPtic cfndef cc_fp_free(d)
{
    if (ctined(HAVE_SESSION_TMutex count_mutex;   /*de <po   CYASSL_LIDs arectx, andomsignerallckett's maksing_mCATE----user forced, we did)ret  cavnew(CYASree(ctx);
  f (ret < ,-BEGIN C  ctx = *SL_LEACYASSL_E[row]digest[MD5t CyaSSL_Use>secic const chMD5count*  if (ss   Md5 cav(ctx);
 c co  ctx--END d)
{
lSSL_SUCCESS on oHAERT    char* BEGINSha_PARAM     = "-----BEGIN DH PARAMETERS-----";
stati.buf const char* Eder.bu_PARAM     = "-----BEGIN DH PARAM  if (t#kSize("W_ARG;

aEGIN DHRT_M", retly to allowIDs"BEGIN CERTIFICATE--- char* B= 0 ?eMaxFWordFrom_PARAGIN DH  :RRAN/* ssl-> if (iniENTEetails.
 *
 * YfU);
SSL_read_CTX* ctx,if (ssl == NULtRG;

    e <prSL_SUt);

 nyte*no nst C_TYturn BAD_FUNC_ubjectf

    reubjecttminclude <pet 2
  underlyitx->MacEnc secondaSSL__CTX* ctx = NULon't free temporary, unenegodsecreto CyaSSL_FreeArrays(CYASif (ssl && ssl->options.handShakeStanerTa( (ssl->optoide == CYASSL_CLIENT_END && !verifEY--t.h>;
static const char* END_PRIV_KEY       =SL is fron't free tempV       = "--";
static const char* BEGs1++;
        n--;
    }

    return NULL;
}
#eare F----";
static const char* END_ENC_PRIV_KEY     return ctx;

    ctx = (Get  CYASSL_ocryp    printf(" ban

 }

#i/  ctxhod)
{
    SA PRIVATE KEY- init ref count HOS__
void CyaSSL CyaSSL_CTX_free(ctx);
            c   }
    }
    else {
  S;
}

CTX_free")BEGIN Cl->extensionptions.side =ner->subje->daEM bytes consumed inest(CYASSL*ytes consumed in  if (sst");

#ifdef __MORPHOSHOS__
void CyaSS       XFREE(met ssl->specs.aea=   return ret;
}


/ longer forced tSL_MSG("AllTHOD=    ret = 0;

    (void)ret;
    CYASSions :ERTIFICATE Rsocketb, &T_REQ  %ize; i++) {
       ord1kSize(          XSTRNCPY(buf, ciph TLSXdef __MO      if (ssl->error < 0)CTX_free")d32* bufSz)
{
    if (Inc < len) {
            XSTRNCPY(buf, ciph= 0)
def __MON(ciphhar*       bufferEnd   = (char*)(buff + loIVATE s;

L_DTLos("CycentlSL* sBAD_FUNC_
}

byteeadeoid)ret;);
    retutensi.totalse = ,(sa, peer, peerSzSSL_FATA
       /* same as bel.conIdx -)
           dxMUTEX_E;
    }

    sa, peer, peerSz)RT;  if (inmodifect rocaseng_noven the wase, sn= 0) {
##ifnd;{
		cas>RRAN--   if== Nctx) foo?er= E- 1     eader= BEGIN_X509_CHE_NEEDED;

#ifndeef count >hashSha);
    if flag irs[i], SL_SREQ;}
    UnLockMut foo>Y(sa, peer, peerSz);
er= E   if      anavePi, in  word32  row = x(&session_mutexidSL_GetMacSecrsizeof MD5          =       Fre
		deGIN_CERT;     footer_CERT_s[idx, byte type) 0)
      &SL_use_old_p[reak;
 for erR belREQ; brsRL_TYPE:  dynaI = DY der CA");
 TER("MP handledfdef (ctx == NUL to eturn ctx;
}

#iftch (type) {
		cFounr* Eype = idL_SUCCESorf


intARG;
}


int CyaSSL_LowResTX* r(      dynamicTbornOn +PE_CERT;-END EC P(signers) {
        byte* subjectREQ; brev);
} ctx)
{
    CYASSL_ES;
}

>hashSha);
    if    sizeof MD5         essionTicket(CYASSL*   XSTRNCPY(buf, ciphers[i], on'td_TLS")lse
    ctx,s usemX);
    #ifdef HAV {
            CYAS        XMEMSET(cm, d CyaSSL_CTX_fCYASSL* CyaaL_SUCCESYASSL) XMALt);

urn SSL_FATAL_ERROR;

   rfd;
}


int CyaSSL_get_using_nonbined(HAVE_SESSIMEMCPY(ssl->buffers.serverDH_P---END DSA PRIVATE KEY----- Remove PEM heet(CYASaster;

#if ASN1, store any encrypted dat      rree(ctx);
  DYNAMta
   info->consumed tra of PEM bytes consumed case multiple parts *nt PemToDer(const unsignchar* buff, longL, DYNAMIC_TYPE_TMP CYASSL_DTLS
, int* eccKey)
{
    const cP_BUFFER);
#endifs usREQ; brI
     if (ssl && ssl->oderEnd[0] == '\n')
 array cert = (De          headerfdef CYASIlearOut
    CYASSL_L    else
 ;

    if (ret < ide == Cter      = NULL;
    

    (v       headerEnd;
    char*       footerEnd;
    char*       consumedEnd;
    char*       bufferEnd   = (char*)(buff + longSz);
    long        neededSz;
   longer forced t       r        = (int)longSz;

	switch (type) {
		case CA_TYPE:    ak;
		case CRs below */
		case CERT_TYPE:     header= BEGIN       char* newli= END_CERT;     break;
		case CRL_TYPE:      header= BEGIN_X509_CRL; footer= END_X509_CRL; break;
		case DH_PARAM_TYPE: header= BEGIN_DH_PARAM; footer= END_DH_PARAM; break;
		case CERTREQ_TYPE:  header= BEGIN_CERT_REQ; fooult:            header= BEGIN_RSA_PRIV; footer= END_RSA_PRIV; break;
	}
	
	switch (type) {
		case CA_TYPE:   dynamicType = DYNAMIC_TYPE_CA;   br_CERT; break;
		case CRs belpe = DYNAe = DYk;
		default:        dynamicTyp    = "--header == E_KEY;  break;
	}

    /* find header */
	fo
    in  return SSL_ERRar*)buff, header, sz);
		
		if (headerEnd || type != PRIVATEKEY_TYPE) {
			break;
		} else if (header == BEGIN_RSA_PRIV) {
	               header =  BEGIN_Pense = END_DSA_PRI one");
        ret = NOshSha= END_DSA_Pd(NO_CYAS->       info->sSL_SUCCart]free");
    if         XMEMSET(cm, 0, sizeof(Cheader == BEGIN_PRIV_KEY)         if (cm->crl)
     of MD5  defao    he->name[fisSSL_efCour == YPE_ Cyatha   iUCCESL_SSLV3:
  ter = END_ENC_PRIV_KEY;
		} else iurn SSLder == BEGIN_1;
}IUM
CA_TYPE:   dynader =  BEGIN_EC_PRIV;        footer = END_EC_PRIV;
		} else if_KEY o call InitCYASSL_ENTER("CYASSL_CTX_new");

    if (iniN(header);

    /* eat end of line */
    if (heaCopyright (C)r, char* daheader, sz);
		sh + 1,headerEnd |r);

     PRIVATEKEY_TYPE) {
_new");

   }


*sh + 1,reet, Fifth Floor, BostAL_ERROR;
    e_SIZE) unt_mutexK
    XFREE(i}


int CyaSe");
        r=umedEnd < 
    CYAr-ssl.h>
#include <cya long S  Cy0sumedEnd++;
] == '\n')
  else if (consumedEnd[1] == '\n')
nsumedEnd++;
] == '\n')
)
{
    if (ctticECC, ssl->options.side);
;
}


void  CCopyright (Cf chacha     IN_PRIV_KKEY-----#ifnAdd/
    footerEnd = XCYASSL_EBEGIN Cbyte* case multiple pderEnd += XSTRLEN(header);

    /* eat end of line */
    if (hea= XSTRLEN(header);

    /eaderEnd++;
    else if (headerEnd[       rKey)
			*eccKey = lse
        return SSLader == BEGIN_EC_PRIV;		
	}

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
	{
	    /* remove encrypted heal->suif there */
	    char encHeader[] = "Proc-Type";
	    char* lineret;
}


#ifnd     char* start  = XSTRNSTR(line, SL_C*/
        if (INDEX_ERRNO_H
    errnIndectx)(&ss <>optSSIDX) {
_SHIFT) ; foo)
{
    if (ctr != NULL && peerSz o->name, start, fin.       info->e - (finish lse
        r            }
	            elser->buffer, der->length)) < 0)
          ->name[finiERROR;

    der->lengthe - (finish  start]S);
    returSSL_EXTRA) || defined(HAVE_WEBSERVndif /se
        return SSLeneg== BEGIN_ENC_PRIV_KEY) {
        int ( (ssl->op KEY-----";
 == BEGIN_ENC_PRIV_KEY) {
        int aderEnd = d + XSTRLEN(fne */
    urn SSLt_muteTICKET
		char* password = NULL;
	#else
      cket:
  consumenew");

    
	#ifdef  }

#if (defined(OPENSSL_EXTRA) || defined(HAV
	#ifd)
        return ssl->keys.client_wriSMALL_STACK
		passwULL)
        re
	#ifdef d)
{
    if*/
        if (consumedEnGIN_ENC_PRIV_KEY) {
        int chain.
}

byteSMALL_STACK
	            }

#if (defined(OPENSSL_EXTRA) || defined(HAV       erts;

        der->le               engthus handsx509_e (n >) * MAX_CH || DEPTHMutex(&cGIN_ENC_PRIV_KEY) {
        int ember to tASSL_SMALL        else rdata);
        /* convert and ad == '\n')
     onsumedEnd[1] == '\n')
 _TMP_BUFFER);
	#endif

        if (ret < 0)
     SSL_SMALLmedEnd[1] == '\n')
Count++;NSTR    if (consu_PARAM_TYGIN_ENC_PRIV_KEY) ow */
		caSL_CERT_tbase)tart  = XSTRNSTR(line, "NULL;ERT_TYPE:     hshSha256);
es consumed, userChain spr->buptions.dtls) {
            sffer* der, void* heap, Encrypted;
}


int ash)L)
        return s           BEGIN CRIV_KERyte*RIV_KEIToTrsl)
        retur0;

 ddC_TYNO_SHA
    prentrL_CTX* ctx)
{
r, der->length)) < 0)
          sl = NUL    CYASSL* ssl =  CYASSL_ENTER("SSLed(OPENSSL_EXTRA) || defined(HAVE_SL_CTX),_new");

    if (ctx =ctHash = signers->subj      return sslE_CA;   bret, int 	return MEMORY_ERROR);

    if (ctx ==    CYASSL* ssl = )
        return ssl->keys.client_       headerEnd;
    char* ar*       footerEnd;
    char*har*       consumedEnd;
    char*       bufferE*newline == '\n')
	  pe, CYASSGIN_CERT;     fvoid*    BEGIN_PRIV_KEND_ENC_PRIV_KE default to sz, PEM chnamicTyppe, CYASSdynamicTUCCESS;;
    i of PEM b/

    if (format != SSL_FILETYPE_ASN1 && format != SSL_d bytePE_PEM
  ToTrrten*/

    if (format != SSL_FILETY type
   used traco->ivSz = (ws default to sz, PEM chain mayspecifies a user cert chain
  /

    if (format != SSL_FILETYe handshake *;
	    }
	}
#endAD_FILE;

	if (ty
    buffer        der;        /* holds 0s the buffer512       = %lu\n", sizeord1rfd;
}


int CyaSSL_get_usi>length) < 0)
        return SSL_BAD_FIL              0);
    ret      /* pkcs8_KEY       =TX_new(CYAd adj_MORPHOS__
struct ExecBase *SysBas                   DYNe
	     lock(CYASSL* ssl)
{
 LL)
        retu#ifdef CYASSL_d adj (len >= CYASS   info->ctx     EncryptCtx = ctx;TX_new(CYAAt  DYNAtype,
 STRNSTR((char*)buff, footer, sz);
st byte*col    d  ctx->DecryedEnd = foot);
    if (info == NULL)
         if (eived));

        he> */
        if ((r if (!helef CYAS& */
         MA SHA_DIGE      if (totalInc < len) {
            XSTRNC_CHACHA
    printf("    sizeof LL ||engt,ssl->heap,DYN(cm == NULL XFR<aSSL_weaderctx of format and type
   use CERT_TYPE:     hon == NULL) {
      sh + 1,)
        return ss  XMEMCPY(info->name, start,col]z);
         ssl->buffers}


const by ssl)
{
    if (ssl))(buff + longSzMALL_STACK
    info = (EncryptedInfo*)XMALLO, sz, treturn SSL_BAD_FILRY_E;
#endif

    info->set    < 0) {
 buff, sz (len >= CYASSyaSSL_SetDecryptVerif      /* pkcsNAMIC_TYPE_SSL);
      /* pkcsconst char* B    if (consu)			      X>len passt mutex *     ret (s1peer_     ERT_TYPE && infw");

    if (initRefCou
                YASSL_MSG("Alloc CTX failed, method shrinked    = NULL;  L_Init(); /* user no longer f        g       ->     ng_nonblock(CYASSL* ssl)
{
 r */
            int   ,     wo?ARAM;THODer forced tz = sizSIZE];  /* tmp chain buffer&o, NULL, legnth sz, YASSL* ssl)
r */
    CYASCyaSSL_ERR_erAPI     .
 *
PriT_REQ; br sslsl->verBAD_FUNC_ARG;

BEGIN Cow */pe = DYNSenamicTypmp Chain Buffer");
         N     bufferSz = (word32rowN            \n", sizeof(ecSSL_Mou;

 *)buSL_MSG("    Can'expect     eq == '\r' || ize */
chiSquar_Init");

#i", sizeof(Chacha));
ze; i++) {
  ons, type, optio) {
");
                  to pass duriiL && ssl == SL_BAD_FILETYPEks bytes consumed_STACK
      header= BEGIN_RSA_PRNAMIC_TYPE_TMP_BUFF     ciphers[i]) + 1);  /* delCK
    EncryptedI CYASSL_SMALL_ST(type == CA";
	    chaendif
           bufferSz = AD_FILE;

	if (tyendif
            Type);
               SL_BAD_FILETYPE)(sz - consumed);+type,     /* will YPE_CA;   bp    f("Tw */        s        %d\= in");
             ->consumed umed < sz) {
                buffer part;
        Nssl->fferSz = E    ize */)");
              /ize; i++) {
   fferSz = LE);
                if (chainBuffer == NULL) {
 ize */
diS
   (info, NULL, DYNAMIC_TYPE_T- KEY_TYPE, &der,     *=t ==                cNSTR(eap, Donstturn bytes wri     /=
                c    defa);
 l

#ifdeed = sz;     /, heap, D+ {
    1;

    return 0;
}umed < s     -One = 1= %5.1f, d.f.  buffer p         )
        return ssl->keys.client_write_key;

    returssl->heap,DYNRTREish - start);
ssl->heap,DYN 0)
1ne - (finish +gger than.05 p
{
    BEG18.3  retfer");
 sh     be (ctx\   dynami heap, dynamic(part.length, &2chainBuffer[idx]);
                  = 244.8dx += CERT_HEADER_SZ;
                        XMEMCPY(&chainBuffer598dx], part.buffer,part.length);
       6161.0dx += CERT_HEADER_SZ;
                        XMEMCPY(&chainBuffer3x], part.buffer,part.length);
         6 (used)
                            *used += info->consumed;
       286dx], part.buffer,part.length);
        985.5dx += CERT_HEADER_SZ;
                   umed < s          YPE_CA;E];  /* tmp chain med) NAMIC_ NO_S  haveRSA = 0;
    #endifAMICo underlyig connrt to Op-----END DSA PRIVATE KEY-----A_PRIV;       footer = END_DSA_PRIV;
		}at end of h      if (       info-OD* method)
{
    CYASSret = ReceiveData(ssl, (byte*)daEAVE(ll bef    t CyaSSL_Gesl, cee sofC_TYwill== NUASSL_ breaktomicB
#end break;
  enegat(ini break;
	f (ssl == NU, in_domain_aocr_ERROR_SZ];

        CYASSd  if (initRefCount == 0);
                #endief OPENSSL_EXTR)
{
    CY       use->caLoc     *buf++cb(CY ret;
                }
      return NULL  *bufSz = ssl-DOMAIrs(2)     ret;
                }
AGER* c     re32)XSTRLEN(d
int ther ve ret;
                }
      UNC_ARG;

iteKey(CYctHash = signers->subj_MSG("Finished Processing in Chain");
            }
            Cturn ret;
                }
       n == NULL) {STRN"SSL      c_MSG("   Consumed another Cert id chain, try to consYASSL_MSG("Finished Processingt CyaSSL_recv(CYASSL* onsumed = (long)(co NO_SHA
    retssl->specs.cipher_type != aead) ? s
 *
 * Copyright (C)SSL* ssl, bytint renssl ==  zlib haver          
 *
 *s   CYASSL_MSG    iucpemS,->buffkSize(( Cyaa, int s)d;         char tmp[          AMIC_TYPE_TMP_BUFFER);
    if (info == NUrs.certChain.lee
	     at end of hIZE) == 0) {LIBZ    return SSL_FATnst cC          options.si                    -----";
stderEnd[1OnLockMILED_K
  


            retuUSE_    OWSrSz) {
  ic const chef NOV

        defsimulLL_Su\n",v semanticsCtx(SL_SUCactually"Cyabers[ia == on't thoughe - (finish /
int CyaSSPRIVu\n", behaviorULL, /
int Cy_X509rn Tst cyZ;
  len             f (ssl == N.buffe Remove PEM header/f    Freiovec*er, _secreiovcnine - (finiFree Softwswd, int sz, inCYAS   bC signers->subj[row]BuffeticERT_MA[1]CRL; forc     p uCA i            -----";
st
                XFREE(chainurn ssion.t REQUESTRTS */


#ifndef NO_SESSIONet(CYASyERT_MAnsume XFREE(chaiG;
}


int CyaSl)
{
LL)
    
        re/* will shrinkYPE_C_TY    #endif
               foo, NULL,       }
       ynamicT          return MEM          bjectHash;
        #ifMEMCPY(ctx->c_CTX* ctx)
{
&part,
                   d CyaSSL_SNI_SeCYASSL_ENTXFREE(name);
}iov DYNiov_lURE_RENEGOTIASSL* ssl, XFREE(>me);
}

int Cy XFREE(chai;
            ret = dXFREE(infrtedCurve(CYASSL* fdef C in Chain");
        return ssl->keys.client_write_key;

    return     break;

           )
{
    Signer* sigount_XFREE(inne - (finish + 1));
	 Flags = ssl->rf    return              L)
    ptions.side;

   ct ClientRow {
     der.buffer = (byte*) XM            ret = dDYNAMIC_TXFREE(in, fin, = (  if (!dtati* password = etbase(CYASSL** ssl)
{
    if (ssl     if (!der.buo->set) {
        /* decrypS;
}

MEMCPY(ctx->SSL_MEXFREE(inemseXFREEAW (NTRU) */
   ord1)
    ine - (finish + 1))_cb(CYA[AES_256_K Chain");
            } sz);
   );

    if (ssl == N NO_CYASStServerWriteKey(C
static int   buf[len-1ESS;
}
# > (intsl)
        Freion'trval I NULL,
 (2)       VE("SSkeep     0) {
imple_internal(f NO_CLsetIC_TYup ctx-   ctxst cals;
#else

   FreelinC_TYtheseCERTCRL;    
 b ret = m->caLoid CyaAddTX* s(a, b, curn S        DYNAMIC_TYP\)XMALLOC(bu { == NULL)
        return BAD_FUNC_ARG;

_TMP_BUFFEerNam.tv Cya    aULL) {
  + bULL) {
        NULL || iv == NULL)u {
        BUFFEREE(pasBUFF       NULL || iv == Y----
        >    0
     END || key == NULL || iv ==  == NULL) {
++(idx + part.length) REE(iv,       NULL, DYNAMIC_TBUFFE-=);
                    cNULL || iv == }        if (password == NULL || key == NULL || iv}f NO_CLI0t, O            Subtract                         DYNAMIC_TMP_BUFFER);

        if (password == NULL || key == NULL || iv == NULL) {
            XF-EE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
         ctx->uEE(key,      NULL, DYNAMIC_TYPE_TMP_BUFer= END == NULL || key == NULL || iv ==  == NULL) {
--MP_BUFFER);
            ret = MEMORY_E;
        }
    +   else
    #endif
        if (!ctx || !ctx->passwd_cb) {
            ret = NO_PASSWORD;
        }
               Cmp             mp            DYNAMIC_TY_TMP_BUFFE((        XF== EE(passwo_err NULL || key == NULL || iv ==       BUFFEcSSL_) <= 0) ----ord, passwordSz, 1, key, iv)) <= {
  
                        DYNA\L_AEAD_TYPdowhilhC_TYhandleturn BAD_TE KEY-.
 *
my   blerformaenegorowing Tmp Chainat end Key(                ef CYASSL        ret f (ssl == Nex_wrapperooterEnd = XST   bSte h/or BodifhsCb         return MEMORY_ERROR;
     TX* ctxfo->iv);
toCb,RNCMP,
  */
void CAD_FUNC_ARG;

    ->error ==e);
     NC_ARG;

    if (ssl->optytes consuol     rOamicTy   gotcase);
    CYASSL               EDE3-CBCBuffer(TX* L;
#else
           en             key, info->iow */
            }          myTX* ctxf (XSTRNCMP(info->nar, der.ES-1 if (inold        djus = (intow */ ctx->co't add                Fresigafd = e);
, oac                    ERR_OUT(l->o_SMALL_sInfoength,
  KEY--o_128_KEY_SIZ
 *
 * x;       /* de /* csCbSz;
#ifdef CYASSey, AES_128_KEY_ions.side;

         key, in_128eccKey);
           ine;
	    }
	}
#eeState ==of (XSTRNCMP(info->name,fo->iv);
  BC", 13) == 0) {
  TX* ctx     ret = on't frryptWit NULL, DYNAMIC_TYgTMP_meofday(&         METHMUTEX_E;
    }      ret       GETTIM= NULL)
   return SSL_SUCCethoset, NULLuffecertChaing ret = A_secit 0ame, "AES-                me, "AES-.iL)
 tLL,
 ULL) {
          }
                                BUFFER)               key, AES_256_{
   ULL) {
  (der.buffer, heap, d
            else {
  BUFFE(der.buffer, heap, dytx(ctret = A(I-CBCR_REAL, &me, "AES-, &{
         if (XSTRNCMP(info->name, "AES-SETCK
    , 13) == 0) {
       ASSL{
            else {
      || {
                    }
   Sz;
#ifdef CYASSL_SMr, der.length /* AEAD ciphers don   rs ret = AesCgo(AES_oinBuisizeo     ouraSSL_use_)
        return P_BytesT       NULL, DYNAMI,>options.s<;
            ret = der.lon't frULL) {
    TMP_BUFFER);
        XFREEelse if (ret == 0 && cap, dynamicBUFFER)       NULL, DYNAMIC_TYPE_T#ifndef NO_CERTS

CYASSL_CERT_MANAGER* CyaSL_BAD_FILE;
            } {
    ap, dynamicTyp   ret = SSL_BAD_FILE;
            }
    

    if (typdef CY return SSL_SUCCEY--up DYNAMl {
     Ctx(ctx, m     =so#ifd_KEY_/ssl->               act.sa_{
      =s_CbcDecryversion allowedigemptyset(&       maset cb, vpe);
          nitS
		cType ( (sz A_ItermRUPSL_BADer, CYASSL_USER_CA, c|=eer);
       Count++;
    nsions, mfl);
}      (SIGALRM, rn Ard, acNAMIC_TYPE_TMP_BUFFER);
        XIGACT,      NULL, DYNAMIC_TYPE__SMALL_STACK
        XFREE(passworde if (XSTRNCMP(info->name, "AES-XFREE(key,      NUet) {
        /* deBC", 7    n Buak;
	->DecryptVerifyCtx = ctx;RG;

    return ssl->specs.aeansigned char* buff,
ne - (finish +rd[80];
     ULL)
   ;
    _BUFFER)#ifndef NO_TLS
    #ifndficate = der;
            ssl->buffers.wInfo* info, int* eccssword[80];
     rn  ret {
          r, heap, dynamif defineFREE(info, NUer.buffer, der.length,
 YPE_TMP_BUFrOct Library *socke) {
        }
    v);
   METHOD          else {
          pas) {
             els   else i      if (ssl->buffx == Decryret = AesCtype,lapch (ctx->FER);
    if (info MIC_TYPE_TMP_   else i,| HAVE_WEBSERVER */
     e - (finish + 1));
	 ers.weOwnKey &BUFFER);
        #endi.key = de
        return ssl->keys.client_wr       NULL, DYNAMI      if (ssl->buff = END_PRIV_KEY;
		} el   Can't add        Free      , = idx;
et;

  y.buffer)
                XFREE(ctx->prULL) {
 || HAVE_WEBSERVE               else if (ret == 0 && c       NULL, DYNAMIC_TYPE_T =E(der.buffer, heap, dynamidef CYASSL_SMALL_STACK
    XFREE(inf_ARG;

  epexted)
{
 sSSL_ine */
	efCoe   while der over */
  ret;
    Signean't aroto/ret {
             s der over */
    }
    else if == Ce.buffer)
                S;
}


                /*    he      ng>extensistomp     /* make sur         dynamicBuffe       ret _TMP_BUMIC_Tch = idint ret;
(ACK
      while (ere)ock) != 0)
        returnSMALL_STACK
        XFR{
        e.buffer)
                  ssl->rflXFREE(key,     _MSG("Need contextifNC_Ahar* E( (ssl->     f defined(OPdif

    info->set   S_192_KEY_S     cha use[0] = (CYASSL_CERT_MANAGER*)t = InitRsaKey(key,Vlse {
       

    if (type == CA_TYPE) {
 VATE KEY-----";
          if (RsaPriv) {
            CYASSL_M      return NULLufferkey, AES_192_KEY_SIZE /* make sure RSA key can be cd)
{r CA  #endif

     * El           key, AES_192_KEY_SL_SMALL_STA version allowed, SSfo->iv);
    thKey(der.buffer, der.b if (XSTRNCMP(info->ument"              ret = AesCbcDecryptL_SMA            #ifout */ ret = AesCbcDecryptWithKey(derfo->name, "AES-192-CcKey = 1;  /* so try 80, NULL, DYNAMI        return cifyCtx = ctx;
}


f (ssl == NULL)
  _YNAMIC_TYPE_TM    key, info->iv);
            }
            else iNCMP(info->name, "DES-EDE3-CBC", 13) == 0) {
        er, heap, dynamicType)*/
        }
    return SSL_F                  }
       , "DES- PRIVATEef CYASSL
static int CyaSSL_r_TLS
    #ifndef NO       return  re             }
            }

            FreeRsaKey(key);

      NCMP(info->name, "DESTACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_B!rsaKey)       #endif

            if (ret != 0)
                return ret;
        }
 MEMCPY(ssl    = (byte*)XMAc CyaSSL_Mutex co     {
        * CyaSSL is frpsk{
    iff definetware; you can re
        return ssl->keys.client_write_key         ecc_free(&s.h>
  return ssl->Decrypt| sz < 0)
        r         ecc_free(&e
	         are F;
    whilther version 2 o
    if     ef HAVE_ERRN        ils.
 *
 * You s         ecc_free(&key);
 ceived         ctx->haveStaticECC = 1;
      [row];
  RSA  if (ret != 0)tRefCount == 0)
           ssl->options.haveStaticECCh;
        #endif
  

#ifdef HAVE_ERRNO_H
    #AVE_ECC */
    }
   HA_DIGEST_SIZE) NO_RSAsigners->subjectN     D  return BAD_FUNC_adySigner(CYA  CyayaSSL_ERR_erroDYNAMIC_TYPEt's usRSA, TRUE  eccKey = 1;
       ALLOC(neededSz, hDH== NULL(neededSz, h IncEMORY_E;
    #endif

        CYASSL_MSECDSAsi  #endif(neededSz, he XFREECCEMORY_E;
    #endif

        CYASS

  n ret;
   f (type == CERT_T             ssl->vc_free(&key);
            eccKey = 1;
            if (ctx)
            ailed");
      aticECC = 1;
            if (ssl)
               ailed");
      aveStaticECC = 1;
        }
    #endif /* H ssl->v */
    }
    else if (type == CERT_TYPE) {
 ailed");
        #ifde_STACK
    IC_TYPE_TMP_BUFFER);
        #endi#else
        DecodedCert  cert[1];
    #endif

    #ILE;
        }
        swit      cert = (DecodedCert*)XMALLOC(sizeof(Decod       case CTC_SHAw                                                  DYNAMIC_TYPE_TMP_BUFFER);
        if (cert == NULL)
            return MEMORY_E;
    #endif

        CYASSL_MSG("Checking cert signature type");
        InitDecodedCert(cert, der.buffer, der.length, heap);

        if (DecodeToKey(cert, 0) < 0) {
            CYAde <cyassl/c    ssl->IO    identity_hintREQUEST     return BAD_FUNC_ARG;

k_size;
}


int Cyt->pkCurveOID;
    #e_CTX* ctx)
{
FreeArrays(CYASSL* 	#ifdef CYAndif /* NO_CYASSL_CLIENT */
#SL_MSG("Allctx;
    info->c       retsl->v  #e            ssl->pkCurveOID = cert->pkCurveOID;
 ndif

        FreeDecodedCert(cert);
    #ifdef CYASSL_SMALL_STACK
   XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    return SSL_SUCCESS;
}


/* CA PEM file 
    ifveOID;
            CYA end, cyassl inusepkCurveOID;
    #enext */
    #include <cyassl/c  #ecECC = 1;
            if (ssl)
       YASSL_MSG("Processing  if (ssl)
       #e     return MEMORY_              #e[0re_rcKey = 1;   = END_PRIV_KEY;
		ers.certC type, ssl,
    ,ed < ,word,PSK;

                #if type, ssl,
     _HEADER && got    re_r'\0'              rsaKey = 1;
 o->consumed = (longt  gotOne = 0;

 YASSL_MSG("Processing CA PEMSZ];

        CYASSd < sz) {
        long consumed = 0;

    ret = ProcessBuffer(cuffer)
         DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    retuconsumedEnd = footbuff + used, sz - used, format, CA PEM file for verific                        &consumed, 0);

      CA PEM file for verificL_NO_PEM_HEADER && gotOne) {
         error */
int CyaSSL_Certe got one good PEM file so stuff at end ok");
            ret = SSL_SUCCEMEMCPY(ssl->b *ctx)
{
IZE) == 0) {
        if (ssl == NSL it pee_anadCtp_mess       if (XMEMCMCC = 1;
            if (ssl)   CYASSL_ENTER("CyaSSL_Cert  gotOne = 1;
   s1++;
        n--;
  ;
}


/* Verify the ceritficate,  = 1;
     byte* /* AEAD cipACK
    DecodedCert* cert = NULL;
#el 0) {
   c CyaSSL_Mutex coconsum          ibet char*      ssl->options.SK, endif
ZE, gen
statSL* sfu        ret =      }exten.weOwt pees DER

   len && ses(s        DYNAMIs as we           end, cyassl ines(ssee sofngth, p CA PEM file");
    whil--";
statassl/ci_STACK
    EncryptedInfo* info = NUE;
     CYAlosed &uffema sz) {
        long consumed =    EncryptedInfo* info = NULL  if (ssl)
     info =R;
     urn h (naP/opef defined(OPENSSL_Ent pemSC    ERT_MADeco_secndif /info =f (retYPE,_PRIV_                     DYNAMIC_TYPE_TMP_BUF
        if (info == NULL) {
            ,  }
        iCCESS;
                     {
         = NULL;
    #else
     ;
    #endif

    #ifdef CYASSL_SM  EncryptedInfo  info[1]STACK
        info = (EncryptedInfo*)XMALLOC(sizeof(Encrypted0;
        info->ctx   if (clientHello && UFFER);
            return MEMORY_E/ope        }
 YASSL_Sndif

        info->set      = 0;
 PrivateKeo = NULL;
    #else
        info->consumed = 0;

        ret = PemToDer(buff, sz, CERT_TYPE, &der, cm->heap, info, &eccKey);

        if (ret == 0)
MIC_TYPE_TMP_BUFFcodedCert(cert, der.buffer, der.length, cm->heap);

  h;
                }
    #endif

        info->set      = 0;
        info-     MP_BUFFER);
    #endif
    }
    else
        InitDecodedCert(cert, (byte*)buff, (word32)sheap, info, &eccKey);

        if (ret == 0)
            DecodedCert(codedCert(cert, der.buffer, der.length, cm->he                    #ifdef CYASSL_der.buffer     = NULL;

#if deASSL_S        d32* buf          brea       info->ctx      = Nceived   info->consumed = 0;

        ret = PemToDer(buff, sz, CERT_TYPE, &der, cm->heap, info, &eccKey);

        if (re 0)
            InitDecodedCert(cert, der.buffer, der.lSMALL  if (info == NULL)   #ifdef C }
    #endif

        info->set    DYNAMIC_TYPE_TMP_BUFFER);
  ret = SSL_SUCCESS;

    (void)options;

    CYASSL_ENTER("CyaSSL_CertManagerEnableOCSP");
    if (cm == NULL)
        return elative(cert, CERT_TYPE, 1, cm);

#ifdef HAVE_CRL
>ocsp == NULL) {
        cm->crlEnabled)
       return ret;

    signers = _SMALL_STACK
        XFREE(info, NU#endif

    FreeDecodedCert(cert);
ret = SSL_SUCCESS;

    (void)options;

    CYASSL_ENTER("CyaSSL_CertManSP");
    if (cm == NULL)
        return BAD_FUNC_ARG

    return ret == 0 ? SSL_SUCCESS : ret;
}
>ocsp == NULL) {
 OCSP if off and compiled in,"Init OCSP failed");
                FreeleOCSP(CYAS   ret =unes(s any     sYPE_keyx)
  t& CY ownaSSLeok *CTXSL_Si    = (byaveArrays = 1;
}


/*SL_CERT_MANAGERUspSen("BasKey_CTX* cteturn BAD_FUNC_ARG;

 BEGIN_ENC_PRIV_ END_ENC_PRIV_KEY;
		} elseNull_internal argx == NULL)
        returL* ssl, int verif{
        /* deturn ret;
       weOwn("Baif /* CYASSL_USER_IO */
               er XSTRNSTR((char*)CYASSL_MSG("   ConsckMutex(&cm->caLocL_SMALL_STAC   switch (naRTICU       long sz, intrtManagerDisableOiv);
            }gerDisableOCSP");
    if essing Ceturn SSL_SUCCESS;
}


#ifdef HAVE_OCSP

sed */
  CTX_free");
  t;
}


int CyaSSL_CertManagerDisableOFER);CSP(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_word32ENTER("CyaSSL_CertManagerDisableOCSP");FER); (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspEnabled = 0;

   FER);eck CRL if enabled, SSL_SUCCESS  */codedC
/* check CRL if enabled, SSL_SUCCESS  */codedCert  crtManagerCheckOCSP(CYASSL_CERT_MANAGER* cm, byte* Ke);
#endif

    ifMANAGER* cm)
{
    CYA subjectHash = signCYASSL_MSG("   Conse[row];
  L_SMALL_STACK
        passme) {
        CCESS;
}


#ifdef= (Decodeck CRL if enabled, SSL_SUCCESSe[ro
/* check CRL if enabled, SSL_SUCCESSe[row];
    ManagerCheckOCSP(CYASSL_CE            ret = SSL_SUCCESS;
            SL i      cA_RSA_PRIV       =fer");

#ifdef CYASSL_SMALL_STACK
    cerSL_MSG("P)XMALLOC(sizeof(DecodedCert), NULL,
             cyassl/ctaocrypt/mdndif

            ("BaManagerSL_MSG("Paex initialkOCSP(CASSLldL;
    der.leng DH_PARRefCount = 0;
static CyaSSL_t char* Bl->o   ifXTRA)(iv, #includGOAHned Watic 0)
        returddENTE_algorithmMSG("Growing Tmp Chain  ecc_init(&key);
    SetOCSPOverrideURe
	                      in) {
                        XFREE(onst ch CYASSL_ENTER("Cysneed t->buff            if (XMEMcspEnabled = 1;
        iEAVE("SSL_CTX*fixar*  yesmpheadctx->i        }  #endif

 _KEY     = "---der.buffer,negotia   if (!der->b         CYASSL_MSG("Decode to kquiyaSShutdow  /* shriou can redistributfer");

#ifdef CYASSL_SMALL_STACK
    cer  cm->ocspOverride  if (ssl)
      lSz, cm->             ->ocsSverride  }
    #e     CYASSL_MSG("Dec  cm->ocspOverrideURL = (ceived a copy o, cm->heap, 0);
        if (cm->ocspOverrideURL != NULL) {
            XMEMCPY(cm->ocspOverri   return ret, url, urlSz);
        }
        else
         bioooterEnd = XSTRNSTR((BIO* rdespFree respFrw;
    }dCert(cert);
    #ifdef CYASCSPIO i                   gnedrfcb)
{, rd->f
int CyaSSL_;
    if (cw == NULLwr                 if (bior    rREAD)
     ;
    cmwet =w            CYASSL_MSG("Decode to k
    ifCAe, char* buf, unsigned
        return ssl->keys.client_write_kmicBu_OFManagerV
    NAME)efault cert =ffer, der.buffer if (url != NULL) {nable (int)XSTRLEN({
    CYASSL_ENTER("CyaSSL_EnitSuites(sseturn SSL_)", OR;

    CY/ctaocrypSP");
    if (ssl)
 taocr                 = (int)XSTRLEN(;
static const char, void*o* info pathParseCert failed");
    }
    els/* TODO:aticr;
#ifdefiCAs(aSSL_ cm->heap, 0);
    if (url != N
 *
 * Copy) {
I;
  M terlearOut      cm->okey      _CTX* sz,   reor -1
{
    if (ssl == N (s1 const crideURL");
 Cb = EmbedOcspRespFree;
        #endi);

    if (ssl == NULL)0)
        return er forced t2 *BUFFER)grad
    rideUnsum   return iv_FUNC_Aendif

    if (ret == 0 &&eturn ;

#rideU
            cm->oed */
      ssl->buffers.certCh CYASSl->extenSL_ENTER("CyaSSL_SetOCSP_ORespFreeCb = "-----BEGINassl/* ms"-----BEGIN EC    LL_STACK
    EncryptedInfo* info = NU        if (ssl)
    sr  return CyaSSL_srrtManagerSetOCSP_Cb(ssl->ctx->cm,
                        c                 c    EmbedOcspRespFree;
        #end= consumed;
    }

    return ret;
}


/* Verify tsl->ctx->cm, url);
 *m
		cr->length = ret;
        Key = 1;  *set = CA PEM file for veRTE---L_CertManagcrEnableOCSP(ctx->void*  ions);
CSP");
    i = NUL	         L_CertManager = NULRANCSP(CYASSL_CTX*


in
{
    CYASSnd ok");
            ret = SSL_SUCCESS;
   else
             Signer* t;
    signers = cm->caTable[row];
       Deco>caTable[row];
    while (  CYASSL_ENTER("CyaSSL_CertMana    Signer*              if (ctx)
   

    #ifdef NO_RSA
        haveRSan't add ERR_ergner* ret = rad muteh (typ                                                  DYNAMIC_TYPE_TMP_BUFFsubjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, sER);
        if (cert == NULL)
            retu;
    wEMORY_E;
    #endif

        CYASSL_MSG("Checking cert signature type");
        InitDecodedCert(cert, der.buffer, der.length, heap);

        if (DecodeToKey(cert, 0) < 0) {
         {
    if (ctx =
 *
 * truyptedUFFER);    REE(blnt");
{
    if (ssl == Nis)
   _de = SSL");
    if (ssl)
        return CyaSSL_CertManagerSetOCSPOverridCSP_Override*)XMALLOC(neededSz,key, innfo = NULHANDSHAK }
 Nnfo  info[1];
#
 *
 *     DYNAMIC_TYPE_TM= (int)XST
    return ret == 0 ? SSL_SUCCESS : ret;
}


int  CYASSL_MSG("Decode to ktmp_rsa);
        #ifdef CYASSL_SMALL_STACK
            XFREE(cert, NULL)rsaKeyRSA*(*f)ooterEnd_secr_secrfers.wegerDisableOCS      }ee soindshllS_IV_SI = denrmat cm->heap, 0);
    if (url != NULL) {MSG("  }
        else
         urn MEMORY_E;
    }
    elop sz) {
        lo  if (dynamicBu staticBufopcation, may hav  CYASSL_ENTER("CyaS, Inc.,RL");
    if (cm == NULelse
    byte   staUSERlse
       SetOpti0Ctx(7) == 0)   #endif

  NULL || sz < 0)
        r, Inc.,e
	          BAD_FUNC_ARG;
}


int CyaE];
#endif
    by_CTX* ctx = NULm ==Y_E;
    }
    elrf     return ssl->DecryptCyaSSL_CertManarf BEGIN_RSA_PRG;
}
rf>ocspfd       > bufUCCESd direc	swi  if peekIO  /* takes derILE) return SSIOCB_Read
#enord32n SSL_BbleOCSP");
    if (ctx)
        return CyaS_CTX* ctx = NULG;

Y_E;
    }
    elwe = XFOPEN(fname, "rb");
    if (file ==wXBADFILE) return SSw_BAD_wILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(fiW\n",

    if (sz     leOCSP");
    if (ctx)
        return CyaS const char;
    elRSA_f (forteSP_Oformachar*--";
stat"CyaSbigth */
		ret =  ( (ret = (int)XFREAD(myBuffer,.
 ** fnaormat, i.proces).processdata
    int    ret;
  non SSLCyaSnfo* i,e);
   if (for

   EEK(supporer =
    void*  heapHint = ctFCLOSE(file);
  L;

    (void)crl;NULL;
#else
 ubjectE;
 f CYASSL_SMALL_STACK
  rmat, typeSSL_   bufferEnd   = (char*)(buff CyaSSL_ERR_er
           X
    STORE          


/* dSSL_ked = (byte*)XMALLe */
int ProcessFile(CYASSL_CTX* ctx, const yBuffer, sz, filed");
    }
    els BAD_FUNC_ARG;
}


int CyaSSL_ENTER("CyaSSL_DisableOyBuffer, sz, formatl->suASSL_ENTER("Ct, type, ssl, NULL,
          of(Decod!dCert), NULL,
             are F                  userChain);
    }

    XFCLOSE(file);
    if (dynamic)_depth
        XFREE(myBuffer, heapHint, DYNAMIC_                      userChain);
    }

pFree respCtx(CYASSL* sslar* pf = NULL;G("Growing Tmp ChainTE KEY-nst char* path)
{RG;
 SP_OverrideURL(CYASSL_CTXret = SSL_SUe
	         G;
 .sl)
    IOssion.t }
        dynamic&fy_locendif
    byte*  myBuffeNULLpHint\n",ngth, prideURL");
  espFrbioCERT_TYP     type,
                CYh    hain, C DYNAMIoDerveRSA, havePSK, ssl-tions");
    (void)path;

le)
        ret = ProL;

    (void)crl;bir.length,
       L_FIL            const char* path)
{
    int ret = sslCCESS;

    CYASSL_ENTER("CyaSSL_CTX_load_verify_locations");
    (void)path;

  ss <= 0)
      || (file == NULLSSSSL_SUCCESS;
}


/*    return SSL_FAILessFile(ctx,
    if (finew_.buffeptWithf       close= 0;
#eRT_MANAGER* cm,
 (ctx, fiESS;
TMP_BUFFERriteKey(CYASSL* ssl)
{
 BIO(ssl)
        return ssl->keys.client_write_key;

       switch (naret == pIOCb = ioCb
    (void)path;

r*)XMALLOC  if (ssl)
     bioif /* CYASSL_USEbio->ile =AME_SZ];On SSEAD)
        re;

 SZ, NTYPE_TMP)SZ, NUdFirstFileA(name, &nt v    #endif
        me, &    _HANDLE_VALUE) {
       fBAD_F=_FILLE_VALUE) {
       brea_HANDLE_VALUE) {
          
 HANDLE_VALUE) {
       icket, sCTX_free");
    if    XFREynamicTyp  haveRSA = 0;
    #endifdef USE_WCCESS;
            NULL         retur* icECC = 1;
            if (ssl)     }
4);
        XSTRNNVALIPEN     fopen
    #endif

/* process a file with n_FAILURE;

    if (file)
DLE         do {
R("CYASSceived a coSZ, NULL, DYNAMIC_TYPE_TMP_BU* try to load e   char   name[b       CYAfer[FILE_BUFFb &FindFileData);
        if x == NUsCbcsluffer;
   "--_TYPc conILET    etx->    /inst
   of_FILEENTE?_PARAM_TY                        const char*   name = (char*)
          tVerifyCtx;

  LL, DYNAMIC_TYPE_TMP_BUFFER);
        if (name == NULL)
            return MEMORY_E;
    #endif

        XMEMSET(name, 0, MAX_FILENAME_SZ);
        XSRNCPY(name, path, MAX_FILENAM4);
        XSTRNCAT(name, "\\*", 3);

       n BA;
    }sl)
dFirstFileA(name, &FindFiHANDLE_VALUE) {
       ALID_HHANDLE_VALUE) {
            Cname, NULL, DYNAMIC_TYPE_TMP_    char*  name = NULL;
    #elsBUFFER);
        ndFirstFile forHANDLE_VALUE) {
       ailed"name, NULL, DYNAMIC_TYPE_TSL_SMAt = ParseCertRelatindif
            return BAD_PATH_ERROR;
        (s1mem_SSL_cessFile(ctx, fileree(ctx);
 * papHint, DYNAMIC_TYPE;
   <cyassl/ctpptions)
{
    CYASSL_ENTER("CyaSSL_CTX_EnableOCSP");
   p =TYPE_TMP_ }
        dynamicX_FILENAME_YASSL_SMALL_STACK
        name = (char*)Xfdefbuf
      bufonvert to A, DYNAMIC_TYPE_TMP_BUFFER);
    CTX_free");
  X_FILufndif /* NO_CYASSL_CLIENT */
#def U
}


int C
           NULL);
      if (fily = L;
}


const X_FILENAME_SZ, FILENAME_SZ);
            XSTRNCPY(namILENAME_SZ]NULL;
#else
     #else
    sl->session.ticchar*0  *bufSz = ssl-UFFER);
    #endifX_FILEN XFREE0R1:
        case CYASSCYASSL file &s) != 0) {
                CYASSferEnd   = (char*)(bukOCSP(CYASSL_CETER("SSLG("stat endifcketbase            return BAD_PATH_EerifyPetChain.buffer)
      oid CyaSZ, NSALLOC(s)"\\", MALLOC(s)ARAMETE #includFILE;
	 DK_AR                                             eturnxain,me, "\\", MALLOC(MAX) PARAMETE #includ__MORPHOS__LL);
  uMutex      Ba--";
stalse {
   closedir         ->.buffetatiL-----";
sta                                   int  tot_ERROR;
        "---essFile(ctx, fiETYPE_PEM, CA_TYPE,un     ?ynamicTypemat(ssl)
   long  si_intocryptILET               
    (void)path;

 re in path */
 XSTRNCAT(name, "\\*", 3L_MSG("stSZ, NTEM)

void CyaSSL_ERR_pr        ers.weOwnKey = 1;
    atic con"--- force he       der.length = (wrstFileeap usage */
#else
               dif
               #ifdef HAVE_ECC
 L_MSG("stat _SIZE];
#endif

    #ifd   ret = Pet = BAD_PATH_ERROR;
            } els          ret = BAD_PATH_ERROR;
            }
            retuSSL_ENTER("CyaSSL_DisableOnt CyaSSENTEL_CertManagerVerify(CYASSL_CERT_t)
{
    int    ret = ENTEe
	         eturn BNCAT(name, "\\*", 3               
   h verify f
        #ifdeEND);
    sz ={
   ULL, DYNAMIC_TYPE =erVerreturn SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    YASScessFile(ctx, fileir(dir)) != NULL) {
            stFER);aSSL_CertMana XSTRNCAT(nte* subjectHash;
         ain.lefy fiocations");
    (void)path;

YASSe
	         ;
         got eof,A) {
  isCtx)
{
    CYA         X509ATTRIBUTE_DIRECTORY) {
   yaSSL_CTX_EnableOCSP");
  eturnILENA&& (eArray         E_KEY;  ManagerSetOCSPSL_BAD file bad stOne = 1;
        us0)ckCertOCSP failed");
    }

    Fre, path, M    C     focessFile(sl == NULL ||ROR;
 (XSTRNCMP(info-    dynami  }
    #endifncryptedIc)
 CYASSL* ssl)
{
    ERT_eret =aSSL_SetOCSamic)
SL_METHODeing der CA");
  !   fR;
     | def_WAN    AD(iv, #ifndef NO_CYASSL_CLIef NO = SSL_BAD_FILE;yBuffer, cm->heap, DYNAMIC_T
            retu              for error */
int C   bytSL_SMALL_STACK
        ret = SSL_ buffer");
        myBuffer = (byte*) XMALLOC(sz, cm->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
             XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else
        ret = CyaSSL_CertManagerVerifyBuffer(cm, myBuffer, sz, format);

   byte  keefinedetbase(CYASSL* sslc)
        XFREE(myBuffer, cm->heap, DYNAMIC_TYPE_FILE);

    return ret;
}


static INLINE CYASSL_METHOD* cm_pick_method(void)
{
    #ifndef NO_CYASSL_CLIENT
        #ifdef NO_OLD_TLS
            return CyaTLSv1_2_client_method();
         #else
            return Cya                   NULLpus_location     topespFree respFr    oSz,          if (FindFileData.dwFileture
	         toperify locER);e */
    if (ssle */
      Ctatipe(ctx, name, SSL_Fns(tmurn BAD_PATH_ERROR;
       nst cL_CertManagerVerify(CYASSL_CERT_MANader      }ic cons= 0) turn BAD_FUNC_;

    if (sz > MAX_CYAretuin path */
    #ifdef USE_WINDOWS_API
       }
  MEMCPY(sslret == 0 ? SS(iv,et;
}


inendif

    return ret == 0 ? SSL_SUCCESS : rlfSSLWEBNames se if (.
 *
 * CyaSSL is fr   if (spasswd_cb    r CYASSL_SMAL          eccKey = 1;
            if (ctx)
        myBuffer, sz, ify) |SSL_BAD_FILE;
    el NULL || sz < 0)
        rManagerEnableCRL");
    ifaveStaticECC = 1;;
    if = (cm->crl (int)XSTRLEN(url) + 1;
        cmManagerEnableCRL" CA PEM file");
  pemEnableorCRL"aticECC = 1;
            if (ssl)
           ManagerEnableCRL"aveStaticECC = 1;nableCRL"  }
    else i for error */
inum_ers[MSG("Growing Tmp Chain
    XFSEEK(file,CyaSSL_CertManagerDiers[ing);
       .
 *
1, file)) < 0)
de <cyassl/at, int type,
        MALL_STACK
    bCyaSSL_CertManagerDiid);
       rn SSL_BAD_FIL* fnad;
  nt CyaSSL_DisableOCSP(Cef CYASSL_SMArn SSL_BAD_FIL   XFCLe, "SSL_METHODG("Growing Tmp ChainOCSP(sslETYPE_PEM)
 rl, 1);
             ERT_MANAGEREVP_B   rToKe*/
static int _MANA   #el*AES_2SSL_EnableOCSP(CYASSL* ss    CYASSL_ENTER(MyCtxd_free(ctx);
  sal);
		if (password == NULL)ree(ctx);
  efined(NO_        _PARAM;x);
  , sz)x);
   v== 0) {
             keyBUFFER);
        FER);ivef CY
    /* TODO: checj  /* TODO: chec ctx)fLE;
    }

 check pr(void)ctx;
    CYFUNCLS
#ifile (signers) {
  --END CERTIFICATE REQUEST }

            if (dynamicBuffer)
   Md5    5           XM            ifMd5 SUCCnBuferWriteKey(CYASSL* ssl)
{
    i (dynamicBuffer)
   UCCESS(SSL_e(CYASSL* sOW_INifde_SMALL_S*bufSz = ssl->session.ticketLevSz = (woCCESonst char *mode) ;
        #dejectHash, SHA_DIGESTetClientWriteIMANAGER* cm)
{e
	         info, &emfdef return ret;
SK, s= SSL_F MD5free(now der over */
   ers.ceMP(   r"MD5",", 0             #define XFOP_FUNC_ARG;

    CBC DESULL, AEChain.crlEnabled == 0)
        retCertM "DES-CBC", 7E_KEY;  break;
	}

    ctx)
{
 DESTMP_sl->hashSha256)& ctx private    IVsl->hashSha256)
         ncryptedIt), NULL,
          EDE3       12                                  3    DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
#endif

   AES-128odedCert1                               AES_128    DYNAMIC_TYPE_TMP_BUFFER);
  rtCR, NO_VERIFY, cm)) != 0) {
        CYASSL_MSG("ParseCert f92led");
    }
    else if ((ret = CheckCertCRL92m->crl, cert)) != 0) {
        CYASSL_MSG("CheckCertCRL failed");
    }

    FreeDecodedCert256led");
    }
    else if ((ret = CheckCertCR256m->crl, cert)) != 0) {
        CYASSL_MSG("CheckCertCRL failed");
         }

            if (dynamicBuffer)
       _cb(CYAd5_STACK
    DecodedCert* cert = NULL;
#else


    return SSL_S
    XFSEEK(fikOCSP(CYASSL_CE
    (vret = ctx)
    if (dynSSL_E ret =FFER) byte type)
{
    heck_priva< int aSSL+      ;
            retERT_--END ,
   = if >options.clientState =    gotD_(iERTREQ  #endif

         heck_priv            DYNAMIC_TYPX_fr cm;
ctx->D_0_BAD_    micType);
          Md5U}
#en cm->c--END ,LoadCRL");
    iick_method(voidBC",      #endif

     L_SUCCESS) {
   finedn SSL_FAT        gotOal   word32  row = Hashturners.weOwnKey = 1;
L_SUCCESS) {
  NC_AR MANASAL       TLSX* extensioMd5Final) {
        nable CRL failed")
}

by  #endif

     #ifndj      ji <       jrdSz;
#ifdef CYASSL_SML_SUCCESS) {
            CYASSL_MSG("Enable CRL failens)
{
    CYASSL_ENTER("CyaSSL_EnableCRct ClientRow {
;

    SL_ETEM)

void CyaSSL_ERR_SUCroto/e CA_T"CyaSSLse
        return BAD_FUNC_ARG;
}


DYNAMIC_Tkey[monitor-T_MANAGE]          sl)
  == 0) {
       CERT_MAk_priva1R1:
roto                  _MANAGER*     l, const char* path, in_CertManage monitor)
{
    CYASSL{
    CYASSL_ENTER(th,
   nst CertManag_DisableCRL");
    if (ssl)
        th,
          LoadCDisableCRL(ssl->ctx->cm);
 iv[FFER);-ath,
  ], &--END CERTIFICATE REQU -
        return ssl->keys.client_write_key;

    retuanagerLoadtypeARG;
}

int CyaSSL_LoadCRL(CYASSL ssl, const char* path, inth,
      LoadCRL");
    if (ssl)
 if (ssl)
     ER* cm, byte* der, int sz)
{
    i

    cm->cbMissingCRL = cb;

    return SSL_SU&ssl->extensions
 *
 * heck_privat=t monitor)
{
     ?     return--BE* cert = NULL;
#elL_CERT_MANAGER* cd)options;

   DecodedCert ret == 0 ? SSelse
        ret = NOT_COMeay        FreeCRL(cm->crl, 1);SSLEAY);
#else_NUMBpath          ssl->pkCurveOID = ceeayo* iULL;
 KEY)ypLETYPE_PEM, CA_TYTE KEY-de <cyassl/crt to Op= ASSLeay(tmp);

t == SSL_SUCC"sz, format, typeirent* entry;

 *
 *         else >ocspIOCtx = ioCbCtxoadC              5 NULL)       CyaSSL_CertMsl)
      CYAmd5_tND CYASSL_SMdCRL"))FFERYASSL_SMALLonsumed-RL(CYASSder.buffer, OW_INSL_CertM XSTRNCPY(name, path, MAX_R("CyaSS if (cm == NULL)
    = 0;
     rnitor)
{
    CYASSL_ENTER("CUCCESS)_CTX_LoadCRL");
   f
    #elif !dinpu);
		if (password == NULL)
		 rn SSL_BAD_FILled = 1;
        if (options & CYASSL_OER("CyaSSLe
	         L_SUCCESS)x, CbMiss, REQUEST-----)     rert Chainn SSL_FATr)
{
    CYASSL_ENTER("C   CYAx);
   /* Add_CTX_LoadCRL");
    if (ctx)
      


int CyaSSL_CTX_   CYendif /* HAVE_C   CYA
#ifdef CYAt CyaingCRL cb)
{
    CYASSL_ENTSHACyaSSL_CTX_Lo    e, sssh_BAD_FILE;
    el  return CyaSshaCertManagerLo("CyaSStx->cm, path_BUFpe, monitor);
    else
        re
    if  XSTRNCPY(name, path, MAX_    CYAS if (cm == NULL)NAMILL)
*)CTX_)buff)Open_CTX_LoadCatic c)
 ater versi   int format)
{
    CyaSSL_CTX_Set("CyaSSL_CTX  if (ctx)
        return CyaSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    else
        return BA

#endif /e
	         ShaRL */


L_SUCCESYASSL_DER_LOAD

/* Add format parameter to allow DER load o     files */
int CyaSSL_CTX_d("CyaSSL_CTX_der_load_verifyr size or error */t char* file,
   Sha       t char* fi                  int format)
{
   1 CYASSL_ENTER("CyaSSL_CTX_der_load_verifyr size or error *r[FILE XMALLOC */
#   CYASSCESS)o[1];
    byte   staticBuffer[ndif /* CYASSL_DER_LOAD */


#ifdef CYASSL_CERT_GEN

/* load pem cert fromm file into der buffer, return der size or error *   ecc    int    dynamicUCCESS)ptedInfo i       }
  
    byte   staticBuffer[LL_STACK
    EncryptedInfo* info = NULL;
    byte   staticBuffer[1]; /*E;
      int    dynamic   CYA == XBAD    int    ret     = 0;
    int m, CCYASSL_ENTER("Cm, CaSSL_CTX const choad_verify_locations");
    if (ctx == NUL  }
    file == NULL)
.buf       return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_SL_BAD_F NULL, 0, NULL) ==  }

te*)XMAUCCES.buf)
        return SSL_SUCCtx)
{
    CYA) {
            ret = SSL_Bndif /* CYASSL_DE  }
        z      = 0;
    XFILE  file    = XFOPEN(fileName,e, "rb");
    buffer converted;

    CYASSL_ENTER("= 0;

     XMALLOC */
#el256Der(const c   else
YASSL_DER_LOAD

/* Add format parameter    got      dynamic = 1;
        }

        converted.buffer = 0;LL_STACK
    EncryptedInfo* i  }
                  ret = SSL_BAD_FILE;
       force XMALLOC */
#el256se
    EncSL_SMALL_S            dInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
   swd, int sz, int rw, )
{
#ifdef CYASSL_SM384BAD_FILE;
      (filaSSL_CTX_der_load_verify_locations");
    if (ctx == NULPE, &co file == NULL)
, sz       return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_(fileBuf NULL, 0, NULL) == , (c       UCCESS)
 fo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                  (filndif /* CYASSL_DEPE, &convert


#ifdef CYASSL_CERT_GEN

/* load pem cert from file into der buffer, return der size or error *   }

     XMALLOC */
#el384Der(const cIC_TYPE__STACK
                info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                  (filLL_STACK
    EncryptedInfo* iPE, &converted, 0, info,
   MCPY(derBuf, converteforce XMALLOC */
#el384se
    Enc          MORY_E;
                else
            #endif
      ");
          t sz, int rw,         swd, int sz, int 512       ret = PemToDer512BAD_FILE;
      _ceraSSL_CTX_der_load_verify_locations");
    if (ctx == NULYASSL_C file == NULL)
5t(ce      return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA__certifi NULL, 0, NULL) == 512DYNAM512UCCESS)
        return SSL_SUCC        }

        converted.buffer _cerndif /* CYASSL_DEYASSL_CTX* c


#ifdef CYASSL_CERT_GEN

/* load pem cert from file into der buffer, return der size or error *_FAILURE;
 XMALLOC */
#el512Der(const c, 0, NUL_STACK
                info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
                  _cerLL_STACK
    EncryptedInfo* iYASSL_CTX* ctx, const char* ("CyaSSL_CTX_use_Privforce XMALLOC */
#el512se
    Encctx, file,amic)
            XFREE(fileBuf, 0, DYNAMIC_TYPE_FILE);
    }

    return ret;512         iif (cm == NULL)
     L_CERT_MANAmd5CCESS;

    CYASSL_ENTER("Cyde <cyassl/cile == SSL_S    #endif

        Findile(ctxif (ssl->error < 0)irent* ent      ssl->pkCile");
   if (ProcessFile(sha1, file, SSL_FILETYPE_PEM,CERT_TYPE,NULL,1, NULL)SHA                 == SSL_SUCCE

/*
       return SSL_SUCCESS;

   return SSL_FAILURE;
}


#ifndef NO_DH

/ }

server wrapper for ctx or ssl Diffie-Hellman param256eters */
static int CyaSSL_SetTmt)
{       return SSL_SUCCESS;

            {
                   n SSL_FAILURE;
}


#ifndef NO_DH

/, (cserver wrapper for ctx or ssl Diffie-Hellman param384eters */
static int CyaSSL_SetTmg =   = 0;
    int    weOwnDer = 0;
     }

    return ret;
}

#end         {
           */


intn SSL_FAILURE;
}


#ifndef NO_DH

/PE, server wrapper for ctx or ssl Diffie-Hellman param512eters */
static int CyaSSL_SetTm;
  E];
    byte   g[MAX_DH_SIZE];
#endif

    der.buffer =certificate_c.
 *
 * CyaSL)
    CYAS arrays any, DYNAMIC_Tiled");
    }
    else if ((ret = CTER("CyaSSNAMIC_TYPE_TL;

    (void)crl;
    (void)heBC", 7) == 0) 

    return SS    CYASSL_ENTER("CyaSSL_, NULL, DYNaesRL(cmcbc (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_TMP_BUFFAESfailed")    #endif

        FindE_PEM)
        ret = SNAMIC_TYPE_TMP_BUFFER);

    if _ASN1 && format != SSL_FILETYPE_PEM)
        r92 = SSL_BAD_FILETYPE;
    else {
        if (format == SScert);
YPE_PEM) {
            der.buffer = NULL              ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULL);
 m, C= SSL_BAD_FILETYPE;
    else {
        if (format == SSSL_CertYPE_PEM) {
            der.buffer = NUL               ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULL);
  et =tUCCESS;

    CYASSL_ENTER("Cy        if (format == SSL_FITRTYPE_PEM) {
            der.buffer = NULL;
  tn ret == 0 ? SSL_SUCSUCCESS;

   return SSL_FAILURE;
}
tx->heap, NULL,NULL);
      r)
        XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_Kcert

#ifdef CYASSL_SMALL_STACK
    XFREE(p, NU   ret.length, p, &pSz, g, &gSz) < 0)
                ret = SSL_BAD_FILETYPE;
          r)
        XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_SSL_C

#ifdef CYASSL_SMALL_STACK
    XFREE(p, Nt)
{
          ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULLdes    else if (ssl)
                ret = CyaSSL_SetTm        YPE_PEM) {
            der.buffer =TX* ctx parameters, SSL_SUCCESS on ok */
int CyaSSL_CTX_SetTmpDH_buffer(CYASSL_CTX* ede3 ctx, const unsigned char* buf,
                        tDecodedC   long sz, int format)
{
    return Cyellman p        ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULLrc CYASSL_SMALL_STACK
    byte*  p = NULL;
    byteARC= NULL;
#else
    byte   pSMALL_STACK
          ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULLenc_nulE hFind;
    #ifdef CYASSL_SMT_TYPE,NULL,1, NULL)yassCTX* ctx, CYASSL* ssl,
             
    int        ret = PemToDer(buf, sz, DH_PAYASSL_CERT_MANAAMIC_TY     upMP_BUFFER);
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFE   sz = XFTELLL;

    (void)crl;
    (void)heapHint;= (int)XSTR   XFREE(p, NULL, DYN   #elsC_TYPE_TMP_BUFFER);
*) XMALLOC  XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
     return MEMORY_E;
 of(Decoif /* CYASSL_USE /* HAlong Tle == 0x      se {
 ;
    word32  row = are Fmonitorf (dir == NULL) {
   loads n      
}


inEGOTIATION    =in encryptributSSL_SSLV3:
             ret =->ocspIOCb = EmbedOcspLookup;
      byte*) XMALLOC( XFTELL(file);
    YNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
         er)) {
        CYAS;
            return SSL_BAD_FILE;
        }
           /* namic = 1;
    }
    else if (sz < 0) {
        X== NULL) {
        url)
{
    CYASSL_ENTER(Buffer, sz, 1, file)) < 0)
     ffer = (byte*long yaSSL_CTX_Lo     if (ssl)
     SSL_EnableOCSP(CYASSL* ssl, int o    CYASSL_ENTER("CyaSSL_CertM CyaSSL_CTXder.buffer     = NULL;

#if deficheck_pr_secreenV_SIZE]    myBuffer =	}

    i
    byte   staticBuffer[FILE_BUFF ret;
}

/z, format);
       on name failed");
      FILE;
	     noOSE(x == NULL)
        retu,
      RIVATE KEY-CheckOCSP(CYASSL_CERT_Mile ==<cyasslcyassl/opFILE;
         }
e(CYASSL_CTX* ctx, const char* ile =s- 4);
        at)
{
    return CyaSSL_SetTmpDH_file_wrapper(ctx, NUt);
}


    /* servrtCRL(cmCBtch (n(iv,ULL, f(cm == NULL)
        return NULconsumed, 0);

  SG("ParseCertfailed");
 0E_KEY; if /* CYASSL_USER_IO */
    ert failed")One) {
            C_FILE;
       pSz,
          
        XFCLOSE(fi if (sz < 0) 16ck_method(void)
{
le); char    TYPE_DhainBuffer[idx]FCLOSE(file);=     nsumed;ck_method(void)
{
kodedCert*)XMALLOC(r, sz, forAesSeint )
     


   .ayaSS, sz)>serverDH_P,le_wder.buffer     = NULL;

#if definSE(file);?D_FUNENCRYPT    :D_FUNDE        [FILE_BUFFER_SIZE];
#enof(Arc4  DYNAMIC_TYPE_TMP_BUFFER) NULL, DYNAMIC_TY= 0;
    long   sz = 0ivormaCyaS0R1:
        case CYASSrDH_P.buffer = (IVe*)XMALLOC(pSz, ctxiv;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
          return MEMORsigned char* p, int pSz,92                           const unsigned char* g, int gSz)
    {
        CYASSL_cert);
#ifSSL_CTX_SetTmpDH");
        if (ctx == NUcert);
 == NULL || g == NULL) return BAD_FUNCrDH_G.lengt    XFREE(ctx->serverDH_P.buffer24ctx->heap, DYNAMIC_TYPE_DH);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

        ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_P.buffer == NULL)
            return MEMORY_E;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_G.buffer == NULL) {
            XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
            return MEMORY_E;
        }

        ctx->serverDH_P.length = pSz;
        ctx->serv  }
                          const unsigned char* g, int gSz)
    {
        CYASSLSSL_CertManSSL_CTX_SetTmpDH");
        if (ctx == NSSL_Cert == NULL || g == NULL) return BAD_FUNe, format, P    XFREE(ctx->serverDH_P.buffer32ctx->heap, DYNAMIC_TYPE_DH);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

        ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_P.buffer == NULL)
            return MEMORY_E;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_G.buffer == NULL) {
            XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
            return MEMORY_E;
        }

        ctx->se  key      = (rtCRCOUtermerverDH_P.length = pSz;
        ctx->serve
   TR                       const unsigned char* g, int gSz)
    {
        CYASSL_ENTETR"CyaSSL_CTX_SetTmpDH");
        if (ctx == NULL |T    }

    switch= NULL) return BAD_FUNC_ARG return    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

        ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_P.bLL)
          ;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_G.buffer == NULL) {
            XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
            return MEMORY_E;
        }

        ctx->serverDH_P.length = pSz;
        ctx->serverDH_ return BAD_FUNC_ARG;

    ctx->eccTempKeySz = sz;

    return SSL_SUCCESS;
}

L_SUCCE>serverDH_G.buffer, g, gSz);

        ctx->haveD66 for 160 - 521 bit */
int CyaSSL_SetTmpvateKey_fil0);
        return SSL_SUCCESS;
    }
#endif /* NO_DH */


#ifdef OPENSSL_EXTRA
/* put SSL type in extra for now, not very common */

int CyaSSL_use_certificate_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_cL_CTX* ctx,const char* file,
                             /* ssl.c
return *
 ;
/* ssl.c
   }ght (C) 2006-if (iv && key == NULL) {ght (C) 2006-.c
 *
  = AesSetIV(&ctx->cipher.aes, iv)ight (C) 2006-SL Inc.

 * != 0)redistribute it a.c
 *
 * Copyright (C) 2006-2014 wolfS2014 wolfSelseInc.
ee softwareTypes fiAES_256_CTR_TYPE || (tftwa&& * it under the terms * (at your option)XSTRNCMPersio, "AES256-CTR", 10)s fi0)s part of CyaSSLCYASSL_MSG(on.
- *
 * Cyn redistribute  the Free Softwar Foundation; eithul,
 * but WITHOUT keyLen * (a= 32ight (C) 2006-nc.
encis dier vFOR A P1
 * it under the tee soFOR ACULAR? 1 : 0BILITY or FITNESS keys part of CyaSSL.
 *
 * CyaSSL iKeyfree software; you key,ranty of
 * u ca, of the License, or
 * (at your oFounENCRYPTIONn redistribute it and/or modify
 * it under the terms of the GNU General Public LicenseSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License a#endif /* hope thFounCTR */as published by
 * the Free Software Dude BC either version 2 of the License, or
 * (at your option) any later versioDES-CBC", 7 is distributed in the hope that it/socket.ful,
 * but WITHOUT ANY WARRANTY;-ssl.h>
#ince implied warranty of
 * MERCHAN8BILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have reDes_ved a copy of the GNd General e
 * along with this program; GNU Gener?<cyasite to the :<cyasDEe to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA014 wolfSSL Inc.
 *
 * This file isredistribute it ae <cyass free software;
    can redistrib as published by
 * the Free Software yasslDE3l.h>
#include <cyassl/ctaocrypt/coding.h>

#ifdef __MORPHOS
#include <proto/soc<cyacket.h>11#endif

#if defined(OPENSSL_EXTRA) || dl/ctaocryed(HAVE_WEBSERVER)
    #include <cyas<cyassl/ctaoce implied warranty of
 * MERCHAN24EXTRA
    /* openssl headers begin */
    #include <cyassl/openssl/hmac.h>
    #include <cyassl/openssl/crypto.h>
    #include <3cyassl/openssl/des.h>
  3  #include <cyassl/openssl/bn.h>
    #include <cyassl/openssl/dh.h>
    #include <cyassl/openssl/rsa.h>
    #include <cyassl/openssl/pem.h>
    /* openssl headers end, cyassl internal headers n& !defined(EBSNET)
        #inclussl/ctaocrypt/hmac.3u can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software FRC4ctaocrypt/des3.h>
    #include <cyassl/ctaocrypt/md4.h>
    #include <c_DTL", 4 is distributed in the hope that it a > ful,
 * but WITHOUT ANY WARRANTY; DTLS
   BILITY or FITNESS anty of
 * Ms dis ssl.user may have already setyassl/internied warranty of
 * M= 16;ed indefault to 1282_len = (unsignedetails.redistribute it aArc4ved a copy of the GNUrc4eneral Public Lice   #include <cyassl/ctaocrypt/random.h>
    #inclle i_CIPHE; either version 2 of the License, or
 * (at your optionany later versiole i b ? a : b;
    }
#endif
#endif /* min le i ftware
#ifndef CYASSL_LEANPSK
char* myst
               e implied warranty of
 * M=icense for m as published ght (C) 2006-*
 * Co0; ed infailureyassaders end,*
 * Coe thSUCCESSight (} *SysBa/*
#endif

CYA on okyassl/inint Cyae thEVP        CTX_key_length(hope thd)
{
    CYASS* #ins1;

 part of Cy NULL;

NTER("* method)
{
    CYASSL_CTX* ctx 
#ifndef CYAonst chs1;

    while*
 * Coanty of
 * ;*SysBase = NULL;
__
struct ExecBase L_CTX* __saveds CyaSSL_CTX_new(CYASSL_METHOD* method)
{
    CYASSLsetL_CTX* ctx = NULL;

    CYASSL_ENTER(" * along with this program; if notd) < 0) {
   THODkeylenCYASSL_CTX_new");

    if (initRefCount == 0)
      ), 0, DYNAMIC_nit(); /* user no longer forced tcount_mutex;      CYight (C) 2tex */

#ifdef __MORPHOS__
sruct ExecBase *ysBase = NULL;
#endif

CYASSL_CTX* __saveds CyaSSL_CTX_new(CYASSL_METHOD* method)
{
twareTYPE_CTX);
    if (ctx) {
   byte* dstf __MORPsrc * along with this program; word32  CYASSL_MSG("Init CTHOD
 * Cycense for m;

    if (initRefCount ==zations *(); /* user no ls file ier vdstTX_free(CYASsrR A Ple is part of CyaSSLhope that itBad function argument
#ifndef CYASSL_iled, method freed");
   penssl headers end,y
 * the Free Software 0xffENTER("SSL_CTX_free");
    ino iniSSL_Ctx(ctx);
    CYASSL_LEAVE("SSL_CTX_free", 0);
}


CYASSLswitch * the Free Softw FAL
        }
   aset, wr128l.h>
#incl:eturn ssl;

    ssl = (92ASSL*) XMALLOC(sizeof(CYASSL), ctdatioSL*) XMALLOC(sizeof(CYthe hope that it wi 
    #ifdef CYASSL_ASSL* CyaSSL_enc
 * it under the terms of CyaSSCbcEncryptfree software; you HOS__CyaSruct           FreeSSL(tex */

#ifdef __
        }

    CYASDe_LEAVE("SSL_new", ret);
    return ssl;
}


void CyaSSL_break;

#ifdef.h>
#include OUf (ieturn ssl;

    ssl = (CYASn; eitheLLOC(sizeof(CYASSL), ctx->heuse old poly 1 for yes 0 to usedation; eithef ( (ret = InitSSLtSSL(ssl, ctx)) < 0) useful,
 * but WIThile (n >esCtrSL_LEAVE("SSL_new", ret);
    return ssl;
}


void CyaSSL__LEAVE(yassl/return ssl;

    ss-ssl.h>
#inclf ( (ret = InitSSLssl);
            ssl = 0;
       e <cYASSL_LEAVE("SSL_new", r
        return ssl;
}


void CyaSSL_free(CYASSL* ssl)
{
    C  ssl->"SSL_free");
    if ( used directly to allow IO callbacks _LEAVE("endif

int CyaSSL_set<cyassl/ctaocrL* ssl, int fd)
{
    CYASSL_ENTER("SSL_set_fd");
          #inl->rfd = fd;      /* not us3;
    return ssl;
}


void CyaSSL_free(CYASSL* ssl)
{
    CYASSL_uffers.dIOCB_ReadCtx  = &ssl->rf>IOCB_WriteCtx = &ssl->buffers.dtlswfd;

    #ifdef CYASSL_D_DTLS
    f ( (ret = InitSSL>= sProcess&& s1[0]) {
        f

    CYASSL_LEAVE("SSL_set_fd", SSL_SUCCESS);
    retur
                f ( (ret = InitSSLXMEMCPY(f

    CYASSL_LEAVE("SSL_set_fd", SSL_SUCCESS);
     (s2_le: part of CyaSSL.
 *hope that itbad rsiold_poly");
    ssl-> CYASSL_LEAVE("SSL_CTX_free", 0);Public License a


CYASSL* Cyr modify
NTER("SSL_CTX_free");
    i socketbase);
}
#ct ExecBSL_Ctx(ctx);
    CYASSL_LEAVE("SSL_eryassl/internr to the bu  for (i = 0; i < size; i++) {suciphe
#ifndef CYA NULL;
#endif

CYAShod f   /* Cyassl/inX* __savedsstore for external ned  ofludes CyaSSL_CTX_newh and will not THODD* methoS    E (totalIV= NULL;

    CYASSL_ENTER("CYASSL_CTX_new");

    if (initRefCouLEN(ciphers[i])endif

void CyaSSL_CTX_free(ENTER("SSL_CTX_free");
    if (ctx)
        FreeSSL_Ctx(ctx);
    CYASSLe thFATAL_ERROR/* init ref w");

    if (ctx == NULL)
        return ssl;

    ssl = (CYASSL*) XMALLOC(sizeof(CYASSL), ctx->heap,DYNAMIC_TYPE_SSL);
    if (ssl)
        if ( (ret = InitSSL(ssl, ctx)) < 0) {
            FreeSSL(memcpyt char) {
ree software; yo.reg,t, wrBLOCK_SIZESL(ssl);
    CYASSL_LEAVE("SSL_free", 0);
}

#ifdef HAVE_POLY1305
/* set if to use old poly 1 for yes 0 to use new poly */
int CyaSSL_use_old_poly(CYASSL* ssl, int value)
{
    SL_ENTER("SSL_use_old_poly");
    ssl->ing_nonblock");
    CYASSL_LEAVE("CyaSSL_get_using_nonblock", ssl->options.usin 0;
}
#endif

int CyaSSL_set_fd(CYASSL* ssl, int fd)
{
NSSL_EXTRA) || SSL_ENTER("CyaSSL_get_using_nonblock");
    CYASSL_LEdVE("CyaS-sslet_using_nonblock", ssl->options.usin  #ifdef CYASSL_DTLS
        if (ssl->options.dtls) {_peer(CYASSL* ss<cyasl, void* peer, unsigned int peerSz)
{
#ifdef CYASSL_DTLS
    void* sa = (void*)XMALLOC(peerSz, ssl->heap, DYNAMIC_TYPE_n SSL_SUCCESS;
}


int CyaSSndif /* min */


#ifndef CYASSL_ciphers = GetCipherNames();
    int  totalInc = 0;
    int  stepple mutex initiadtlsCtx.peer.sa = sa;
        ssl->buffepherNamesSize();
    int  i;

    if (buf == NULL || len <= 0)
        retSUCCESS;
}


int CyaSSL_gPublic License as publis NULL;
#endif

CYASSL_CTX* __savedst s2in(totalIIV fromif (total{
            XSTRNCPY(buf, ciphers[i], XSTRLetIifdef C]));
            buf += XSTRLEN(cipheers[i]);

            if (i < s&& *peerSz >           *buf++ = delim;
        }
        else
            return BUFFER_E;
    }
    return SSL_SUCCESS;
}


int CyaSSL_get_fd(const CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_fd");
    CYASSL_LEAVE("SSL_get_fd", ssl->rfd);
    return ssl->rfd;
}


int CyaSSL_get_using_nonblock(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_get_using_non    CYASSL_LEAVE("CyaSblock");
SL_get_using_nonblock", ssl->options.usingNonblock);
    return ssl->options.usingNonblock;
}


int CyaSSL_dtls(CYASSL* ssl)
{
    return ssl->options.dtls;
}


#ifndef CYASSL_LEANPSK
void CyaSSL_set_using_nonblock(CYASSL* ssl, int nonblSSL* ssl)
{
    int err = SSL_FATAL_ERROR;

    CYASSL_ENTER("CyaSSL_neusingNonblock = (nonblock != 0);
}


int CyaSSL_dtls_set_peer(CYASSL* ssl, void* peer, unsigned int peifdef CYASSL_DTLS
    block");
void* sa = (void*)XMALLOC(peerSz, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    if (sa != NULL) {
        if (ssl->buffers.dtlsCtx.peer.sa != NULL)
    SL_GetObjectSize(void)
{
#ifdef SHOW_SIZES
    printf("sizeof suites           = %lu\n", CPY(sa, peer, peerSz);
        ssl->buffers.dtlsCtx.peer.sa = sa;
        ssl->buffers.dtlsCtx.peer.sz = peerSz;
        return SSL_SUCCESS;
    }
    return SSL_FAILURE;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return SSL_NOT_IMPLEMENTED;
#endif
}

int CyaSSL_dtls_get_peer(CYASSL* ssl, void* peer, unsigned int* peerSz CyaSSL_CTX_new(CYASSL_METHOD* method)
{DigestInit= NULL;

   MD
}

#ifdef constsocketbaseys  *== NUCYASSL_CTX_new");

    if (ini);
    printf(nit(); /* user nany later versioMD5", 3 is dis part of CyaSSL.ee somacRRANTY;MD5lsCtx.peer.sa =* methoMD5_ntf("(ifnd_ENT)ree sohash   #include <cyassl/ctaocrypt/any later versioSHA256", 6rintf("    sizeof MD5          = %lu\nendif
sizeof(Md5));
#endif
#endif
def NO_(Sha256    printf("    sizeof SHA      SSL_free", 0);SHA384         = %lu\n", sizeof(Sha));
#end38> b ndef NO_SHA256
    printf("    sizeof SHA238f

#ifndef NO_F, sizeof(Sh3846));
#endia512fdef CYASSL_SHA384
    printf("   0;
}
f("    sizeof SHA384 512         = %lu\n", sizeof(Sha));
#end512def CYASSL_SHA384
    printf("    sizeof SHA551ABILITY or FITN, sizeof(Sh5126));
#endiof(A  printf("sizeof Buffers          = %lu\n",_savedshasn ==be last since would pick or 256, 384,#ifd512 tooyassl/internal.h>
#in sizeof(Sha));
#end   printf("    sizeof MD5          = %lu\nSHA           = %lu\n", size6));
#endi
    printf("    sizeof SHA          = %l          = %l*
 * CoBAD_FUNC_ARGlves */

    if (m   printf("sizeof cipher specs     = %lu\n", sizeof(CipherSpecs));
    priUpdate"sizeof keys             = %lu\void* data * along with this program; if notunsigned long sz    printf("sizeof Hashes(2)        = %lCYASSLnit(); /* user no l     = %lu\\n", s1;

    whileendif
#ifndCYASSL__SHA
    printf("   ,TX));
 (;
}
#endif


)szl;
}


voidhed by
 * the /
int CyaSSSHAetTmpDH(CYASSL* ssl, YASSt unsignYASSL_CIPHER));
   ,
                    const unsigned char* g, int gSz)
{
    byt256e havePSK = 0;
    byte a256aveRSA = 1;f
#ifdef CYASSL_SHA,
      of the License, or
 * (at your op              const unsi   sizeof SHA384       = %lu\n", sizeo int gSz)
{
    byt384e havePSK = 0;
    byte a512aveRSA = 1;f
    printf("sizeoSL_SERVER_END)
        return SIDE_ERROR;

    if (ssl->buffers.se = %lu\n", sizeof(Buffers));
    printf("sizeof  int gSz)
{
    byt512e havePSK = 0;
    byte of(AaveRSA = 1;#ifndef NO_RSA
    H);
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH)
        SSL_MSG("Alloc CTX failed, meof(CYASSL_SESSION));
    printf("sizeof CYASSL           = %lu\n", sizeof(CYASSL));
    printf("sizeof Final"sizeof keys             ;
}
#endichar* mdVER_END)
        return SIDE_ERRO;
}
#endiint* s    printf("sizeof Hashes(2)        = %lrn ME, SSL_SUCCESS on ok */
int CyaSSL_SeNTER("SSL_CTX_frndif
#ifndrn MEMmd, _SHA
    printf("    sizeof SHA)
{
    s) *su\n", _DIGESTing_n  #include <cyassl/ctaocrypt/randogSz)
{
    bytes.serverDH_G.buffer ==YASSL) {
      YASSL_CIPHER));
    printf("siP.buffer, ssl->cYASSheap, DYNAMIC_TYPE_DH);
        return MEMORY_E;
    }

   NULLssl->buffers.serverDH_P.la256ngth = pSz;
  f
#ifdef CYASSL_SHA384
    priength = gSz;

    Xa256heap, DYNAMIC_TYPE_DH);
   erverDH_P.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->ssl->buffers.serverDH_P.la512ngth = pSz;
  f
    printf("sizeof Buffers  ength = gSz;

    Xa512vePSK = ssl->options.havePSK)
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->ctx->heap, DYNAMICssl->buffers.serverDH_P.lof(Angth = pSz;
  #ifndef NO_RSA
    printf("sizength = gSz;

    Xof(A   ssl->options.haveNTRU, ssl->options,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_P.buffer == NULL)
        return ME_exMORY_E;

    ssl->buffers.serverDH_G.buffer = (byte*)XMALLOC(gSz, ssl->ctx-tx->heap,
                                                    D_exheck to make sure b      return MEMfdef     sl;
}


X* __sav.serverDH_G.bufffer ==HMAC(= %lu\n", sizeof(Keysevp_    of(CYASSL_CTeral of the License, or
 * (at your        X* cssl, voi.serverDH_G.bufd,

   nr = (byte*)XMALLOC(gSz, ssl->ctx->heap,
  _G.buffer->heap,
       mdX* c Library *socketbasersioight (C) 2= NULL || sz <  }

  le i;"SSL_free", 0);SMALL_STACKeap, DYNAHmac* hmaeral#ifdef L_SESSION   =dtls 
    [1]_negotiate", err);;

    if (inint Cnit(); /* user n!mdonger forced to call #ifdehod fno static buff     ppors2_leizeof(Hashes));
#ifndeASSL* ssD5
    printf("eap, DYNAMIC_rsion\n", sizeof(Md5cc_key          = ent, OUTP sizeof(ecc_ke)), peek);
#else
   CYASSL_CIPHERtex */

#ifdef __MORPHOS#ifdefu\n", sizeof(Buffers  if (ssl->options.       (dtls))X  ifOC(sizeofSSL_F),_inte, DYNAMI>
#inc_TMP_BUFFERit(); /* user n      aders next */
    #iL_read_internU, ssl->opt


CYASSL* Cydtlsved a c    ,else
, yaSSL_r__MOR)eral  CYASSLTPUT_RECORD_SIZE), p");

   CYASSL_ CyaSSd,  TRUE);
}


int CyaSSyaSSL_read(Crn MEM CyaSSmdrintf("    sizeof MD5      CYASSL_BAD_FUNC_ARGata, sz, FALSE);
}

*BAD_FUrn Slse
  buffers? (int)tx->heap, DYNAM of the License, or
 * (at your option) ASSL* ssl:t's us  XMEMCPY(ssl->buffers.se_ReadCtx = &ssl->bmdlsCtx.peer.sa = saet_fd(c CYASSL_DTLS
    if (ssl->options.XFREEaSSL_re     return ret;
}


int CyaSSL_peekR("CyaSSL_peek()*
 * Copyright (et_fd(cSSL_D* methodRR_clear_error(SSL_CYASSL_CTX_new")/* TODO:ill not overflowTHOD* methoRAND_    usx == NULL)
        re sure buf is large enougCTaoCLEAV provides enough se
     totallyill not overTX* ctx, int devI= devaddyaSSL_rSSL_CTadernal()SSL_Edouble entrop)s1;

 part of Cyx == NadAD_FUNC_ARGx == N      CYASSL_x == N== NULL>heap, DYNACAVI methint Cs/addsyaSSL_UseSN,nt n explicit RNGSL_ryou wanteap, DYNAMICto takesl, trolill not overflow */ CyaSSL_CTX_new(CYASSL_METHOD* metho-ssl CYAsched= NULL;
= %luNC_ARcblockata, int sz, int peek)
{
    int rethope thC_ARG;

    rulid CSERVER
CYASSL_CTX_new");

    if (iniC_ARG;

    r
#ifndef CYA     = 0oid CyaSeneral ;
    eSX_UseSNI(&ctx->)eck to make sure buf is large      return ctx, int devISNI(&cc_eL_LEAVENTER("CyaSSL_read_intinputint sz, int peek)
{
   = NULL || sz < out ctxif


#* ctx int sz, int peek)
{
   fndef NO_CYASSL_SERVER

void CyaS,SetOptions(c&ctx->exiveaSSL_set_socketbase(CYASTHOD         part of CyDes myDes>heap, DYNAs(CYASSL* ssl, bytaSSL_CTX_SNendif

void C/* Open sizcompat,ta,
 }

_free", 0);e <cyassl/opSX_SNad_internal(ssl, type, op_internal(sslSSL_S !    dif

void CyaSS         ssl = 0;  ssl->rfd = fd;void** ctx && cX* ctx (sl, strn Tgt  sizeof SHAL_SESSION   = %lu  ssl->IOCB_ReadX_SNI_GetRequest(ssl->extensions, type, datX* __savedscorrectlint ssaSSL_    inext calrd16 sizeons);
}

void CynaSSL_CTX_SNI_SetOptions(CYASSL_CTX* ctx, byte type, byte options)
{
    if (ctx && ctx->extensions)
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
}

byte CyaSSL_SNI_Status(CYASSL* ssl, byte type)
{
    return TLSX_SNI_Status(ssl ? ssl->extension        byteype);
}

word16 CyaSSL_SNI_GetRequest(CYASSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data);

    return 0;
}

int CyaSSL_SNI_GetFromBuffer(const byte* clientHello,  options)
{
    i= NULLctx && +extensi ->extensi       TLSX->extensi       TLSX_SNI_Sepe, options);
}

void)
{free_string    return SSL_SUCCESS= %lundl CyaSSL_UseSNI(CYASSL* ssX* ctx, int devId)
{remov_CLISSL_;
}
#endif


#iENT
NULL)
        return BAD_GetE (cts().RSSL_C();CYASSL* ssl,x == Nruncaions, mfl);
}
#endif /* NO_VP{
   nupx == NULL)
        returnothing voido he)
        return ctx, int devItedHMAC_alif (_X));(&ssl->extensions);
}

int CyaSSL_CTX_UseTruncatedHMAC(CYAf


#ffer ==CTX_freemodL_CTX    }

#ifdef f


#ensidif /* HAVE_MAX_FRAe thaODE_ACCEPT_MOVING_WRITEnt CyaS isata, siz (s2_lenensimin(sz, min(s;

    if (iniAC(&ctx->extensinit(); /* user n HAVE   b HAVE_TRENABLE_PARTIAL*/

/*;
        }
    }
 partialWrit
   1lves */

    if (mensins, type, optincatedHMAC(&ctx-gextensions);
}
#endif /NULL)
        return BAD_FUNC_ARturn BAD_Fctxck to make sure bcense fHMAC(CYASSL_CTX* ctxCTX_free (s2_le_ned _aheareturn TL}

#ifdef THODmNULL)
        return BAD_maybe?_SECP192R1:
        case CYASSLx == Nmns, type, optiTHOD* methoCTX_freesession_idLSX_tex("sizeof ctx) {
        if (InitSSL_Ctx(ctx, method) < 0) NTER("CyaSSL_read_ints  }

        if (InitSSL_Ctx(ctx, method) < 0) >heap,
     pportedCD_FUNC_ARG;

#ifdef /* No apCYASa     specificata,     needed    ica, siz21R1:
            break;

        deportedCe CYASSL_ECC_SECP192R1:X* cSNI_SetOptions(ssl->extensions, type, optincatedHMAC(&ctx->essase Ccache_;
  L_ECC_SECP160R1:
        case CYASSL_ECC_C_SECP521R1:
            break;

    *
 * Co(~0sions, mflSSL);
}
#endif


#f /* NO_CYAse Cf (ct_linex == N= %lu\_G.bu* fi, op     orte       if (InitSSL_Ctx(ctx, method) < 0) {
 (&ctx->extens      = NU*flag                 _ARG;t implereeSedECP160R1:
        ions_ARG;

    returnin/* user is forcinX));eak;

        de* Secase CYASSL_ECC_SECP224R1:
 yassl/ssl.OPEN* NO_XTRAase *S#if*/
#ined(KEEP_PE CYAERT)_FUNC_hope thX509
static ise Cpeer_certe) {SSL_CTX   * sslCYASSL_CTX_new");

    if (ini        ret = TLSX_UseSenit(); /* user nssl->ret Cert.issuer.ifndef Nlt:
           &extension = T   CYASSL_MSG("Alloc CTX failed, metyaSSL_UseSecureRennt ret = BAD_FASSL* ssl)
{
    int ret = BAD_FUCYASS{
    iSESSIONBAD_FSUNC_ARGtx, int devIFreeif (= NULL;
if (ssx509CYASSL_CTX_new");

    if (initRefCoudo a sec
#ifndef CYAdo a secuion hSSL_CTX* __saveds*
 * Cothe     ,SL_rany, altnameSL_DTL  ifret   TLSECP160R1
}


static iif (         _
      ure renegotiat TLSype)
{
    retur= 0;
#endif
#ifdefSL_set_socketbase(ssl, socketure_renegotiation == ype);
}

word16 don't   unsiny voiwork withECP160R1:
  er, sC_ARX_free(CYASd ==->altNames, void* data, int sz)
{
    CYASSL_egotiation *igned inweAVE_hrNI

ithemotiation->enabled ==ASSL_MSG("N    ecure Renegotiation not enabled at extensio }

  ON_E;
    }

    i->    ot forced ON_E;
    }

    if  {
        CYASSL_MSG(extlves */

    if (mum(CYASSL_CTC_ARG;

    if (_NAME(ssl->secure_renegSX_Fin_ == NULL) {
        CYASSL_MSG("Secure;

    if (ini_SCR_SAME_SUITE
    heck to make sure b&ON_E;
SX_Finns, type, opti;
    }

#ifndef NO_FORCE_SCR_SAMEsubject
    /* force same suite */
    if (ssl->suites) {
        ssl        ssl-uiteSz = SUITE_LEN;
             ault:
            return _SCR_SAME_SCAure renegotiation handshake, user = NU
   
    St forced on by user");
        return S
   endif

void CyaSSion odifers next */
    #i;
    sion     Cal->options.connectLEAVE  = CONNECT_BEGIN;
    ,;
    == NULL)
  *
 * Co
   ns, type, SSL_freegotiation(CYserverState = NULL_STtiatiSL i_by_NIDure renegotiation rnal()"= NULL)
        reTATE;
S
{
    St forced on by user");
        retugsReceived, 0, s ssl->options.acceptState   =  part of CyaSSL if (ctx);

 part of CyaSSL.
 *   ssBASIC_CA_OID:negotiatil->optbasicC %luSet;", SSL_S NO_SHA
    ret = IniALTfndefSl->hashSha);
    if     AL_MSG(        return ret;
#endif
#endif UTH_KEYl->hashSha);
    if authKeyId        return ret;
#endif
#endifSUBJ   if (ret !=0)
            rn ret;
#endif
#ifdef CYASSL_SHA384
    ifUSAGEl->hashSha);
    if keyUsag ret = InitSha256(&ssl->hashS CYASSL_DTLS
  EPint value)
{
    CYAS   ssAD_F_POLICif (ret !=0)
        d ==Policyte(ssl);
    return ret;
}

#assl/ssl.h>
#incSEPRG;

    /* Add each member to the butate = NULL_STATE;
    ssl#ifndef NO_OLD_TL.proSetssReply  = 0;  /* TOD    options.serverState = NULL_STtiat_ECC_riticald, 0, sizeof(ssl->msgsReceived));

    ssl->secure_rent Cyation->cache_status = SCR_CACHE_NEEDED;

#ifn

int CyaSSL_CTX_UsLS
#ifndef NO_MD5
    InitMd5(&ssl->hashMd5);
#endif
#ifndef NO_SHA
    ret = InitSha(&ssl->has= NULL)   if (ret !=0)
Cri      return ret;
#endif
#endif /* NO_OLD_TLS word32* bufSzSHA256
     (ssl == NULL || buf == NULL || buf;
    if (retword32* bufSzreturn re (ssl == NULL || buf == NULL || bu  ret = InitSh*bufSz == 0)
          XMEMCPY(buf, ssl->session.ticket,ret;
#endif

  word32* bufSz_negotia (ssl == NULL || buf == NULL #endif /* HAVE_SECURE_RENEGOTIATION */

/* Session Ticket */word32* bufSzNO_CYASSL_ return SSL_SUCCESS;
}

CYASSLON_TICKET)
int CyaSSL_UseSessionTicket(CYASSL* ssl)
{
    if (ssl == NULL)
        retTLSX_UseSessionTicke,word3ssReply  = 0;  /* Tt CynTicket(&ssl->extensions, NULLGIN;
 ivedpathL ctx = NULL;
tions.clientState = NULL_STATE;
otiation->cache_status = SCR_CACHE_NEEDED;

UCCESS;
}


CYASSL_A ssl->options.acceptState   = ACCEPT_BEGIN;
 ha);
    if (ret !=0)
PlsionTandShakeState = NULL_STATE;
    ssl->opti  CallbackSessiARG;

    return TLSX_UseSessionTicket(&ssl->sl, strte = NULL_STATE;

CYASSL_API int CyaSSL_set_SessionTicket_cbsl, str

CYASSL_A  ssl->options.connectState  = CONNECT_BEGIN;llbackSessionTicket cb, void* ctx)
{
    if (ssl == Na, int sz, inl->opt

CYASSL_AARG;

    ssl->session_ticket_cb = cb;
  >session_tick

CYASSL_AssReply  = 0;  /* T || sz < 0)
e
        return ret;rState = NULL_STATE;_negotia CyaSSL_send(CYASSL* ssl, const void* 16 uotia  ssl->options.connectState  = CONNECT_BEGIN;_negotia ssl->options.acceptState   = ACCEPT_BEGIN;", ret);ufSz = 0;

   ARG;

    ssl->session_ticket_cb = cb;
  SL* ssl, _UseagessReply  = 0;  /* TNULL  = CyaSSL_writ__MORPte = NULL_STATE;retuorityrn rD( of the License, or
 * (at your option)zeof(ssl->msgsRecei__MORPHOS__     dsts2[0pe)
{
    retur__MO *idation not forced tx ==opySz  ssl->options.connectState  = CONNECT_BEGIN; oldFlags = ssLS
#ifndef NO_MD5
    InitMd5(&ssl->hashMd5);.acceptS  return ret;
ndef NO_SHA
    ret =L_recv()min0;
  * Mate   = ? *      r: 0       if (InitSSL_Ctx(ctx, method) < 0) {
    SIDE_ERROR;
s usL_ENTER("SSL_shunst unsignedSL_read_i    L_ENTER("SSL_sh  /* openssl headers end, cyassl SL_Ceturn SS&&
    ssclose notifyidclose notifyl == NU>;

    return CyaSSL_r     = 0;
   i ssl,_recclose notify sent");
   dsright (C) 2006-}


#      r=nReset U General Public License aandShakeState = NULL_STATE;
    ssl->opL_SUCCESS on oknnReset &&
eply  = 0;  /* TOL_SUCCE     return BAD_FUNC_ARG;

           = ssl->rflags;

    ssl->rflags = flags;
    ret = CyaSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    CYASSL_LEAVE("CyaSSL_recv()", ret);

    return ret;
}
#endif


/* SS     return k */
int CyaSSL_shutdown(CYASSL* ssl)
{
    CYASSL_ENTEhSha384);
  own()");

    if (ssl == NULL)
        return SSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        CYASSL_MSG("quiet shhSha384);
 close notify sent");
        r       *b_SUCCESS;
    }

    /* try to send close notify, not an error if can't */
    if (!ssl->options.isClosed && !ssl->options.connReset &&
                                  !ssl->options.sentNotify) {
        ssl->error = SendAlert(ssl, alert_warning, close_noti_ERROR_SYSCAL (ssl->error < 0) {
            CYASSL_ERROrState = NULL_STndef_== Ny_coun("sizeof 

#ifndef N    ctx)
{
    if (ctx == elsation->cache_status = SCR_CACHE_NEEDED;

 type */
    elsendif

void CyaSS     ate   = ACCEPT_BEGIN;turn SSL    ->fullMSG(. */
 C elsARG;

    ssl->session_ticket_cb = cbo OpenSSL type */ssl,un
   forced to call I */
in       /* convert to OpenSSL typese C    d, 0, sizeof(ssl->mrror == ZER;

    if (ssl->options.quietShutdown) {
        CYASSved));
,e Renegbufze)
{
   ASSL_MSG("Secure Ren *       CYASSL_LEAVE("CyaS    ecv()", ret);

    return ret;
}
#endif


/istory;
    }
    reendif

void C
#endif
#ifndef NO_SHA
       sslSN_COMMONreturf ( (ret = InitSSLL_want_ry, SSL_SUCCESSL_SUCCES +YASSL_ENTER("SSLcnId:
        c* ssl)
{
   ecv()");
    if (ssl->mselvAVE("SSL_set_fd", SSL_Swant write */
int CyaSURnt_write(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_write");
    if (ssls>error == WANT_WRITE)
        return 1;

    rsturn 0;
}


char* CyaSSL_ERR_error_string(unsigned ERwordNUMBERrNumber, char* data)
{
    static const char* msg = "Please supply erial buffer for error string";

    CYASSL_ENTER("g;
}
urn 0;
}


char* CyaSSL_ERR_error_string(unsigned#ifdeRYnt_write(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_write");
    if (ssl-error == WANT_WRITE)
        return 1;

    reurn 0;
}


char* CyaSSL_ERR_error_string(unsignedLOCALIT_ERR_error_string_n");
    if (len >= CYASSL_MAX_ERROR_SZ)
        CyaSS


void CyaSSL_ERR_error_string_n(unsigned lonchar* buf, unsigned long len)
{
    CYASSL_ENTER("STATEng errNumber, char* data)
{
    static const char* msg = "Please supply t buffer for error string";

    CYASSL_ENTER("     0;
}


char* CyaSSL_ERR_error_string(unsignedORGnt_write(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_write");
    if (ssloerror == WANT_WRITE)
        return 1;

    ro       ssl->options.saveArrays = 1;
}


/* user doesUNI* NO_Oeed temporary arrays anymore, Free */
void CyaSSL_FreeArrays(CYASSLu* ssl)
{
    if (ssl && ssl->options.handShakeu       ssl->options.saveArrays = 1;
}


pherName0;
}


char* CyaSSL_ERR_error_str to the bufferbufclose notify     InitMd5(&ssl->hashMd5);        r)
        rn ssl;
}


void Cya     = 0YASSL    rite_Ml == NULL)
      buf[_secre] = '\0'NT_END && !verify) ||get_alert_history(CYASSL* ssl,  0;
}


/* returAC_secret;
    elseet;

   secreh) {
   R("CyaSShelloSz, bpyreturaSSL           , aef Hf(RszFlags.h>
f        is null will_error_smallo        ,      responsissl    iSSL_yaSSta, sz, FALSE);
}


#;

    if (ssl->secure_r typeoneg abturn SSL_SUCCESS;
}


/*ASSL_CTX*S */

ifndef NO_DH
/* seCyaSSL_recv())
  sz,return onst WANT_READ)
        return 1;

    returnaSSL_GeMAX_FRAGMENT
    
    retu0;  /* TOelves */

  
    inSL* ssl)
{
    CY HAVE_G.buTAL_ERROR
    ret, 0 return ret;
}
egotiatl;
}


void Cya  if (c DecryptVerify

    if (ssl == NULL
    retNT_END && !verify) ||
   l == NULify
 * it under tcryptVerify cb)
{
        retn;

    rSL* sslL_recv- 1it(); /* usen[urn ssl->Dn sson->cache_st*ctx)
{
    if bufSz;

    return SSL_SUCCE}
#eature_rsioPI int CyaSSL_set_SessionTicket_cb(CYAlse
   own()", ssl->error);

    ssl->error = SSL_ssl)
{
    if ssl->options.acceptState   = ACCEPT_BEGIN;lse
   BAD_FUNigOIDror < 0) {
       _ERRNO_H
 SL_GetClientWriteKey(CYASSL* ssl)
{
 izeof(ssl->msgsReceUCCESS on ok */
int CyaSSL_UseCavium(CYASSL* ssl,ions)
{
    if (YASSL* s   reSfndef NO_DH
/* server Diffie-HeWriteKey(CYASSL* ssl)
{
 nit(); /* user neptStX_free(CYASLL;
}return ssl->*keys.s<RROR_NONE;
  ig.ns, typ   }
    return SSL_SUCCESS;
}


int erify) ||
         (ssl- CyaSSL_GetKeyys.client_wrirn NULL;
}x(CYASSLrn NULL;
}


int    if (ssl_IV;

 n ssl->keys}


intESSION));
    printf("sizeof CYASSL           w     if ( g e, c numb

von if (ctx =binar->sec        if (ss       case\n", siza{
  of(REXTERNA CyaStrinng_n (32))
{
        ss  if (ss   printf("sizeof  XSTRNCPY(buf, ciphers[WriteKey(CYASSL* g;
}
_}


inizeof(ssl->msgsRecei__MORP   if (BAD_OucretYASSL_CTX_new");

    if (initRefCouL* ssl)
{
    if (ssl    if (ssl)
        return ssl->>Dec_free(CYA of the License, or
 * (at your optiG;

   server_write_AM_TYPE;<G;
}


ig;
}
   if (s  = %lu\n", sizeof(CYASSL_SESSION));
     if (ssl)pher_type ==}


int CyaSSLl == NULL)
  l->specs.n ssl->kerBlockSESSION));
    printf("sizeof CYASSL        internal(sspe(CYASSL* ssl)
{dl == NULL)
        retNC_ARo
    if (ssl->specs.cipher_type == block)
        d
#endif

void CyaSS    return ssl->YASSLf (ssl->options.handShakeState != HANDSHAKE_*aead_maSG("quiet shdon = TLif (ssl)L;
}


const byssl == NULL)
       h) {
        *h = ssl->alert_hverG;
 ure renegotiation handshake, user forced, we discourageturn 1;

   FUNC_ARG;

    return ssl->sp CyaSSL_GetKeySize(CY NULL;
}


const byL_ENTE1;

   RG;

    return ssl->specs.block_size;notBefoerWriteKey(CYASSL* s if (ssl->specs.cipher_type == block)
    't have H   return ssl->options.side;

    return BAD_FUNC_e != HANDSHAKE_DONaSSL_GetHm't have HCYASSL* ssl)
{
    /* AEAD ciphers don't Aftl == NULL)
        r (ssl)
        return (ssl->specs.cipher_typeaSSL_ad) ? ssl->specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#endif /* ATOMIC_USEaSSL_ move states in i/* HAVE_SEC
 cb)
{
 x, i (ctx)
        ctx->MacEl->specs.yptCb = cb;
}


void  CyaSSL_SetMcryptCtx(CYASSL* ssl, void *ctx)
{
    if (. Actual>exte BAD_FU dataretul->specs. Requiret CyC_TYPE_e non-  Cya*/
>specs.block_size;
}


ivic    if (ssl)
        reteturn BAD_FUNC_x(&cm->ca)
part oCyaSSL_rec  if (s(ssl == NULL)
        return BADvientWriteSL Inc.
 M_TYPE;
    ifDecryptVeon not for
    ssl == N    oftwSkDecryptVerify cb)
l == NULL)
  l->specs}


int "CyaSSL_CertM  if (s  if (ctx)
        >Decryal(sslAL_ERRORdef HAVE_CRL
     oid  CyaSSL_SetDecryptVerifyCtx(CYAS  if (ctx*ctx)
{
    if (ssll == NULLdef HAVE_CRL
     urn BAD_FUNC_eturn -1;
}


int "CyaSSL_CennReset &&
     ssl)
{
           }
   cryptVerifyIATI>specs.block_size;
}

hw      CyaSSL_CertManagerFree(cm);
    ARG;

    iurn NULL;
        }
    }

    return cm;
}


void Cy   XFRE
#ifndefFree(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER(hwL_CertManagerFree");

    if (cm) {
        #ifdef HAyaSSL_Cer      if (cm->crl)
                FreeCRL(cm->crl, yaSSL_Ce#endif
        #ifdef HAVE_OCSP
            if (cm->ocsp)
                FreeOyaSSL_Ce, 1);
        #endif
        FryaSSL_ble(cm->caTable, CA_TABLE_SIZE, NULL);
        FreeMutex(&cm->caLock);
        
    if (ssl == NULL)
        reurn BAD_FMANAGER);
    }

}


/* Unload the CA signer list */
int CyaSSL_CertMareturn CYASSL_BLOCK_TAs(CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("CyaSSL_CertManagerUnloadCAs");

    if (cm == NULL)
      Sg;
}
Numturn BAD_FUNC_ARG;

    if (LockMutex(&cm->caLock) != 0)
LL_STACK
    return BAD_MUTEX_E;

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, NULL);

  LL_STACK
  ckMutex(&cm->caLock);


    returLL_STACK
ble(cm->caTable, CA_TABLE_SIZE, NULL);
        FreeMu& bufSz > 0))
        re

;

    if (ssl)
    _SUCCd2iPI int CyaSSLManagerFn ssl->specs   if (sl)
{
part o if (ssl->e *newn BAD   ssl->}
    }

    return cm;
}


void2iendif

voFree(Cclose notifyef Himitted by a CYASSL_DTLS
    if (ssl->options.Decoded = T    CYnt_read");
  dtls_expected_           gotiatz + 1k */
int CyaSSL_ CYASSL_DTLS
    if (ssl->options.       (            TAL_ERROR;
    e                   l)
{
    if (ssl)
        return ssl->keys.server_AMIC_TYturn ret;
}


int CyaSSL_peek(CYASSL*d == 0) {
  data, int sz)
{
    CYASSL_ENTER("CyaSSL_peek()ntf(           LL, i,     Fressl)SSL_Ele is_OCSP
        Parse = TRelativeC_TYPE_Sessieithoid  le is ntf("    sizeof MD5 FUNC_ARG;
PI int CyaSSLTAL_ERROR;
    e if (ssl->e) info->consumed = 0;
    der.buffer     = NULL;

    ret      return ret;
}
     fyCtx(CYASSL* ssl,FUNC_ARGInitMd5(&ssl->hashMd5);(info, N secuFUNC_AR,>DecryptVerifSL_read_inteCopy       To           ret  CYAzeof(Encryptens.isClosed && !s;
}

      ret der.length;
        }
        else {
e {
        if (deon not forced C) 2006-2014 wolfSSL Iic License as publisdo aULL, DYNAMIC_TYPffers.serverDH_P.buffe  return SSL_SUCCESS;
}

_TYPE_t's use cavium, SSL_SUCCESS on ok */
int Cy && !verify.acceptState   = ACCEPT_BE*    re     if NULL);
       asswd, (cstates n_freNO_FILESYSTEM return min((STDI((word32)sz, (= CA_TYPE && type != CERTREQ_fp{
               CYASXwordsions;
        return BA*WEBSERVER)

/* ou
#ifdef CYASSL_SMALL_STACK
    inf_fpo = (Encrypteions CYAXBADwordndef NO_SHA
__MORPionsB      )

/* our KeyPemf


#ifte_key;

    reXFSEEKr* peoid  X pas_END        elsbuffSXFTELLr* pete options)
REWINDnt             TLSX* es.citted by a : */
    for (i = 0f (ctell_newwordSL_Ctx(ctx);
    CYASSLon not forced  SendAlert(uff,
            FreeCRL(cm-
voi     return ret;
}
emSz,_OCSP
        uff,
      wn(CYASSL* ssl)
{
    CYase)
{
  G("qu retA buffe
     , 
voi1, ReturfyCtx(CYASSL* ssl, }

->options.isClosed && !FUNC_ARG;
type != CERTREQ_     rL_MSG("Bad pG("quonst unsigned006-2014 wolfSSL I returL_MSG("Bad pER("CyaSSL_KeyPemToDer");

    if 2014 w= NULL)
        return 0;

    XSTRNCPY(passwd, (char*)userdata, sz);
    & bufSz > STRLEN((char*)userdtype = CA_TYPE && type != CERTload= TLSX_UseSe_ionse(&ctx->exte fSL* ss <= format;
   CYASSL_DTLS
    if (ssl->optilags;
      
     z + od frorce heapret;
  */>dtls_expecined(HAVE_WEBSERVERwordnt CyaSk_cip+ 100, MAXed char* buff,
        AVE_WEBSERVEanagerFrs[i dynamieral)
     ifdef pyright (f


# buffSz, , NULL
/* Retu error */
int gotiation                     d    }
    }

    return cm;
}


voi    info->consumendif

voCAVIheckurn BX* ctbuf, ciphef ((ffer s file is  == stream)(NULL;
| burage ILEt;
}
ASN1tifyault_passwd_cb_userdataPEM) CyaSSL_Ge BAD_FUNC_ARG;
}

* pem0;
 egot;
    , "rb      int ty pemSz int pemSz,return BAD_FUNC_ for error r* pass)
{
    int            ec = 0;
    int          t;
    buffer       r;
#ifd> (    co
    eAVE_WEBSERVEstributed in 
    (void)pass;

    CYASSL_ENTER("CyaSSL_KeyPemToDer");

    if (pem == NULL ||CYASSL_ENTER("SSL_CTX_fXFCLOS      NULL;
#else
    EncryptedInfo  info[1]if ( (sslYASSL_SMA1h) {
   ceiveData(sslifdef CYASSL_SMALL) {
            XMEMCPY EncryptedInfo  i SendAl0) {
        CYASSL_MSG("Bad pem der args");
   urn BAD_}
        else {
            CYASSL_MSo senYASSL_ssl->specs.key_L,
                                                G("Bad der length");
   ) {
           .lengder(ssl->o             RR_pRG;

  e_key;

  ULL, ult_partedCurs);
    }
#en     return sslec_SMALL_STAC CYASSL_DTLS
    if (ssl->options.SL_LEAVedInfod cefo                  DYNAMIC_TrrorString(erACK
fo    if (info == NULL)
        return MEMORY_E;
#endif

 data);(rrorString(errTAL_ERROR;
    errorString(erLL;
    info->consumed = 0;
    der.buffer     = NULL;

    ret = PemToDer(pem, pemSz, type, &der, NUL data)n(CYASSL* ssl)
{
    CYASSreturn ret;
}


#endi, NULL,
                                        ata, int sz)
{
    CYASSL_ENTEaveNTRU, ssl->optTER("SSL_pend(ssl SSL_ERf


#ifndef NOL_CTX CYASSL_LEAVE("Cyonneconsume    on->cache_stt < 0emToDerSL_MSG("Bad pem d"Bad Pem To&d          r ce, &ecc NULL, CLIENT
/*part of CyaSSLRenenly time this sh;
#ent Ex, and retve `der`renegoa(CYASSL* ssl)
{T_BEGIN;
  whe    ifBase64TYPE_TM = 1;sLockretu CyaSS(ssl->o`itMutexsl)
        rha    se.
        return (chaRR_print_erCYASSL_MSG("Bad der length"f /* !f


#ifnde                     AD_FU 0;
}


char* CyaSRR_print_errors_fp(FILE      ssl->error = SendAlId = devId;

    return SSL_SUCCESS;
}

 == NU* userdata)
{
    (void)rw;

    if (userdata == ceiveDatapart of CyRR_print_erross;

    CYASSL_ENTER("CyaSSL_KeyPemTosl == NULL)
   ssages for ssl object */
int CyaSSL_se     = 0;sages(CYASSL_MSG("Bad pem= NULL)
       * fp, int errextensioyptVerifyCtx =     DYNAMIC_TYreturn ret;
}


#L)
       return BAD_FUNC_ARG;

    ctx->groupMes/* A    is poifdewebyte CyaSSL_to   uns  if TLSX_UseSe    DERctx, (voEncryptt retd in", sizd      andshake ssages for ssl object */
int CdInfo), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (info == NULL)
        return MEMORY_E;
#endif

    info->set      = 0;
    info->ctx      = NULL;
    info->consumed = 0;
    der.buffer     = NULL;

    ret = PemToDer(pem, pemSz, type, &der, NULL, inate   = ACCEPCYASSL* ssl, copart of CyaSSLo, NULL, DYNAMIC_TYPE_YASSL_MSG("B* fp, int endif

    if (re (ret < 0) {
        CYASSL_MSG("Bad Pem To Der");
    }
    else {
     byt   #endr.length <= (word32)buffSz) {
            ;
    info->consumed = 0;
    der.buffer     = NULL;

    ret   ret = PemToDer(peSL_EXTRA) || defined(HA_MD5
    InitMd5(&ssl->hashMd5); length");
      nagerF = BAD_FUNC_ARG;
   
        }
    }

    XFRE  CYASSer, NULL, DYNAMIC_TYPE_KEY);

   O_OLD_TLS
nagerF

#if defined(OPENSSL_EXTRA) || defined(HAVE_Wbyte haveRS
/* our KeyPemToDer pa006-2014 wolfSSL Ir password callback,  if (ssl)
  ata */
static INLINE int Ou        ssl->options.minDowngrade = TLsz, int rw, void* userdata)
{
    (void)rw;

    if       CYASSL_MSG("B         broup_messages(CYASSL* ssl)
{
    if (ssl == NULL)");
      aSSL_GetY_E;
#endif

    iet      = 0;
      ssl->secure_renegotia|| ;
    }

    ASSL* sslin internal.h */

THOD* metho), 0ctx == NureRenegoti    = idx,ASSL_CTX));
#if defineFORTRESSnagerFreesslan error if cax < MAX_EX_DATte havepart of Cyextenctx == [idxn ssure renegotiat   printf("sizeof CYASSL  dtls_expecCC_SECPsl_CLIENx == Nirror == se secure resl->optionsPLEMENTED;
#eILURE
    rdef NO_RSA
    _ARG;
    }

    return T0;
    _SetOptions(CYASSL_CTXer = (byte*)XMALLOC(gSz, ssl->ctx->heap,
     pe");
                ssl->options.aveNTRU, ssl_SECP224RD_FUNC_ARGIATItx, int devI), 0conn    IENT
iureRenegotiat|| !defined(NO_SESSIOSz, li    by*/
#ifdef*/
lbackMacEnTHOD* methoSSL* hutdownyaSSL_read_inMakeWordFromH        extenop    s.isClosed e == stream)
      hashID[3];tatiRe_CYA /* !NO_CERTS || !NO_SESSIONsentNotify)     ssl->options.hRG;
  reus return T2] <<  8) |
           hashID[3];resumingY_E;
#_ARG;
    }

    #iftx, int devI;
    }
SSL_{
      ;
    }Sz)
RG;
 ordFromHash(conSIZE;
nt o
}
#endi;
    der.bu) | (hashID1;

    returnMakeWordFromHnsions);

    if (ret )
        r  TLSX* exten1;

   .majo.lengSSLv3_MAJOR+ 1];

    C if (ctx
    int     rinor is want write */
int    worINOR = 0;
    int  step        if v3"R_error_string(unsiTLSv1       return  ret;
    signers =ile (caTable[row];
    while (s(signers) {
        byte* subjectHash;
.
        #ifndef NO_SKID
  2         subjectHash = signers->subject2caTable[row];
 l->options.side == CYASSLigners =unknowncaTable[row  switchlength;
          int     ret = 0;
DTLSord32  row = HashSigner(hash);

    if (LockMutex(&cm->caLock) !=           return  ret;
    signers =    caTable[row];
    wh    
            subjectHash = signers->sA if ftNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SHA_DIGEST_SIZECMP(hash, subjectH} << 24) | (hashIDcurrent_ftware_suiE word32 MakeWordFromHnsions);

    if (ret ners;
    word32  ro      int tyotiation( |
            hashID[3];ftwareS  ro0 << 8) ||| !NO_SESSION_ return rek from the front ofturn TLS      */
int Alreaners;
    wordw = HashSigner(hash);

    if (cm == NULL)
        retur;

    if (LockMutex(&cm->caLockE_RENEaTable* signL_SESSION   =info->ctx)
  IATIigner list */
int A       enego== N= %lu\n", siz      byaTableordFromHash(co subjecthash);

    if (cm == N   if (XMEMCMP(
#ifeturn min((


in_STRINGePSK = ssl_DIGEST if deion->dataHAVE_CHACyte havePSK ners->next-> != 0)
        return ret;== ex(&cm_BYTz, unsigned cwd_cbaCha 2  rowill not 
    if (ctx  return ret;
}


#ifndef NO_SKI;
    }_freckMutex(&cm       }
   RS

    [row];
    while_ECDHEMANA_WITHtex(&cm20ion Y1305f(Sha25s) {
        byte* subjectHashT_MANAGER*)vp;
    Signer* ret = NULL;
 ">heap, DYNAMIC_TYPE_d32 ANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32 ow;

    if (cm == NULL)
        return CYASSL* ssl, co (CYASSL_CERT_MANAGECDR*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row;
        while (signers && ret == NU
        signers = cm-
#include <cyassl/* ssl)
{
    ickMutECCtension->datackMutAESCCM  return S>optwkwardTX_U  ifECCA_DIGESLL. WalkseSN }
     CA i asNI(Cecteer = (byte*)   r    ssl =-CCMUnLockMutex(&cmalsom->cait, evtOnly  ones trun
#endif


/*are    ECCandshake grou

    return ret;
}


#ifndef NO_SKID
/* );

    f found, otherw   UL. Walk through hash table. */
Signer* GetCAByName(void* vp, byte* hash)
{ECCYASSL_CERT_MANAGER* cm = (CYASSL_CERT_MANAGER*)vp;
 l = (CYASSL*ULL;
    Signer* signers;
    word32  row;

    if (   row;
    byte* 
        signers = cm->caTable[row];
        whi   row;
    byte*       subjectHash;
#ifdef CYASSL_SMALt[1];
#endif

    CYASSL_MSG(
   SSL_CERT_MANAGER* cm = (CYASSL_CERT_MAN word32      row;
    byte*       subjectHash;
#ifdef CYASSL_SMLL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  c_STACK
    cert = (DecodedCert                     DYNAMIC_TYPE_TMSTACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
      ALL_STACK
    Dsl)
                subjectHash;
#ifdef CYASSL_SMALL_STACK
    Dfndef NO_SKID
rt = NULL;
#else
    DecodedCert  cert[1];
#endif

 fndef NO_SKID
    subjectHash = cert->extSubjKeyId;== 0 && cert->isCA == 0 && ty*)XMALLOC(sizeof(DecodedCert), NULL,
                    fndef NO_SKID
    subjectHash = cert->extSubjKeyI;
#else
    subjectHash = cert->subjectHash;
#endif

    if (reSL_MSG("    Can't add as CA ifder.buffer, der.length, cm->heap);
    ret = ParseCt add as CA if not actually S CYASSL_CERT_MANAGER* cm = (CYASSL_CERT_MANAGER*)vp;
    row;
    byt      subjectHash;
#ifdef CYASSL_SMALL_STACK
    DecodedCert*caTable[row];
    whilejKeyId;
#else
    subjectHash =    subjectHash = cert->extSubjKeyId;
#else
    subjectHash =rt = NULL;
#else
    DecodedCert  cert[1];
#endif

    CYASSL_M"Adding a CA");

#ifdef CYASSL_SMALL_STACK
    cert = (DecodedCsage certificate signing");
  {
        /* Intermediate pe != CYASSL_USER_CA) {
        CYASSL_MSG("    Can't add as CA*)XMALLOC(sizeoC    = , verify, cm);
    CYASSL_MSG("    Parsed new CA");DTLS(CYAROR;
    }
#endif
    else if (ret == 0 && AlreadyOID;
     caTable      signers = cm->caTable[row];
        whiyOID;
            signer->publicKey      = cert-Size;
            sign
        sMALLOC(sizeDES3u\n", siL_CERT_MANAGER* cm = (CYASSL_CERT_MANAGER*)vp;
 3TLS
   CA_ERROR;
    }
#endif
    else if (ret == 0 && Alread       signer->p    signer->pubKeySize     = cert->pubKeySize;
            signer->permittedNames = cert->permittedNames; #endif
        #ifndef NO_
        sXMALLOC(sizeof(DecodedCert), NULL,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (cert sage certificate signing");
       ret = NOT_CA_ERROR;
    }
#endif
    else if (ret ==  && AlreadySigner(cm, subjectHash)) {
        CYASSL_MSG("   Already have this CA, not adding again");
        (void)ret;
   }
    else if (ret == 0) {
        /* take over signr parts */
        signer = MakeSigner(cm->heap);
        if (signer)
            ret = MEMORY_ERROR;
        else {
            signer->keyOID        = cert->keyOID;
            signer->publicKey      = cer->publicKey;
            signer->pubKeySize     = cert->pubKLen;
            signerUsage not set, all uses valid. */
            c     signer->name           = cert->subjectCN;
        #ifndef IGNORE_NAME_CONSTRINTS
            signer->permittedNames = cert->permittedName;
            signer->excludedNames  = cert->excludedNames;
     jectKeyIdHash, cert->extSubjUsage not set, all uses valid. */
            ch, cert->extSubjKeyId,
   #endif

    inHYASSL*yte* hash)
{AESGCME, verify, cm);
    CYASSL_MSG("    Parsed new CA");

#i(CYAGCM byte*       subjectHash;
#ifdef CYASSL_SMALL_STACK
    Decod->caCacheCsage certificate signing");
        ret = NOT_C->caCacID
    subjectHash = cert->extSubjKeyId;
#else
    subjec Mutex Locrt = NULL;
#else
    DecodedCert  cert[1];
#endif

    C->caCacheCallback(der.buffer, (int)der.length,     }
        }
    }

    CY {
        /* take over signer parts */
        s Mutex Lock failed");
                ret = BADE(cert, NULL, DYNAMIC_TYPE_TM*)XMALLOC(sizeof(DecodedCert), NULL,
                        ->caCacheCallback(der.buffer, (int)der.length type);
            }
            else {
               CYASSL_MSG("    CA Mutex Lock failed");
                ret = BD_MUTEX_E;
                FreeSigner(signer, cm->heap);
         FreeDecodedCert(cert);
#ifdKeyUsage
                                              eturn ret == 0 ? SSL_SUCCESS : ret;
}

E(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    CYASSL_MSG("   Freeing der CA");
    XFREE(der.                  int   Mutex(&cm->caLock);
C               if (cm->caCacheCallback)on set. User loadeCM_8   Signer* signers;
    word32 oad,
       allows ovesage certificate signingROR;
    }
#ifndef over 13,000 new sessions per minute or over 200SESSION_C->name           = cePS = MakeTLSv1_1 (LockMutPSK,
       allows over 13,000 new sessions per minuty 3kB is too much RAM,sage certificate signingy 3kB is too SESSION_CACHE only stores 6 sessions, goE stores 33 sessions (    default SESSION_CACHE stores 33 sllows o this define
       uses less than 500 bytes RAM

     default SESSION_CACHE stores 33 sessionsno XXX_SESSION_CACHE defined)
    */
    #ifdef HUGsage certificate signingsed efine SESSIONS_PER_ROW 11
        #define SESSION_R_SESSION_CACHE)
            #elif defined(MEDIUM_SESSION_CACHE)
 fine SESSIONS_PER_ROW 7
        #definMALL_SESSION_CACHE)
    ->name       {
    int            /* take over signer parts */
     llows oveAdding a CA");

#ifdef CYASSL_SMALL_STACK
    cert = (DeUGE_SESSION_CACHE
        #dsigner parts */
        si over 13,000 new sessions per minut              /* where to plac */
            URE;
#else
    (void)s
        if (XMEMCMP(hashNONEctHash, SHA_DIGESude <cyassl/s */
int  during verify
   don't allow chain ones to be ad!ed w/o isCn 2 of the Licen. */
Signer* GetCAByName(void* v;

  return CA if foL_FAILURE;

    nULL;l AddCA(CYASSL_CERT_MANAGER* cm, buffer der, int type, int verify)
L_CERT_MANAGRY_ERROR;
        else {
     iredx(&cm->caLock) != 0)= cert->keyOID;
            signer->publicKey   x;            /* Session    signer->pubKey;          MD5   word16 serverIdx;            /* SessMD5 return  ret;
    signers = cmdx;                /*    signer->puame           = ce      wo       = cert->subjerd16 serverIdx;                  signer->permittedNames = cert->permiion Clients[SESSIONS_PER_ROW]    signer->pubKeySize     = cert->on set. User loaded root certs are not. */
        CYAS   XMEMCPY(signer->subjectNameHash, cert->subjec      ret = NOT_CA_ERROR;
    }
#endif
    else if (ret&& AlreadySigner(cm, subjectHash)) {
        CYASSL_MSGword32      row;
    byte*       subjectHash;
#ifdef CYASSL_STACK
    DecodedCert* cert 
    #endif  /* NO_CLIENT_CACHE */

#endif /*def __MORPHOS__
    if(!SysBase)
         SysBa */
#endif

      sign#else
     BLAKE    printf    CYASSL_ENTER("CyaSSL_Init");

B2B256__MORPHOS__
    if(!SysBase)
         SysBase = *(s
#endiExecBase **)4L; /* tricky...but works */
#end
#endif
        if (InitMutex(&count_mutex) != 0)= SSL_SUCCESS)Count;          */
            word16 serverIde)
         S
     /* NO_SESSION_CACHE */

int CyaSSL_Init(voD_MUTEX_et = SSL_SUCCESS;
    CYASSL_ENTER("CyaSD_MUTEX_def __MORPHOS__
    if(!SysBase)
         S ret;
}


#
        

    iRSYASSLr systems whereBad Lock Mutex count");
            y 3kB is too much row];
                cm->caTable[row = "-----END CERTIFICATE    default SESSION_CACHE stores 33 sessioFICATE-----";
static const char* BEGIN_CERT_REQ   ner(cm, subjectHash))Bad Lock Mutex256ar* END_CERT           = "-----END CERTIFICATE
       MEDIUM_SESSION_CACHE allow---BEGIN DH PARAMETERS-----    default SESSION_CACHE stores  ret;
}


#ifndef NO_CERTS

static const const char* BEGIN_X50    #elif defined(MEDIUM_SESSION_CACHE)
         byte*       subjectHash;
#ifdef CYASS   = "-----END X509 CRL-----";
    #elif defined(MEDIUM_SESSION_CACH ret;
}


#ifndef NO_CERTS

static const ct char* END_RSA_PRIV      if (InitMutex(&se);
     the default of nearly 3kB is too much->caCacheCallback(der.buffer, (int)der.le----";
static const char* E    #elif defined(MEDIUM_SESSION_CACHE)
     ->caCacheCallback(der.buffer, (int)der.le_KEY = "-----BEGIN ENCRYPTED PRCount;             /* sesizeof SHA384       = %lu\ICATE REQUEST-----";
static const chaKeyUsage & KEYUSE_KEY_CERT_SIGN) =RIV      = "-----BEGIN EC PRAMETERS-----";
static const char* BEGIN_C PRIVATE KEY-----";
static const char* ENDtatic const 211
    #elif defined(SMALL_SESSION_CACHE)
   NO_SKID
    subjectHash = cert->extSubj char* END_DSA_PRIV       = "--E KEY-----";
static const char* END_RSA_PRIV "-----END DSA PRIVATE KEY-----";

/* Remove PEMDSA PRIVATE KEY---_PRIV_KEY     = "-----BEGIN PRIVATE KEY-----";
staticYNAMIC_TYPE_TMP_BUFFER);
#endif
    CYASSL_MSf, long longSz, int type,
  211
    #elif defined(SMALL_SESSION_CACHE)
  Mutex Lock failed");
                retconst char* header      = NULL;Count;             /* sessions ever on tS-----";
static const char* BEGIN_9_CRL     = "-----BEGIN X509 CRL-----";
static c */
                UnLPSKERTIFICATE-----ANAGER* cm = (CYASSL_CERT                   cmRL-----";
static const char* BEGIN_RSA_PRIV          SysBase = *(struct ExecBase **)4L; /* tricksed new CA");

#ifndef NO_SKrn ret;

    for (row = 0; row < CA_TABLE_SIZE SSION_CACHE
        iBad Lock Mutex count");
            ension set. User loaded root certs are not. */
        CYAS_MSG("    Doesn't have key usage certificate signing;
        ret = NOT_CA_ERROR;
    }
#endif
    else if (ret= 0 && AlreadySigner(cm, subjectHash))Bad Lock MuHC128struct ClientRow {
            int nee)
         SHC      /* where to place next one   pe) {
		case CA_TYPE:       typedef struct ClientRowtex count");
            return BACA_TYPE /* NO_SESSION_CACHE */

int CyaSSL_Init(voE:  dynami     typedef struct CMutex(&session_mutex) != 0)
            ret = CA_TYPE
#endif
        if (InitMutex(&count_mutex) !
	for (;;) {
Count;             /

    iter= ERTIFICATE-----ver on this row */
RABBITecBase **)4L; /* tricky...but wf (heanamicType = DYNAMIC_TYPE_CRL;  break;
		defa            dynamicType = DYNAMIC_TYPE_KNTRU----BEGINRY_ERROR;
        e default of nearlGIN_= cert->keyOID;
            signer->publicKey      =NC_PRIV_KEY;   footer = EExecBase **CYASSL* ssl, cohis row */
            ClientSessf (header == BEGIN       signer->permittedNames = cert->permitted_PRIV;
		} else if (header == EY) {
			       header =  er =  BEGIN_ENC_PRIV_KEY;           SHA_DIGEST_SIZE);
        #endif
    
	}

    if (!headerEnd) {
  ExecBase **)4L; /* trick
	}

    if (!headc const char* END_CERT_REQ       = "-----E}

    headerEnd += XSTRLEN(h    signer->p    HUGE_GIN_   inf        UnLockMuteUCCESS;
    CYASSL_ENTER("CyaSSL_Init"->caCacheCallback(der.buffer, (int)der.letype);
            }
            else {
           YASSL_MSG("    CA Mutex Lock failed");
                ret_MUTEX_E;
                FreeN_X509_CRL; footer= END_X509_CRL; break;
	CRYPTED PRIVATE KEY-----";
static const char*type);
            }
            else {
              CYASSL_MSG("    CA Mutex Lock failed");
                ret BAD_MUTEX_E;
                FreeSe = DYNAMIC_TYPE_CERT; break;
		case CRL_TYPCAMELLIA                                              /* use    if (!start)
	   ExecBase **)4L; /* tricky...but w    if (!

#endif /* NO_SESSION_CACHE */

int CyaSSL_Init(voLE;
	        if (!inet = SSL_SUCCESS;
    CYASSL_ENTER("CyaS    if (!start)
	          return SSL_BAD_FILE;

	if (type == P && finish && (start <     if (!start) return SSL_BAD_FILE;
	        if (!in < finish)) {
	            newline = XSTRNSTR(finishcase CRL_TYPE:      header= BEGIN_X509_CRL; footer= END_X509_CRL;     if (!start)
	            start = XSTRNSTR(line,eof(info->iv));

	            if R)
	{
	    /* remove encrypted headerLE;
	        if (!info)  return SSL_BAD_FILE;

	   newline > finish)) {
	           
        signers = cm->caTable[eof(info->iv));

	            if rn ret;

    for (row = 0; row < CA_TABLE_SIZE &R(finish, "\r", PEM_LINE_LEN);

	            Xnewline > finish)) {
	                 return SSL_BAD_FILE;
	        }
	        else
	   case CRL_TYPE:    = "-----BEGIN CERTIFIC_freBUILD_      _anon if (!headerEnd) {
  
	{
	    /* remove encryif /* OPENSSL_EXTRA || HAV     info->ivSz = (word32)(newlinif /* OPENSSL_EXTRA || HAV
        signers = cm- */
        CYASSL_SESSION Sessions[SESSIONS_PER_eerSz)if (ct_free", 0);
CACHE

     /w;

    stat<cyassl/ssl.        signers nsumedEnN Sessions[SESSh;
        #endif
     jectH     #ifndef NO_SKID
            subjecif (consumedEnd[0
#ifndef       f
        if (XMEMCMP(hte* subjectHash;
        #otia digesnst byte* hash)
{
   ;
  #endif
        if (descrihID[3eturn TLSsh, SHA_DIGESssl)
{
    if (sRTS) || !defined( subjectHashoptions(CYASSLake a work from the front of hash) % CA_TABLEif (consum1just useword32 MakeWo  retuhat's refert his*/rdFromHash(const byte* the front of random hash _SUCCHash(hash) %if (ssbufordFromHash(cobuff lineretuasCTX_nt CyaSS*/
/*  retuegotiatiHash(SSL_CT
    if (!der->buffer)
	ype !THOD* methoOCSP_p) {
_urlyptVer ur);

extenshoOS__, der->    er,
      asions)
        TLSX_SNI      eWordFromHash(cour  ssl->optionbuffbuffer */
           return Sa   returLE;

	der->buffer = (byte*)XMhope thaETHODrEnd);
 v2_shID)
_methodx == NU8) |
         {
        /* pkcs8 key, converserveradjust length */
        if ((ret t ClientRow {4f random hash MD12));
#hope thaD    pr md4h */
   /* m* dasecBawe   unsi bigE_SNI

i       d[1] ==rsio_freER("Sok[_TMP_BUmd4->      ) >=>extensiMd4 letc Li-   if (ix == N>extensiokgroupMes;

    if (ini = ret;

#ifndefntf(Md4(== B*)
   nt of random hash retuCYASSL_CTX    return 0;
  zeof(CYASSL_CTX));
#endif

    return sizeo;
}
#endif


#e");
        retur#ifdef CYASmeters, SSL_SUMd4t unsigne passwo
        *data        xtensions,rd = NULL;
	#else
     rn MEMCyaSSL_read_inte  prioptions);return 0;
    }

#if        return SSL    DYNAMIC_TMd4rn MEMck error */_TYPE_se
    lse if (headMD4type != CA_TYBIOrEnd);
  BIO_poA || HAVEof(patopordFromHash(cotop->buffer = (byte*)XMTHOD* metho, 0,
lse ng             bio  if (!der->bufio->buffer = (byte*)XMrd, sizeof( pkcs8 key, conctx->s_memlength */
          TraditionalEnc(de djus        ret = signers, der->le
#ifndefdjus.lse
   onalEnMORYNULL);
       &CYASSL        /* onalEnc(der->buffer, def_b= 0;
length */
        if ((ret tx, int devI, deret_* Seca);
        /* c    = N Securvert and adjust lengtion, we disco = Tote type, const voscreenlength */ line */
        if (con= devionsMCMP(haer.buffer   nfo->ctx->passwd_cb)
    ion, we("Can't reake a work from the front of ctx->devId = devurn Bed = 0;
    der.buffer ocess the buffdshake */
sssBuffer(CYASSL_CTX* ctx, cons    id = 0;
    der.buffer   to pass during the handshake */
sCAVIUM */

#ifdef HAVE_SNI

i== NULLyaSSL_UseSNIoraSSL_ re    mf (ctLS
        cef HA= -RPOSE.  See       10if

#ifn = signers->subjectNG("qu_SECPYASSL_CTX* ctx, conseg* data,  a use   iocess the buff   if (heah */
		ret = ToTraditiCOMPlEnc(der->buffer#ifdezliblength */
        if ((ret = ToTra#ifdef CYASSL_SMALL_STACKrlword32h */
        if ((ret     return Bifdead }

mprst use djust lP384Rjust     #ifndef NO_P        defjust aveNTRU, ssl->opti= ctx ? ctx->heap :< 24) | (hashIDex_new_indexC_TYPdif
    #ifndef     #ifncb1SL_FILETYP2 info->consumed = 0;
    de_FILETYP3ocess the buffs.haveNTRU, ssl->optiar*)buff);
bet = de SSL_BADABILITY SSL_BAD3k from the front of random hash */
sdyntx->_cresume    back        FUNC_ARGvalue* (*f)l->rflags;

    ssl->rflags = flags;
   ENT */
#endif /* HAVE_SUPPORTED    =)               L)
        return BAD_FUNC_ARGC_ARG;f (type 0;
}


char* Ctx, inamicin_TMP_BUFFEYPE)
        d;

    rynamicType = DYNAMIC_TYPE_CERT;
    else
        dynamicdestroy = DYNAMIC_TYPE_KEY;

#i;

#ifdef CYASSLL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedI        #endif
     turn 1;
ify= TLSUseSuppLIENT E_ASN1erST_SIZE) == 0) erectHashy shorten*/

    if (forma_SUCCLOOKU)rsaKedi == NULL)
    0;

  * lookupEncryptedInfo dir info->consumed = 0;
    der.buffto pass during the hanPEM) {return SSL_Bdi /* set up deint ProcessBuffer(CYASSL_CTX* ctx,   = 0;

   SL* ssl,
 mat == SSL_FILETYPE_PEM) {
 of the License, or
 * (at your op;
    der.buf
{
  , info, &eccKey);
        if (ret < 0) {N

/* user */
    neededSz = (long)(footerEnd    = 0;

   Enc(der->buffer   = 0;

   "    (for#endif

    (void)dynamicTinfo->consumed;

        /* we may have a userd = 0#endif

    (void)dynamicT     if (userChain cs.block_size;STORErsaKePEM) {IC_TYPE_TMP_B byte*/
     info->consumed = 0;
    der.buffer     = NULL;

info->consumed;

        /*mordFromHash(con    return SSL_Bfault:
MALL_STACK
            XFREE(i byte   st  ssffer[1];                 /  ret = CyaSSL_rea  }

}


/* Hashl    ASSL* ssl)
{
    if (syaSSL_GetServerWriteIV(CYA chainBuffer =;

    if (Lo     lose notifyicBuf->cmfer */
     
    InitMd5(&ssl->hashM     returATION);
          if (ssl->o       FreeCRL(cm->crl, 1)ULL)
        info->consumed = 0;
    der.buffer     = NULL;

    n)
{
    CYASSL_ENTER("CyaSSL_SetMinVersiaticBuffer);InitMd5(&ssl->hashMd5);sumed = info->    FreeOCSULL)
        return BAs->next;
   ddCA()    iom ue word32andshake group me       CYAS if (ssl->o  #endif
            XFREE(der.bufARG;

    if (ssl->o      FreeULL)
       L_Ctx(ctx);
    C shrink             in_FUNC = T  byte*  US CYAAfndef NO_OLD_TLS
 urn BA shrisswd_cbif

CYA if  shrinked to size chainB               DYNAMItate = NULL_STATE;
    ssl               ,ef CYASf (consumedEndf CYASsed = info->consum       NAMIC_TYPE_TMP_BUFnewnsumed < sz) fer[1];                 G;
    }

#ifdEMORY_E;ffer[1];           word32)buffSz) {
          (der.b        return BAstaticBuffer */
  row = HashSi      intSMALL_STA = TManagerNew(
        TLSX* e          ngth <= (word32)buffSz) 
}

              CYASSL_Chain");
    ase CYASSL_TLSV1:  switch (vertatic INtmp ch*)XMALLOC(neededSz, h byte eap, dynamicType               }

}


SG("Processing Cert Chain");           int    dyn  return S while (consumed <do a     buffete options)
nfo->consumed = 0;
       }if
            byte*  chainC_SECP256R1:   idif

    &part,
                  ];  /* tmp chain    printf("sizeof CYf
            byte*  chainse Cby_WRITE)
, type, &part,
   SSL_ECC_SECP384if
  of the License, or
 * (at yoMacEncryptCtx(CYASSL* ssfferSz) {
  OBJECT* obj (char*)buff);
1:
     SL_FILETYPE_RAW)
    shake */
static obj            *used = info->consum           onsumed, sz - consASSLType);
                    returnLSX_UseSu }
                dyndef NAL_ERROR of the License, or
 * (at your optior = 1;
            }

  ,par          CYA= signers-txeap, info, &eccKey);
       if (used)
 _  inERROR;     r                  o call Inithan buffer");
                      = BUFFER_E;
                     staticBuffer;
            byte*  shrinked  , (ssl-_OF{
           * skordFromHash(conRR_erro         *used +MSG("Secure ok * part.bu tmp chain  WITHOUT Aers;
         defaulof MD5       doma>Decron not forced ;
    tx ==        CYASSL_MSG("   t n)Ct enough to get pee;
    
        SSL_set_samicBuffer_dept err)
{ 0) {
        iscardSSIZE;
 = Tl->chainBuffer,   printf("sizeof CYASSL  return SSL_SUCCESS;
}


int (buff + consumed, sz - cons    umed, type, &part,
   ECP160R1:
           ok");
                 er, ssl->"Processing CetTmpDH(CYASSL* ssl, , sz - consumed,   break;
type, &der, NULL                iate   = ACCEPT_BEGIN;}


/* do a secu       CYASSL_MSG {
                }
       = 1;
         nfo, NULL, DYNAMIC_TYPE_TMPtedHMAC(ER);
                #endif
              cas
            XFREE(i->set       retain actual size used */
                     X   ifheap, dynamicType        if (ss  int    dynType = DYNAMIC_TYPE_CA;
    else if (type == C       i  CYASSL_MSG("   ConsSSL_SUCCESS;
}


# while (consumed <V>set 
                PE_FICURE_RENEGOTIATION */
                /
               ssl->buffers.certChain.buffer, heap,
           info->consumed;
            d_cb_userdata(inf* ssl)
{
TACK
                    XFREE(ih>
#inclSN1_TIef NO_FORCE_SCR_CRonsumeeof(CYASSL_CTX     = idx;
* crWordFromHash(coc->length     if ((ret = ToTras.certChain.length = idx;
     ;
             XMEMCPY(ssl->buffers.certChain.buffer, chainBuffer,id->bufferuncaPKEYcs.block_size;
}

pubkey || HAVE_WEBSked    = NULL    if (ctx->certThis m)
{
    CYASSL
    InitMd5(&ssl->hashM, heap= NULL;

   ->cer          consumed  += info->cffSz) {
      uffer =         return ret;
}
PUBLIC   i);

    if (pemThisInitMd5(&ssl->hashMd5);key->return ssl->kpubKey.clieBuffer, idx);
   sav    if);
           idx);
   pkey.pt);
  ptVerifyCb = c #ifndef NO_OLD_TLS
        c  }
    _ARG;
    }

                   XMEMCPY(ctx->certurn (char*)      XFREE(bject */
int CyaSSL_set_group_meeral ed == NULL) {
            #ifdef CYASSL_SMALs = 1;

    return SSL_SUEncryptedInfo), NUL    = 0ACK
          info->consumed = 0;
    der.buffer            if        chainB     if (shri= NULL)
       ACK
     _buffS           if (shri     }

       #else
        #define SESSI    der.buffercurv  }
 ("quiet shpkCdef         }

      s

       HUGE_SESSIONERT_MANAGER*)vp;
    Signerkeynked = (byte*)XMALLOC(x;
 ->set  retain actuassl->buf2to24(parain.buffer, hfers.certChain.buffer, nsumedif
  buffer = (byte*)XMALLOC(neededSz, hC_TYPE_TMP      (ctx= BUFFER_E;
                         = ctx;
    i               nfo->ing Cert Chain");

  gth, &ASSL_C

   ntbufferSz) {
  gth, &chainBuffer[idx]);

    ing Cert Chain")uffer = P_BUFFER);
  r.buffer, buff, sz);
Chain.buffer, chainBuffer, L_STACK
          return ssl->specs.key_MIC_TYPE   return Med = 0;
              byte   gotOne = 1;
                    if ( cmptHash;
  optihash, subjectHs.certChainasnTi                FFER);
 ProcessBuffer(CYASSL_CTX* ctx,skEMCPY(REVOKEDf (sVE_WEBSERVER)        retvokedif

    nsumed       x) {
                    if               .length = idx;
                 XMEMCPY(ssl->buffers.certChain.buffer, chainBuffer,idx);
      = (byte*)XMALLOC(ANULL,
                 consumed  += info->consumed;
                                       =               DYNAMIC_TYPE_TMP_Bnsumed     x) {
                    if s.cerINTEG  byte* subL* ssl)
{
    iN(ssl == NULL)
        rocess the buff(ret < 0) (void)dynamicType;
    (vs.certCha_prilse if (ssreturn 0;
ULL, DYNAMIC_TYPE_TMP_BUFFER);
        key   er buff, legnth   = (byte*)XMALLOC(AES_256       }
        );
    har*NULL, DYNAMIC_TYPE_);
      RVER_END)
        return SIDE_Eswd_cb(password, sizeof(pasb        key    return SSL_Bbrd32)sz;
    }

#if }

    returwordSz = ctx-geNI_SetOpE_TMP_BUFFER);
      imat != SSL_FILEain may shorten*/

  SSL_CTonsumed;
             t != SS haveRSA = d;
                       }
 NO_PSK
        havePSK = ssl {
            SK;
SL_GetDecryptVo call Init z)
    ->dtls_expec* decrypt */
        s.havons.haveECDSAsig,
ynamicType;
    (v>ivSz)
    d;
              dx     der->length = ret;
        */
int Alreaz)
     ) | (hashID[2] <<                                     ->options.havePSK;
    #endif

    Ini*/
static INLINEites, ssl->v        }
            ssl->options.havEVP_BytesToKey(info->name  case CYASSL_ECC_SEr ce if (type == CA_T          fdef CYASS#endi       /* decrypt */
        _CERT;
ARG;
    }

    return TLpeekif (ctx == NU

    (void)dynamicType;
    (vd)
{GET_REASON          = ctx;
    info->consumed = 0;
    FILE;
    }

al   =rsio   info_f


     gth,
ID        key          y(der.buffer, der.buffer, der.length,
 (inf                                                            key, info->iv);
  runca             (CYASSL_CERT_MANAGELE;

	der->buffer = (byte*)XMTHOD* methoPEMECP2 = DYNAMIC a usefer     = nr arowngr    #ifnbuff, sz);
      shake */
static nufault:
      wer.length = (word32)sz;
    }

#if :
        case CYASSLaccepreturn TLSX_UseSu       /* decrypt */
  nfo->name, "AES-192-CBC", 13) == 0)tatic I             ret = AesCbcDecryptWithKey(der.buffer, der.buffer, der.length {
   _goocase CYASSL_ECC_S = AesCbcDecryptWithKey(der.buffer, der.buffer, der.length,
             }
            else if (XSTRNCMP(info->name, "AES-256-CBC", 13) == 0) {
;
     renegotiSSL_CTX             else if (XSTRNCMP(info->name, "AES-256-CBC", 13) == 0) {
                                         key, AES_256_KEY_SIZE, info->iv);
            }
    hi        ch         else if (XSTRNCMP(info->name, "AES-256-CBC", 13) == 0) {
 bL_SMALL_STACK
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFSECP3L_SULL_STACK
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XmisseALL_STACK
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XoptiouMALL_STACK
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        X (ssl == NULL)         else if (XSTRNCMP(info->name, "AES-2ons);
}

void Cy), 0, DYuncb(in return TLSX_UseSNI(&ctx->exvoid*** force heap usage */
        #else
            byte   O_CYASSL_SERVER

vbuff, sz);
      SX_SNI_.length = (wordfdef CYASSL_SMALL_STACK
oddrEndit;
       IC_TYPE_TMP_BUFFE CYASSL_MSG("Need confdef CYASSL_SMALL_STecbL_CTX_SNIheap, dynamicType);desRVER_END)
       AddCA(ctx->cm, der, Cboptions);
}

LL) {
           umedEnd - (char*)buff);, CY (ret < 0) {
es;

    gth = (word32)s#ifdef CYASL;
    Signer*, 0,
   # {
            if (!ctx | a userULL;
, ...ocess the buffer buff, legnth ULL;
  ret = MEMORY_E;
        }
        UTCelse
    #endif
        if (!ctx || !ctx->passtificat*   /* used bytesNO_PASSWORD;
   , der.buffer, der.length       if (                                     DYNAMIC_rd32)sz;
    }

#if defi        if (ULL ||                              } {
            if (ctx-if (Base16_Decode(info->iv, */
 unnel 4.28f (ssl)*/ info->ivSz, info->ivSz)
     ash, subjectHa                       DYNAM               E_TMP_BUFFER);
          return BAD_FUNCz)
            = PRIVATEKEY_TY    #ifn               if (ssl) {
                  rd32)sz;
    ain bigger than b  case CYASSL_ECC_ssTACK
jectHbeturn TLSX_UseSupportedCurve(&ssl->exthash) % CA_TABL  DYNAMIC_T*rs.serverDH_G.bu     cSize(      key, info->iv);
            }
 s.key = der;
            L_FI>buffers.weOwnKey = 1;
        }
       || buffSz <= {
            hash) % CA_TABLr)
                XFREE(ctx->privateKey.buffer, heap, dynamicASSL_CL>buffers.weOwnKey =        DYNAMIC_TY= PR"CyaSSL_SetVersion");

    if (ssl == NULL) {
        CYAS     }
    }
    else {
        XFREE(der.buffer, heTHOD* methoi2d_h) % CA_TAB(hash) % CA_TABLE_SIZrs.serverDH_G.bu  XFREE(ssl->buff    heap, dynamicType);
      ffSz) {
      ;
    }rd = NUterEnd - headerEnd);
  conscan be used */
             word32 of the License, or
 * (at your oNTER("CyaSSL_read_in* pcType);, heap, dynamicf (ret < 0) {se16_De     es       hKey(der.bu*SMALL_STACubjectNameHash;
 }

    retur;
    }
y;
        lse if (type = CA_TABLE_SIZ           consumedEnd++;
       if (key == NULLif (consumedEnd    ->== NULL_BUFFER);
            if (key == N)
                return MEMORY_E;
        #endif

            ret = IniaKey(key, 0);
       bornOcKey = 0;
    int nfo->ivSz)
L_FILETYPE_ASN1 && format arg             #ifnbYASSL_SMALL_STACK
            key _FILETYmat != SSL_FILETYPE_RAW)
    argder;
            ssrdata);

    ->bufferd32)sz;
    }

#ifeSecureRenegotiation(CYASSL* ssl_frent ret = BAD_Fuffer, ->error);
            reCd */
            XFREE(ctx-->options.side;

    returinfo->ctx)
       if /* ATOMIC_      rety exist onl->secure_renegotiation         return SSL_BASK
        havePTHOD* methoar*)ret = TLS_toDYNAMIC_TYPEside);

    rER("SS              <= 0) {
 ed to size chainBuffer
                        FreeRsaKey(key);
;

    if (Lockfer */
     
     ate   = ACCEP          ssl->options.minDowngrade = TLrrorString(err, data);
    fprintx = CyaSS          pE_WEBSERVER)
    if (pass) {
        iprintf(fp, "%s", data);
}

#endif


int CyaSSL     /* make sure ECC key can beSSLv23_client_metho		       header =  __MORP* ssl, int       CHAN NULL) {
        #STACK
    {
        YASSL_SCHANhainBuffer,YNAMICE;
      * pemMERCHANnt pemSz           int ake sure ECz
       return SSL_BAe(&key);
      eccKeyey = 1;
         s.key.buffer      ccKey = 1      1:
        c= SSL_BAD_FIL BAD_F     if E_RENEGOTIATION);
             
           D         pem, pemSz, PRIVATEKEY_TYPE, &der, Nr, NULL, info, &eccKey);

    if (         #ifdefeof(C  eccconst char* pass)
{
    int            eccKey = 0;
    int            ret;
    buffer         der;
#ifdMIC_TYPE_TMP_BUFFER);
#endif

    if (re return SSL_SUCCGettyaSS              
#ifndef CYASSL_h) != 0) ASSL* ssl, int versiointf("eapCyaSSL_KeyPemToDer");

    if 
            ret = de   ssl->devId = devId;

    return SSL_SUCCESpending");
    return ssl->buffers.clearOutputBuffer.length;
}


#ifndef CYASSL_LEANPSK
/* trun on handshake grmessages for context */
int CyaSSL_CTX_set_group_metDecryptVerifyCt    _BUFF_ecc_free(&kL_SESSION  CYASSL_MSG("Bad function ardef NO_CYASSL_CLIENT
/*T
/* connect enol)
           peer cert chain */
int key);
      _ECC */Buffer);
 on->cache_stswordCb);h) != 0)           2 of the License,  (Deco0CDSA:
            case  CYASSh) != 0) pem der args"TC_SHA256wECDSA:
         t_cert(CY CTC_SHA384wEC"Bad Pem T>privateKey = der;      /* &_ECC */ER);
         == NULL)
Kls.
ntf(" SA:
            caseitch (ce CYASSLimitte ctx->haveECDSAsig = 1;
           ==ions.haveSnBuffer = (byte*)A256wECDSA:
              MP(ns.haveECDSAsig = 1L_MSG("Bad f (cert->si info->consumed = 0;
    der.buffer     = NULL;

    r 1;
           is dist }
        swpart of CyaSSL.
 *
 * Cy   }
        sw         br            ssl->version = MakeTLSv1_1();
  t minimum downgrade version allowed, SSL_SYASSL_TLSV1_2:
            ssl->versYASSL_MSG("Not R);
        if (cert == NER("CyaSSL_SetMinVereturn ret;
}


#endif /* ! CTC_SHA38);
        if (cert == NULL)
      else {
            CYASS       ret = PpyriglbackMacEnc       CTX*globalRNG; process    }nitGtatic ingnatureif (ctx == NULL)
       ctx->devId = devIee* data, word16    umedEnd - (ch(ctx->certChi = 0; i < s         endif

voYASSL_SM       XFREE(k_SECPnagerFree(Cuffer(CYASSL_tf("    sizeof     ntf(Rng(&static in)def CYASSL_SMALL_STACK
    Encryta, sizntf( fer(CYs */
t Ex byte options) (extension)
     006-2014 wolfSnBuffer(CYASSL_Cet = der.hrinked;
       bigger than bctx, const unsigned char* buff,
        yptCb0, NULL, DYNAMICYASSL* ssnuFFER_SIZEe(&key) ctx->pkCurvee(&key)int TmpRngx->pkCurveRNGoptirle so#ifdef CYASSL_DTLS
    if (ssl->optiat end tmpASSL_C ssl->dtls_expecASSL   break;z + 100, MAX_MTU)        return == SSL_NOendifrPasswordCb(char* passwd, int break;
  (at eTAL_ERROR;
    eEM fnimum downgrade version allowed, SSL_S    break;
 lse {
                 pyrigons ever on SG("Processibreak;
    }
    else {
ok");
break;_CLIENT
/* cPEM file soet = der.length;
     int  gotOne =

    if (ile song CA PEM   = 0;
    rng    CYASSL_MSG("RNG_GenerateBtx-> ret,gotOne    odify
 * it under tCK
    Encrypted der;
#ifdef CYAS
#ifndef CYAtex */

#ifdef __MOR XFREE(if

CYASSL_CTX*  0;
    int M file    ssl->buf  }
    UnLockMutHASHDRBGtension->data;
    ECC
        ifdo aL_CertManagY) {
			       header          _DTLS
    if (ssl->opti   bytbreak;nimum downgrade version allowed, Sons ever on ultiple/chain  (ret < 0Nuffer[idx], p
    dt.length);
      ProcessChail)
 e* hastao_LEAV does    nowf (ss     in(sz, m  for (i = 0; i < s = NULL;
 endif

vot       #endif

    deprintPE) {     return 0= NULLType);

    
    der    else if (XSTRNCMP(infocKey = 0; /* not used */
   int re
        return 0= NULLHash(hash) %        EncryptedInfo  info[1];
    #endif

    #ifdef CYASSSSL_ault_passwd_do    iRsaKey)           trun ILETORY_ERROR;

IATI       tx, intf( not useigN          BIGNUM* b);
        returat it= NULL) {
             int tybctx)
        bn");
;
     ->pkCurveOID     #ifdef CYap, dynamicT          XFREE(cert, not used Type);
                EE(cert,f (total NULL, p_MANAG        pi        ret = 0; /* not used    #ifdef CYmpi    er(buff) AL_ERROR;
    eer(buf   }

    return ret;
BIGIN== NULL)_UseS    YASSL_ENTER("SSL_Cder, cm->heap, info, &ecc      XM, cm
        step = (inG("Bad der length");
   f (totalIertChain.bEE(cert== 0)
             else
      _ENTER("CyaSSL_SetVersion");

    if (ssl == NULLt(cert, der.buffer, der.lengthdif
    }
>heap);

    #ifdef CYASSL_SMALL_STACK
        XFRE  else
      nfo, NULL, DYNAMIC_Tdif
   picodedCert(cert, der.buffer, der.leIC_TYPE_TMP_BUFFER);
    #en= NULL) {
        f (total       f (totalnfo->set     RT_TYr.length, L;
   mpi
    MP_OKAY;

    #ifdefnot used Hash(>heap, DYNAMIC_L_MSG("Bad der length");
      * Co  ret = PeSTACK
        info ncryptedInfo*E(cert, NULL, DYNAMIC_TYPE_TMYPE_TMP_BUFFER      return MEMORY_E;
   turn Mnfo->set  ndef NO_SHA
    r*)X    (if (ret =m, int optionreturn ssl->keynfo->m, int optioRL(cm->crl, cert);
#endif

    FreeDec     info->set      = 0;
    006-2014 wolfSSSL_ENTEcodedCert(cert, der.buffer, der.lessing Cert Chain")BN{
    ind compiled in, set options */
int CyaSSL_CertManageocsp = (CYendif

voYPE_TMP_BUFFER)b		passwoctx, const unsigned char* buff,
   BN_WRI     XFREE(cert,  re %lu\n", sizin, set RVER_END)
        retocsp == NULL)
                
int CyaSSL_CertManagesu, &de
    int rreturn ssl->areturn ssl->kte, SSL_SUCCESS for ok, <)
{
    charmp);
  if (ret =aR("CyaSSL_CUCCESS;

 R("CyaSSL_C0;
}


char* Cyaif (ret =r int optionsUM

t, NULL     XFREE(method, NULL, DYNAtOCSP(cm->ocsp, cm) != 0) {
  et =ASSL0;

        re->certificate = d                 DYNAMIC_TYPE_OCSP)m     }
      if (cm->ocsp == NULL)
                return MEMORY_E;

            if (->ocsp == NULL)
       EFREE(ssl->buffe1];
    #endif

    #ifdef Cmo    long u     CYASSL_MSG("Init OCSP failed");
                FreeOCSP(cm->ocsp,ptio
                cm->ocsp = NULL;
                return SSL_FAILURE;
            }
        }
        cm->ocspEnabled = 1;
        if (options & CYmodet =SSL_RL_OVERRIDE)
            cm-ocsp == NULL)
       YPE_TMP_BU     erifngth, password, passwordSz);
(cert, NerifG;
    }

#ifdef CYASaSSL_CertManageP");
                 FUNC_ARG = 0;
            wUNC_ARG;NULL;
        );

    if (pemck CRLECC
        if_OCS     tSUCCESS;

  erifR("CyaSSL_Ceuffer = shd32)sz;
    _MANAG          info->ctN    SSL_NO_Y_E;

            if (ptions */
int CyaSSL_CertManageL_STACK
 _SUCCESS;
}


#return ssl->kinfo->set    ");
                FreeOCSP(cmFUNC_ARGp_;
}
#end_bin384R1:UCCESS;

    (void)optio#ifdef CYASSL_SMALL_STASMAL  DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1]itendif

    CYASSL_ENTER("CyaSSL_CertManagerCheckOCSP");

    if (cm == NULL)
      l && eturn ARG;

    if (cm->ocspEnabled == 0)
      is_zero SSL_SUCCESS;

#ifdef CYASSL_SMALL_STACK
    cert = (D NULL)
ndif

    CYASSL_ENTER("CyaSSL_CertManagerCheckOCSP");

    if (cm == NULL)
      isLL)
  DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NU   i       return MEMORY_E;
#endif

    InitDecodedCert(certSSL_SUCCESS;
}


#L_ENTER("CyaSSL_CertManagerCheckOCSP");

    if (cm == NU->ocsp,ar*)e;
        TER("CyaSSL_Cemd5.h>
   int           dm == NULL)
              info->ct0) {
 d* data, if ((ret = CheckCertOCSP(cm->ocsp, cert)) != 0) {
 d  cm->ocspIOCb

    if ((ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, cm)) !=  == ARG;

    if (cm->ocspEnabled == 0)
      >passwd_cb(passwo
         RY_E;

            if (InitOCSP(cm->ocsp, cm) != 0) {cm unsigned charInit OCSP fai        cm-nit OCSP failed");
  sl->kcspOverrideUR                                        mp;
        #endif /* CYSSL_FAILURf (url != NpEnabled == 0)
      bn2bi16) | (hashID[turn BAD_FUrs.serverDH_G.bufST_SIZE) 
int CyaSSL_CertManagep, 0);rrideURL(CYASSL_CERT_MANAGER* cm,
              L_CTX_new");

    ex initialbn*/
   heck to make sure buf iESS;
}


int CyaSerVerifyBuf        XFturn BAD_FUNC_ARG    return BAD_FUNC_ARG;

    if (cm->ocspEn_SMALL_STACKto   return BAD           const char*, rEE(cert, NULL, DYNAMIC_TYope that it                      else
        cm->ocspOverrideURL = NULL;

    retLL)
        return BAD_FUNC_ARG;

    if (cm->ocspEnableSSL_CertManagerDisableOCSbin2b16) | (haSSL_CTX_UseSuppV_SIO_CERTS                   else {
              if (cme

#if          XMEMCPY(cm->ocspOFreeC              et    re    t options)
{
    in->ocsp,
                 CbOCSPIO ableOCSP");
 ,= ioCbz, TRimitted by a : */
    for (i = 0    return CyaSSL_Cenfo, NULL, DYNAMIC_Ts = 1;

    return SSL_SUCCESS;k */
int CyaSSL_SetMi ssl, int options)
{
    CYAbyte )
		    inign        re have multiple/chain ake sure RSA masketurn   if (cm->ocspOverr) {
 ocess the buffe buffer */
  (CYASSLManagerDisableOCSP(CYAS    retu#ifdef CYASSL_SM              XFREE(i>ocspUseOverrideURL = 1;
        if (oranions & CYASSL_OCS
}


intedCe


inttoctx)
t botto          CYASSLSSL.
 *
 *  #endif

   e(&key);
     ef H #endedCe /L_EXTRA
at end    long sz, #end            ret = SSL_SUCCESS;
                   rreak;
        &idx,&key,der.leng          CbOCSP

        if (revoid* ioCbCtx    if (i /* make sure     [dyna+ 100, MAX_MTU)               ficate );
  ASSL* ssl, const char* url)
_CerrrideURL(CYASSCYAS% 8SS;
}


inlen++ Processed a CA");
        gotOneL_SetOCSP    FreeCRL(cm-dyna,     int    gotOne = 0;

  

int CyaSSL_peek = 1;
        u= 0)
           ;
    }

    return ret;
}


/* Verify the cerL_Sether_type =_CTX_EnabYASSL_ENTER("SSL_CSSL_ENTuffctx,     return ret;
}


int CyaSSL_peek(CYADYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULLSSL_CTX_UseCavium(CYASSL_Cr error */
int CSG("CheckCertOCSP failed");
    }

    FreeDree");
    if (ctx)
        FreeSCheck to hed by
 *yaSSL_CertManagerVeriBuffer(CYASSL_CERT_MANAGER*                            long sz, int format)
{
    int ret = 0;
    buffer der;
#ifdef CYASSL_SMALL_f->cm, optioncodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endiff (ctx)
       P_Cb(0]     |TX* 80 | 0x4   }
        swP_Cb(len-1]_CTX* 0 return BAD_sl)
        return CyaSSL_CertManagerEioCb, CbOCSPRCSPOvcm, opti
        }
       else
        return BInc < 

int Cy        ret = Procfree(CYASSL* ssl)
{
 ENTER("CyaSSL_Cert  if (ctmedEnd < bufelse
                                       DYNAMIC_ARG;
}


int CyaSSL_CTX_DisableOCSP(CYASSLDYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL)
        return MEMORY_E;
if

    return retbiaveSL)
            SetOCSPOverrideU CyaSSL_SetOCSP_OverrideURL(CYASndif

    InitDecodedCert(certine XFO#ifdef CYASSL_SM    cm->ocspUseOverrideURL = 1;
        if (ohexeeCb CyaSSL_fopen
POverr->buffers.westST_SIZE) e(&key);BAD_FUNendif

   sl, str NO_S ecc= dynami defined(OPENSSL_EXTRA) || definedf, sNO_OLD_
        }

        /* makeNO_OLD_(ssl->ctx->cm,
     
int CyaSSL_CertManage a use   Processed a CA");
        gotOne       CYA    FreeCRL(cm-tx, c  }

    return ret;
}


/* Verify the cer       CY, SSL_SUCCESS for ok, < 0 for error */
int Cs         XF     return MEMORY_E;f (ctx)
        FreeSSL_Ctx(ched by
 * = 016_      (    Fre ioCb      STRLEN   i)_FUN     ;

  crtMaef C;
    long   sz = 0;
     ctx ? ctx->h    else
     hed by
 *SG("CheckCSS;
}


int Cersiint;ile = XFOPE if (ssl)
    *ame, "rb");
    if (ize(CYsent enabled, SSL_SUCn SSL_BAD_FILE;
    XFSEEK(file, 0, XSg   sz = 0;
 Nf CY 0;

        ret = hed by
 *eeCb = respFreeCb(void)heataticBu* MEMWIND(file);

    if (sz > (long)siCyaSSL ret   else
        cndif

    CYASSL_ENTER("CyaSSL_CertManagerV                              DYNAMI(void)heaextern FILE * CyaSSL_fopen(const char *name, const char *modSSL_CertManagerDisableOCSduR("CyaSSL_CertManagerSe NULL;
#else
    _EnableOCSPpen
    #endif

/* process a du unsigned charrlSz);
        }
        else
            return MEMORY_E;b>ctx)
, DYNAMIC_TYPE_FILG("Bad der length");
          enabled, SSL_SUCCESSurn BAD_;
    else {
        if (type == Cof(s   else
        cm->ocspder length");
   );
#ifdeopy CbOCSPIO ioCb, CbOCSPRetManagerEnableOCSP(sslpFree respFreeCb, void* ioCbCtx)
{
    )
{
    else
        cYPE_TMP_BUFFER)CSP(
    return ret == 0 ? SSL_SUCCESS : ret;se if (sz < 0) {
        XFCLOSE(f     ns & CYASSL_OCSP_NO_NONCE)
             NULL;
#el DYNAMIx->userdata);open
    #endif

/* process a     #ifdef CYASSL_SMameHash;
 MIC_TYPE_OCSP);et_sl, rn BAD_FUNC_ARG;
}

;
}
#endif


#wCyaSSL_SetOCSP_OverrideURL(Cw= 1;
        if (options & CYApath, nSSL_ENTER("CyaSSL_SetOCSP_OverrideURLMIC_TYPE_OCSP)decuser certificate chain to pass during handshakeetOCSP_OverrideURL(Cst         ret = AD(myBuffer, sz,t = SSSL_ENTER("CyaSSL_SetOCSP_OverrideURLFILE;
    }

cspOvedec  else if ((ret = CheckCertOCSP(t, DYNAMIC_TYPE_FILE);

    return reSSL_FA


/* loads file then load       = cerH    if (info == NULL) {
 DHn AddCA(cH* d  void*  yte* h        retudh->peccKey = 1on not forced  in ;
          #ifdef USE_WINDOWpub           WIN32_FIND_DATAArivindFi   #ifdef USE_WINDOW       return BAD_FUNC_ARL_SMALotia #endif

        in ex NULL;
    #else    info->ctx/* t path) {
     info->consumed = 0;/* t  ret = PemToDDurn f, sz,if
  ASSL* ssl, int options)

    #         x->cert= (cha");
    if (ctx)
= (ch   }

    return ret;
DHr* signers;This file is part of CyFILENAME_SZ, NULL, DYNAMI      XM= (chnfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
    else
DH  InitDecodedCert(cert, (DH_ENTER("CyaSSL_SetVersion");

    if (ssl ==      return MEMORY_E;
    (cert, CERT_TYPE, 1, cm);

#ifdef HAVE_CRL
    AME_SZ);
      hFind = led)
        ret = CheckCeCYASSL_SMAL     return MEMORY_E;
eDecodedCert(cert);

    XFREE(der.buffDH);
#endif

    ro, NUurn ails.NAMIC_TYPE_CERT);
#ifdef CYALLOC(MAX_ : ret;
}


/* turn on OCSP if ofDH= (CYASSL_OCS/* try to loadL_MSG("FindFirstFile f              each regular file each eOCSP");
    if (ssl)
eak;

        ER);
    path, MAX_FIions;

    CYASSL_EN path, MAX_F CYASSL_SMALL_STACK
            XFYASSL_SMALL_STACK
        char*  ngth);
   YPE_TMP_BUFFER)ANDLE hFind;essBuffer(ctx, myBuffer, sDATAA FindFL_FILETYPE_PEM, CA_TYPE, NULL,gL_FILETYPE_PEM, CA_TYPE, NULL,0me, "\\", 2TYPE_TMP_BUFFEdh) enoughet typeifndle is)
{
 safetNI(CY      ssl->versiinked == NULL) {
     EMORY_E;
      ProcessChaiSetDh *peerSz        /* try to load (&key);
      ENTER("CyaESS;
}


int CyaSNAMIC_TYPE_TMP_p{
   dynamicTypNAMIC_TYPE_TMP_gd);
    #elrPasswordCb(char* passwd, int = NULL || sz < path   #ifdef US= NULL || sz <             }

       = NULL || sz   p(ssl->ct      char*  name =g_CRL* crl)
{
#ifdef CYASSL_;

    iSTACK
                   doptioree(CYASSin pa{
            Cg->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetOCz, cm->heap, 0);
   CYDer");
 >ind) if (fname == NULL) returnp
#ifdef CY_TMPBAD_PATH_ERROR;
        }

    #ifdef gYASSL_SMALg_STACK
        name = (char*gXMALLOC(MAX_FILENAME_SZ, NU          ssl->options.minDowngrade = TLp#els= NULL || sz <         picBuffer[FILE_BUFFER_SIZE];
#endif
    bCYASS (entry = readdir(dir)) != gicBuffer[FILE_BUFFER_SIZE];
#endif
 STRNCPY(name,YASSL_MSG("opr path ver               info->CYASSL_ return ret;
}


int CyaSSL_peek(CYA_MDK_ARM)
ER);
  ;
            XSTRNCAT(name, entry->d_na*
 * Copyright (C) 2CCESS;
}
#endif


#ifnnd);
        }

    #ifdef CYA         NULSL_DIRDYNAMIC_TYPE_TMP_BUFFER)    path, MAX_FILEcs.c PARTICSL_DS_IFctx->cm, url);
    else
      BN 0);    uffer)) {
        CYADhved a c         XSTRNCAT(na,zeofNULL) } et;

    if (fnamee
        return BADDHL_STKe}


/;
}


int CyaSSL_CTX_SetOCSname = NULORY_E;
    #eASSL_MSG("We got    ssl->devId = devId;

    return SSL_SUCCESS;
}

"/", 1);
            XSTRNCAT(name, entry->me, MAX_FILENAME_SZ/2);

            if (stat              name, const char *mode) ;
      DH384R1:
      ttributes != FILE_ATTRIBUTE_DIRECTORX_FILENAir == NULL) {
     OCSP");

    if (cm == NULL)
   YASSL_SMALL_STACK
          eURL");BAD_FUNC_ARG;
}


int ok,      0char* buff,
   DH_g
#ifdef      XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFFssFile(CYASSL_CTX* cSG("statub con= 76_EXTRA

    byte*  myBuriv{
   taticBuffreeCb, void* i           CbOCSPIO ioCb, CbOCSPRespFree respF    DIR*   dir =ub       CbOCS        DIR*   dir =riv opendir(path);ong   sz = 0;
 break;
        }

         char*  name = ub [768
    #else
        chafile= XFTELL(fisl)
        reet < 0)
            break;

   FindFirstFile f usage */
#e   Processed a CA");
        gotOne = 1;
        used += consumed;
     int options)
{
    CYASSL_ENTER("CyaSSL_SSL_CertMntry = readdir(dir)) != Nffer,E;
    }

    if (sz > (long)sizeof(staile == Xntry = readdir(dir)) != NynamiE_SZ);
            XSTRNCPY(name, path, ceritficate, SSL_ns); sz         XFCLile se
        return BAD_FUN
{
    CYASSL_ENTER("CyaSSL_CTX_DisableOCSP");
  closedubD_FIL}
        dynamic = 1;
    }

    if ( (ret = (r) {
FREAD(myBuffer, sz, 1, file)) < 0)
          if (ctx)
        return CyaSSL_L) {
            CYASSL_MSG("opendir path verify locations failed");
            return BAD_PATH_ERROR;
 L_SMALL_STA PAR&&L_STACK
       h re                                    )
{
#ifdef C CyaSSL_CTX_SetOCSP_OverrideURL(CYASSL_CTX* ctx, const char* url)
{
     XMEMSET(name, 0, MAelse
  LL);
, tryyaSSstaticnit(); /* user nint  gotOne = 0;

 edCert), NULL,
           onsumed = noLL);
MIC_TYPE_FILE);
        if (mysz, int format)
{L;

    return S#ifdef CYASSLA_TYPE;
#ifdefKeyPair,0,
                   L_SMA SSL_B&DYNAMICType = DYNAMIC_TYPE_CA;
    else if (type == CERT_TYPE)
     myBuffthodffer CYASSL_METHOD* cm_pick_method(void)     #else
     
#ifndef CYt CyaSSL_CTX_SetOCSE);

   0,
     erSz;
        retuEM, CA_TYPE, NULL,0,
           #ifdef CYASSL_SMA FindFiif enabled, SSL_SUCCESS  */ASSL_CERT_MANAGER*        XFREE(info, NULL, DYN                   _SZ)p      ht (C) 2006-2014 wolfSSL Inc.
tx, name, SSLm, const char* file,
                ame, SSL_F const char* path) hFind;
  D);
    sz = XFTELL(file);ASSL_CERT_MAN hFind;
 
    CYASSL_ENTER("CyaSSL_CertManagerLoadCA");

  riv
#ifndef CYASSL_}

    /* try to senath)
{
    ify,;
    }
    f (ctx)
           CYASSL_MSG("Getting ke lo("GettiULL,0,
           myBuffer = (byte                          p, 0);*/
       if (cm == NULL) 
        CYASSL_MSG("Getting  SSL_BDYNAMIC_->cm);
    tmpe, path);

    /* don't loose our good one */
    tmp->cm = N
    /* for tmp useSL_free(CYASSL* ssl)
{
    ENTER("CyaSSL_CertManag callback, password in u                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL ( (ret = (int)XFREAD(myBuffer, sz, 1, file)) < 0)
    ret = SSL_BAD_FILE;
    else
        ret = Cy char *name, const char *modSMALL_STACtmp;      static0 otherwis    i /* force heapy;

u */
#el= NULL || sz <          }

    if (     Pu                  /* could hase
    byte   staticBuffer[FILE_BUFFER_SIZE];
#endif
    byte*  myBkerecvE];
#endif
    byte*  myBuffer = sdynamicTyper;
    int    dynamic =)
        struct dirent* entry;
        DIR*   dir =SL_CertManagerVerify");

    if (file == XBADFIL(file, 0, XSEEK_END);
    sz =ULL;
    #else
        chaD(filCRL* crl)
{
#ifdef CYASSL_SMALL_STACK
     DYNAMIC_T   Processed a CA");
        gotOneLOSE(er)) {
        CYASSL_MSG("Getti}

    return ret;
}


/* Verify the cerLOSE(file);SUCCESS for ok, < 0 fouffer = (be*) XMALLOC(sz, cm->heap, DYNAMIC_TYPE_FILE);
        if (myBufferm)
{
            return SSL_BAD_FILE;
ke lo_FILE;
    else
        ret = CyaSSL_CertManage)
       er(cm, myBuffer, sz, format);

       CYASSL_MSG("ecs.aNULL)
 ->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetOCfdef{
    xtensioVerify(Cdh)(CYASSL_CTX* ctx                  
        TX_free(tmp);

    retur   #ifdef C hFind;YASSL_SMALSSL_SDYNAMITACK
        name = (char*)ile MALLOC(MAX_FILENAME_SZ, NULL, DYNAMIC_TYPE_TMP_ NULL)
  MANAGER* cm, by veri_2_client_method();
        (void)EMORY_E;
    #endif

      dynamic =rtManagerCheckCRL(CYASSL_CERT_M= 0;f (cm == NUuffer = sDecodedCert* cert = NULL;
#publse if (s.st_modeynamicS_IFREG)uffer              ret = ProcessFile(ctx, name, SSL_FILETYPE_PEM, CA_TYPEAgif (0,
                   ERT_M&CCESSver_methDYNAMIC_ke l      #endif
    #else
        return NULL;
    #endif
}


/* li*  myBuffer CYASSL_METHOD* cm_pick_method(NULL,
 staticBuffer)) {
      

    CYASSL_ENTER(SSL_SCCESS{
            XFCLOSE(file);
            retu(int)X    #ifdef HAVE_CRL
        if (cm->crl == NULL)
            cm->crl = (CYASSL_CRL*)XMALLOC(sizeof(CYASSL_ctx->passwd_cDHASSL* ssl    = cerSA== SSL_SUCCESS && path) {S  ssl->opDSA;
    /* usedo sendaregular file san path */
    #ifdef USE_WINNAMIq_TYPE_TMP_BUFFER);
#endif

  S_API
        WIN32_FIND_DNAMIC FindFileData;
        HANAMIC hFind;
    #ifdef CYASSLNAMIALL_STACK
        char*  n
{
    NULL;
    #else
    NAMI char   name[MAX_FILENAME_SZ];
 MALLt);
#ifdef   #ifdef CYASSL_SMALL_STMALL
        name =sa(char*)XMALLOC(MAX_FILENAME_SZ, NULL, D cm->cC_TYPE_TMP_BUFFERS;
}

      if (name == S;
}
)
            return MESessR        char{
            CYASSL_MSG("FindFirstFile cm->c);
      S;
}
TRNCPY(name, path, MAX_FILENAME_SZ - 4);
        XSTRNCAT(name, SA\\*", 3);

        hFind =SAFindFirstFileA(name, &FindFileData);
        if (hFind == Ipe, int monitE_VALUE) {
            CYASSL_MSG("FindFirstFileoadCRL");
    CYASSL_SMAions failed");
        #ifdef CYASSL_SMALL_STACK
  pe, int m  XFREE(name, NULL, DYNAMIC_TYPE_TMP_BUFSAER);
        #endif
 S;
}
       return BAD_PATH_ERROR;
        }

        do {
            if (FindFiSAeData.dwFileAtMALL_STACK
    n SSL_FATAL_ERROR;
    Y) {
             (cert, NULL, DleCRL(Cath, MAX_FILENAME_SZ/2 - 3);
  bleCRLconst cha  CYASSL_ENTERe, "\\", 2);
         CYASSL_ENTEe, monitor);
}


int CyaSSL_EnableCL cb)
{
    CYASSL_ENTER("CyaSSL_C      ret = ProcessFile(ct_MANAGER* cmL_FILETYPE_PEM, CA_TYPE, NUrtManagerSet type, int monitor)
{
    CYAS                            

   t type, int monitor)
{
    CYASS        NULL);
        SARL(CY
        } while (ret == SSL_SUCCESS && FindNextFileA(sae, monitor);
}


int CyaSSL_Ena                 opti usage */
#else
    bMALL_STACK
    {
     s deL_CertManagerLoadCRL(CYASSL_("CertManagerVeri        return BADtmp;genORY_ case CYbint r, d;
      TER("CyaSSL_SetCRL_Cb");parametersrn BAD_FUNCl)
     rrideURL(ss0;
}


char* CyaaSSL_CTX_UseSupp  long sz    icenseANAGl && erRetx, byte type, byt;
}
#endif


* hEnab    && fo   return CyaSSL_Ceertificate =tLL_STACK
    = 0;
    int  rern CyaSreturn SSL_BAanagerEnalength) < 0)
aSSL_CTX_DisablcbCertManagerSetCRL_Cb(ssl->ctx->cm, cb);nt options)
{name fname into cturn BAD_FUNC_ARG;
}


int CyaSSL_CTX_EnheckCertCRL fa CERTIXMALLOC(sizeof(D  if (info == NULL) {
 Rs         RMALLrSTACK
    XFRE  CYfyBuffer(CYA CYA MERCH        WIN32_FIND_dCRL" make sur (ctx)
        returndCyaSSL_CertManagerLoadCRL(ctxpath */
    #ifdef USE_WIdCRL"  return ret == 0 ? SSL_SL(ctx-mp1;
}


int CyaSSL_CTX_SetCRL_qb(CYASSL_CTX* ctx, CbMissiniqmpath *{
    CYASSL_ENTER("Cy      return BAD_FUNC_AR  if (c NULL;
    #else
   eturn char   name[MAX_FILENAME_SZ];

{
  type, in cm->cbMissingCRL = cb;

 
{
    ret = PemToDRS;
}


int CyaSSL_CertManagerLoadCRL(CYA
}


#eC_TYPE_TMP_BUFFE_LOAD

");
    if (ctx)
                       int tRpe, int monitor)
{
    CYASSL_ENTER("CyaSSL_CertManager
}


#e      XMverifynfo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
    else

{
  InitDecodedCert(cert, ( ctxENTER("CyaSSL_SetVersion");

    if (ssl == Ns(CYASSL_CTX* ctx, const ch(cert, CERT_TYPE, 1, cm);

#ifdef HAVE_CRL
             int foile == NULions failed");
        #ifdef CYASSL_SMALL_STACK
  ctx, conseDecodedCert(cert);

    XFREE(der.buffnt m>heap, DYNAMIC_etOCSP_OvbleCRL");
#else
 imitted by a : *AMIC_TYPE_TMP_BUrmat)
{SS;

    return SSL_FAILURE;
}

#endS
    if ( CYASSL_DER_LOAD */


#ifdef CYAS

#endif /* CYASSL_DER_LOAD */


#ifdef CYASSL_CERT_GEN

/* loareturn BAD_PATH_ERROR;
        }

        do {
            if (FindF
}

Hash(hash) %
{
    CYASSL_EN_SUCCESS)
        returY) {
            "CyaSSL_CTX_Loat    dyath, MAX_FILENAME_SZ/2 - 3);
 n der s
int CyaSnt    ret     ions;

    CYASSL_ENnt    ret    )
{
#ifdef CYASSL_SMALL_STACK
    E;
    if (ctx)
        return CyaS      ret = ProcessFile(cER("CyaSSessBuffer(ctx, myBuffer, szssingCRLLE)
        ret = SSL_BAD_FILE;
 p  else {
        XFSEEK(file, 0,agerLoadCRL(ssl->ctx->cm, p);
   LE)
        ret = SSL_BAD_FILE;
e);
        XREWIND(file);

        }
      XREWIND(file);

   sl;
}


void cert from file  CY
        } while (ret == SSL_SUCCESS && FindNextFileAr* ssl, CbMissingCRL cb) ctx, cons        headerEnd = newl* ssl)!dCert*)XMALLSAtensi          elCyaSCYASSL_SMALL_STIndividualiphers[ir certificate chain ter(buff,XFRECYASSL* ssl, int opEageryaSS    }

        conver             , cm->heap);

    #ifdef CYASSL_SMA, cmA_TYPE && format == SSL_FILETOverrideURL = NULL;

    return E;
    XFSEEv1_2_clientEEK_END);
    sz = XFTE SSL_BAD_FILE;
    XFSEENTER("SSL_CTX_free");
    i    }

        converithmoc 0;

        ret = ProcessBuffSUCCESS;
}


int CyaSSL_getL;

    return 
       rtCRLif (ret =(ACK
)eOCSP");
  ormat);
#endif
        else
            ret = ProcessBuffer(cetOCSP_Cb");
    if (cm == NULL)
        ront octx->passw!EGIN CE&&ted, CYASSL_C;
    }

    FreeDecodeMALL_STAsa  converted.buffl)
        returSS;
}


(word32)s
            if ( (ret =           SSL_DisableCRL(CTX_free(CYASSLocspOverrideURL, cm        return MEMORY_E;   Xtmp;_FILE;
            else {
            #ifdef CYASSL_SMALL* cm, const chaNULL, DYNAMIC               }

        convert& CYASS          (der.buffer, NUL               #p= 0)    else
        cm->ocspOverrideURL = NULL;

    return gth < (word32)derSz) {
     q        q     XMEMCPY(derBuf, converted.buqfer, converted.length);
                    ret = converted.length;
                }
   g        g     XMEMCPY(derBuf, converted.bugfer, converted.length);
                    ret = converted.length;
                }
   nagerSe        y     XMEMCPY(derBuf, converted.buyic)
            XFREE(fileBuf, 0, DYNAMIC_TYPE_FILE);
    }

    return ret;
}

#endif /* SL_CERT_M      x     XMEMCPY(derBuf, converted.buxfer, converted.length);
                    ret = convertif (cm == N   return  sz, CA_TYPE, &convert
                      nst char* pMALL_STR                  
{
    CYASSL_EN_LOAD

/              #ifdef CYASSL_SMALL


int CyaSr;
    int    dyE(file);
   nt    ret    
{
    CYASSL_ENTER("CyaSSL_CertER("endif
                }
            }

            if (ret == 0) {
 ;
    long   sz      nverted.length < (word32)derSz) {
dCRL")CYASSL_En     XMEMCPY(derBuf, converteER("heap,
converted.length);
                    ret = converted.length;
                }
    CYASSL_Eeint CyaSSL_CTX_use_certificate_chein_file(CYASSL_CTX* ctx, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subheap     dint CyaSSL_CTX_use_certificate_chdin_file(CYASSL_CTX* ctx, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus sub               XMEMCPY(derBuf, converteER("ffer, converted.length);
                    ret = converted.length;
                LL(fil            else
                    rER(" BUFFER_E;
            }

            XFREE(converted.buffer, 0, DYNAMIC_TYPE_CA);
  e, 0, XSE, NULL)
 P                  == SSL_SUCCESS)
P_certificate_chain_file");
   if (ProcessFile(ctx, file, SSL_FILETYPE_PEM,CERT_TYPE,NULL,1mqord32 pSz Q                  == SSL_SUCCESS)
Qin_file(CYASSL_CTX* ctx, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subyaSS, NULL)
u      const unsigned char* buf, luin_file(CYASSL_CTX* ctx, const char* file)
{
   /* procce->cm, cb);
L) == SSL_SUCCESS)
         &consumed, 0);

        if (ret tx->cm, cb);
  rn BAD_FUNC
{
    CrrideURL(ssl CyaSSL_fopen
     of the License, or
 * (at your      return BAD_        XFREE(key, NULL, DYNAMIC_TYPE_TS)
        returL, DYNAMIC_TYPE   long used   rs der over */
SSL_CTX_DisableCctx)  ret = ProcessE KEY-----";
s    GEN ret;
        }
    #endif
    #ifdef HAVE_ECat enok");
               DYNAMIC_T if (rng    if (info == NULL)
        return MEMORY_E;
#endif

S
         used += consumed;
    }

    return ret;
}


/* Verify theLSv1_2_servf (ssl->options.handShakeStat);
    #endif

      R("CyaSSL_peek()");
Processierver                             CTX* ong taticBuffer)) {
        CYAMakc     = 0;
    long   sz      ,URL(ssl655373_ser        else if (ssl)
          pSz, g, get = CyaSSL_SetTmpDH(ssl, p,;
}


int CyaSS"CyaS                             nt format)
{
 et = CyaSSL_SetTmpDH(sslpart of CyaSSLSL_CertManaACK
        XFREE(name,et = SSL_SUCCESS;

  essages = 1;

    return SSL_SUCCESS;
}


/* SeL_SMAerify the ceritficate, SSL_SUCCESS for ok, < 0 fo
    if (sple mutex inio  gSzGe
   ilainB;
   ns.haveECDSAsig,
CYASSL_CRL),|| g == NULL) {
        XFREE(p, NULblierdat_      infoFER);
    tedInfo*)XMALLOXFREE(myBuffer, h = SSL_BAD_FILEopen
    #endif

/* process        int forSSL_ENTER("CyaSSL_Ses large enougon{
    return (hasSSL_CTX* ctx, SA    liSL_CTX_SNICtx;

  
    if (ctx)
  ft ECDSA cert signature");
     = NULL || sz < ton CyaSSL_FER);
        padrdat&eccKey);
     
    CYASSL_ENfheapHint, DYNt buff, legnthssl->ctx, ssl, CyaSSL_f, sz, format);
}


/* server er(CYASSL_CTX*                      const char* path)
{
    inbufferive */dSSL_frectx, const unsigned char* buf,
                               long sz, int format)
{
    return CyaSSL_SetTmpDH_buffer_wrapper(ctx, NULL, buf, sz, format);
}


/* server Diffie-Hellman parameters */
static int Cya              file_wrapper(CYASSL_CTX* ctx, CYASSL* ssl,
         84R1:ocsp == NULL)E];
#endif
    byte*  fileBuf = staticB                 ER("CyaSSL_  int format)
{
    int    ret = SSL_FATAL_ERROR;
#izeof(stat          ret = MEMORY_E;
   }

    FreSMALL_STACK
    byte   st   /* C,XFRE                          SA_doaSSL_I_SetOptions(CYASSL_CT)
        reUseSuppogEnableCRL(ctx->cm, o      if (ctx ==MALL_STACK
    XCYASSL_MSG(");
    #endif

      at end ok");
            ret = SSL_SUCCESS;
            break;
        }

        if (ret < 0)
            break;

   ATAL_ERROR;
         my              CTX* ctx)
{
 YNAMIXFREE(info, NUL  if (dynamic)
        XFREE(myBuffer, cm->heap, DYNAMIC_TYPE_FILE);

E(p, NULL, * check CRL if enabled, SNo CYASMALLOC(MAXSSL_FILETY #endif

        while ( ret == SSL_SUCCESS & = 1;
        used += consumed;
    }

    return ret;
}


/* Verify the the ceritficate, SSL_SUCCESS fopSz, g, &gSz) < 0)
                ret = SSL_BAD_FILETYPE;
 ideURL(CYASSL_CTX* ctx0;
    X_CERT_MANAGER* cm,SMALL_STACK
    XFR_method();
        #else
            return CyaSSLvSSLv3_client_method();
        #endif
  f
    #elif !defined(NO_CYASSL_SERVER)
       _Cb(ctx->cm, ioCb, respFre
            return Cember to the buffer #ifdef CYASSL_od();
   saS myB    YNAMIC
                if (co  ret = CyaSSL_CTX_SetTm
        if (ssl-rmat)
_CertManagerSetOCSP_Cb(ctx->cm, ioCb, respFreeCb, ioCbCtx);
  ns.groupMessages = 1;

    return SSL_SUCCESS;
}


/* SeL");
    if (cm == NULL)
        return B                   CYASSL_MSG("CheckCertCRL faL_SUCCESS;

    return SMALL_STACK
    byte                                  XBADFIgn     L_read;
    cm->ocspIOCtx =E(ssl->buffers.certChai
{
    if (ctx == NUmicenssz, ctx->heap, DYNAMIC_TYPE_FILE);
        if ta(ssl, data, sz);
igicense = XFOPEN(fname, "rb")sl, strou     se
      sl, str| g CERT_TYPat end ok")yaSSL_CertManagerLo          XccKey = 1;
       ret = SSL_SUCCESS;
            break;
  if (ctx)
            en     Si");
       

        if (ret < 0)
    t userChainerDH_G.buf[  #enNCODED_SIG_SZ crl)
{
#ifdef CYASSL_SMALL_STACK
LL || g uf, sz, 1, filt = (int)XFREAD(myBuffer, sz, , DYNA"CyaSSL_CTX_use->cm);
    else
        return BAD_FUNC_ARG;
}


int CyaSSL_CTX_SetOCEE(p, NULL, et = CyaSSL_SetTmpDH_buffer(  re myBuffer, sz, format);
  ceriynamate ID_md5>opti p, pSz);
 shaRPOSE.  See_method();
     m == NULL || leSMALL_STACK
   erDH_PBAD_FUNC_AR   sz = XFTELL(file);
    XRE      else
            ret = CyaSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, ctxon->cache_sterDH_G.buffer    FreeCRL(cm-   if (ctx->serverENTER("CyaSSL_SetVersion");

    if (ssl == NULL) {
        CYA= PemToDer(pem, pemSz, type, &der, NULerDH_G.buffepart;
                info->
{
    CYASSL_ENTER("CyaSSL_CTX_DisableOCSP");
 ProcessBuffer(ctx, buff + usR("CyaSSL_peek()");
    CYAS  DecodedCert* cert = NULL;
#else
SATER("CyaSSL_CSSL_CTX_SetOCSP_OverrideURL(CYASSL_CTX* ctxn parameters */
int CyaSSL_SetTmpDH_file(CYASSL* ssl, const char* fname, int format)
{
 014 wolfSSL Inc.
 SetTmpDH_file_wrapper(ssl->ctx, ssl, fname, format);
}


/* server Diffie-Hellman parameters */
int CyaSSL_CTX_SetTmpDH_file(CYASSrn CyaTLSv1_2_server_method() return E_CAVIUM
);
     letMD5h :#endsl)
        XMALLO =CC
 odeat)
erverWerDH_G.buf, m,heap, D));
         TLSX* esubjectmitted by a : */
    for (i = 0, hecert * /
   CYAS
#ifndef CYA as published bpart of CyaSSL*PE_DH);
ile(rs, S g =L_ENTER("Cyale");
    returnerDH_P DYNAMIC_TYPE_TMP_BUFFER);
    if (cz);
            else
   onstinBuffer == NULL)                      ret =CYASSL* ssl, const chsaTYPE_tx Diffie-Hellman parameters, SSL_SUCCESS on ok */
    int CyaSSL_CTX_S                                 DYNAMIC_TYPE_TG;

    #ifdef HAVE_CRL
        if (cm->crl ==L_ENTER("Cya
            cm->crl = (CYASSL_CRL*)XMALLOC(NULL) {
            XFREE(c    /* Check to ssl->ctx->cm);
    else
   buffer(CYAS            f const unsigned char* o       XFREE(ctx->serverDH_P.      long sz, int format)
{
    return CyaSSL_SetTmpDH_buffet Cyrapper(ctx, NU        f, sz, format);
}


/* server Diffie-Hellman parameters */
static int CyaSSL_Se int    dynamic = 0;
    int    ret;
    lon/*FUNCifdef p-1    rq-1{
            XST
        XFREE(p, NULGenAdno c_reha
{
    CYASSL_ENT(&key)nfo->conser(bufX_Sef, sz, format);
}


/* servsa      ) return SSL_BAD_FILE;
 CTX_use_PYASSL_MSG("op_FUNC_A format);
}


inet = (int)XF_TYPE_FILE);
        if SetCRL_Cb(CyaSSL_use_RSAPriCRL _file");
    if (ProcessFile(ctx, f
    inile(CYASSL_CTX* ctx, const char* file)
{
   /* procces upACK
    &tmppFree respFreeCb, void* ioCbCtx)
{
    e");

    return CyaSSL_use_PrivateKey_file(ssl, file, foerDYNA_OCSP_CYASSL_SMALL, fileTACK
    XFRE, ndif format, CA_rCTC_S respFreeCb, void* ioCbCtx)
{
    r* fiile(CYASSL_CTXT_SIZE) ==
        }onst charee;
        FILE;
mpDH_file_wrndifTYPE_TMP_BUFFER);
     ile, SSL_FILETYmp1ERT_MANAGER* cm,
     vateKey_file");
    if (ctx == NULL)
    SSL_turn SSL_FAILURE;  else
 c
 *
 *err = mp_sub_d((mp_int*)rsa->q->internal, 1, &tmp);.c
 *if (Copy!= MP_OKAY) {.c
 *
 * CYASSL_MSG("ght (C)  Copor"ile is }.c
 * ssl.c
 *
 * Copyrightmo 2006-2014 wolfSdL Inc.
 *
 *is f,.c
 *
 * ense as publi the terms of tmq1L Inc.
 *
);
.c
 *mp_clear(is filee is part of =yaSSL.
 *
.c
 *
 * return ree SUCCESSle is  ssl.c
 *
 * ur option) FATAL_ERROR;
}
#endif /* NO_RSA */


void Cyaree HMAC_Init(s free but WCTX* ctx, const  use* key, intimpllenublic License as pubt evenEVP_MD* type)
* CyaSs free softwul,
 * but WITHOedise is partctxLiceNULL
 * CyaSSL is free softwnowith on i GNU Ge
 *
 * CyaSSL istribute is partFOR A * CyaSSL is free softwd ha has FOR U General is partXSTRNCMPral P, "MD5", 3)Lice0ublic LicensSL is free softwad5 hmacedistribANTABILITtx->FOR  = MD5 received ute it version write to the Free SoSHA256", 6 * Foundation, Inc., 51 Franklin Ssha256et, Fifth Floor, Boston, MA 02110e <con01, USA
 */
received /*this po be last since would pick or 256, 384, <cy512 tooill c
 *
 * CAVE_CONFIG_H
    #include <are
 * Foundation, Inc., 51 Franklin Sshattings.h>

#ifdef HAVE_ERRNO_H
    #01, USA
 */

#ifdef HAVE_ation, Inc., 51 Franklin Sbadld ha program;, USA
 */

#ife GNU Generkey &&arrantyublic License
 * along wkeyinget, Fifth Floor, HmacSetKey(&on, Mt, F,ton, MA 02, (t evenbyte*)mplie(word32de <ef Oe <cyassl//* OpenSSL compat, no can rclude <c}
} be useful,
 * but WUpdateUT ANY WARRANTY; without evenunsigned char* dataublic License as publid waef O PARTICULAR PURPOSE.  See the
 nssl/bU General Public && #incublic License
 * along wussl/l headers begin */
    #nssl/bn <cyassl/ope#inclyassl/opel/crypto.h>
    #include <cyassl/openssl/des.h>
    #include <cyassl/opeFinalUT ANY WARRANTY; withounssl/dh.h>
    hashublic License as publnssl/dh.h2014h>
    #include <cyassl/openssl/pem.nclud /* openssl headers e <cublic License
 * along wfcludeaders begin */
    #nclude <cyassl/ope#inclypto.h>
    #include <cyassl/openssl/des. <cyassl/partef OPENSSL_EXTR>

#ifdef __MORPHett */
outpu.h>
 ifth Floor, Bostswitchublic MA 02DIR) \
         BILITase0-13:blic License as publi*len110-13_DIGEST_SIZEe <cyassl/ #include "vbreakm; if not, at.h>
    #enSHA
    #ifdef EBSNET
        #iSHAude "vfapi.h"
        #include "vfile.h"
    #endif
#endif /* NO_F256ILESYSTEM */

#ifndef TRUE
    #256ude "vfapi.h"
        #include "vfile.h"
    #endif
#endifdefault
    #ifdef EBSNET
   HAVE_WEBSERVER)
t, F#include <cyassl/A
 */

#ifdef openssl/ #include <cyassl/ope eitnupUT ANY WARRANTY; with   #incl( use)ctxGeneralULAR PURPOSE.  See the
 {
     edis #int evens free FITNESS ul,
 * FITNget_digestbynid(d waid   #include <cyassl/opensslt char* s2, unsU Generalt.h>
 (idublic Licens  #enNID_mdf
    #ifdef EBur optir* s1, consmd5(am; if not, _len == 0sha1       return (char*)s1;

    wh) {
 (n >= s2_len    }

#endif /* min s free softwBad ar* s2 id valulude <cyao.h>
#eur optienseK
chars free RSAhar* s1, consPKEY2_le1}

 UT ANY W NULL;
} impl b;
    }
#endkeye <cyaULAR PURPOSE.  See  NULL;
}
#endif

U Generals1++;
        n--;
    }D
    return NULL;
}
#endiD


/* prevent multiple mutex initializations */
static volatile int initRefCounD = 0;
static CyaSSL_Mutex co the iatile int iX_STATE>
    #/* prevent CIPHER> b ? a : b;
    /
static volatile int i
{
    U General Publicublic Licenst.h>
        cipherTinclude <sys/stat.h  #enARC4_TYPE
    #ifdef EBSNETs free softwur optl hearc4 st    /* icense as publisur opti}
#en*) <cyas/* use.    .
#endif  b : a;
    }

#endif /* min */

HAVE_WEBSERVER)
x returL_DTLS
    static INL= (CYASSL_C0e <cyassl/openssl/evp.hs1++;
        n--d wa_new");

    if (i_LENCYASSL_CTX* ctx = NULL;

    CYASSL_ENTER("CYASSL_CTX_new");

    if (i(ctxnitRefCount == 0)
        CyaSSL_Init(); /* user no longer forced to call Init themselves */

    if (method == NULL)
        retur sizrn ctx;

    ctx = (CYASSL_C retof(Arc4am; if not, YNAMIC_TYPE_CTX);
    if (ctx) {
        if (InitSSL_Ctx(ctx, method) < 0) {
            CYASSL_MSG("Init CTX faile0(CYASSL_ME    CyaS3des_iv
/* prevent NULL;

    CYASied wadosetublic License as publist/md5.h>
    #in>
    ivied wa>
    #incl}
#endlen#endif /* min */


#ifndef ctx)
{U General Public License || iv License for more details.
 *
 *    function argumenave received a copy of the GNU Gener;
   
 * (at yoDes3_SetIVndef NOsizeof(des3, iv);    #include <cyassl/operetclude <c ssl.c
 *
 * memcpy(L_LEl = (CYASSL*) XMA.reg, DES_BLOCKapi.hSK
char useful,
 * aes_ctr)
{
    CYASSL_ENTER("SSL_CTX_free");
    if (ctx)
        FreeSSctx);
    CYASSL_LEAVE("SSL_CTX_free", 0);
}


CYASSL* CyaSSL_new(CYAFreeSSL(ss* ctx)
{
    CYASSL* ssl = NULL;
    int ret = 0;

    (void)ret;
    CYASSL_ENTER("SSL_new");

    if (ctx == NULL)
        return sAes    ssl = (CYASSL*)aesLLOC(sizeof(CYASSL), ctx->heap,DYNAMIC_TYPE_SSL);
    if (ssl)
        if ( (raes InitSAL(ssl, ctx)) < 0) {
* mystrnstr(const char* s1, consripemd160}
#end PARTICULAR PURPOSE.  See ("SSL_use 0;
static CyaSSL_Mutex co       CyaSSL_CMD_ retCYASSL_CTX* ctx = ESS FOR A PARTICULAR PURPOSE.  See 
{
    CYASU General PubA 0211icense for more details.
 *
 *No md FOR SL_Eifth Floor, ur optiBAD_FUNC_ARG)s1;
        write to the Free Software
 * Foundation, Incur optinclude "vfapi.h"
    ute it and_CONFIG_H
    #include <config.h>
#endif

#includur optio32 min(word32 a, word32}
#ifdefx) {
   SHA384          ssl->IOCB_ReadCtx = &ss384buffers.dtlsCtx;
            ssl384OCB_WriteCtx = &ssl-> hope->buffers.dtlsCtx;512          ssl->IOCB_ReadCtx = &ss512buffers.dtlsCtx;
            ssl512L_LEAVE("SSL_set_fd", SSL_Sndif

#include <cyassl/ssl.h>
#include <cyassl/internal.h>
#include <cl/error-ssl.h>
#include <cyassl/ctaocrypt/coding.h       sslOCB_WriteCtx = &ssl-it CTX failefd;
    ssl->IL* ssl, int fd)
{
 NULL;

   _iv_lengthCYASSL_CTX* ctx = NULL;

    CYASSL_ENTER("CYASSL_CTX_new");

  NC_ARG;

    /* Add d int)XSTRLEN(snit(); /* user no lon>= s2_len && s);
 128_CBCit th 
    #ifde* delimite92*/
        totalInc += step;
 min/
        totalInc (ctx) {
        AES CBCifth Floor, Bostur opti);
    ssl->op;
->buffers.dtlsC);
 COUNTER + 1);  /* delimiter */TR       totalInc += step;

                buf += XSTRLEN(uf is            buf +=will not overflow */
TR      if (totalInc < len) {
           , SSL_StotalInc += stSL(ss large enough and will not overfloD */
        if (totalInc < leSL(ssl, ctx)) n >= s2_len && sSL(sEDE3urn SSL_SUCCESS;
}


int CyaSSL_get_fd(cSL_Lconst CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_fd");
    l Init th                *buf++ = delRC4      if (totalInc < le0n >= s2_len && s1ULLi < sizeASSL_ENTER("CyaSSL_get_using_no_nonck");
    CYASSL_LEAVE("CyaSSL_get_    }

#RA) || defined(HAVE_WEBSERVER)
include <cyassl/openssl/id CyaSSL_CTX_free(CYASSL_CTX*OPENree freeTX*) X ppoly", 0);
    return 0;
}
d CyaSSL_setU GeneralXFREE(p,g_non, 0SK
char       CyaSPEM_write_bio}

 Privateludes free BIO* bio, 

   rsclude <cyassl/openssl/r MERCHANTABILITY or FITNNULL;
* /* use


int CyaSSL_dtls_set_peer(CYASSL* nssl/dh.h>
    passwdLEAVE("SS


int CyaSSL_dtls_set_peer(CYASSL* pem_void*ord_cb cb,n the iargL_CTX_free", 0bioctx;

}
#endrsauffers.dtlsC/* useuffers.dtlsCvoid*)uffers.dtlsC);
}
    }
#endibsCtx.peer.saarg#endif /* min */


#ifndef;
    ssl->options.usingNon 0;
static CyaSSs distributed in thing_nonblock");
    ssl->optDons.usingNonblock = (nonblock ex;  ;
}


int CyaSSL_dtls_set_peer(CYASSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef CYASSL_DTLS
    void* sa = (void*)XMALLOC(peerSz, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    if (sa != NULL) {
        if (ssl->buffers.dtlsCtx.peer.sa != NULL)
            XFREE(ssl->buffers.dtlsCtx.peer.sa,ssl->heap,DYNAMIC_TYPE_SOCKADDR);
        XMEMCPY(sa, pe.dtlsCtx.peer        ssl->buffers.dtlsCtx.peer.sa =/* prevent multip       XMEMread->opts.usingNonblock = (nonblocktx;

    ctx = (C(ctx) {
   ent multi implieDDR);
    if (sa != NULL) {
        if (ssl->buffers.dtlsCzations *eer.sa,ssl->heap,DYNAMIC_TYPE_SOCKADDR);
        XMEMx.peer.sa, *peerSz) 0;
static CyaSSL_Mutex co->bunffert it w
/* Load !=  from Der,ion) any lathoulsuccess < 0houlnssl/des.       CyaSRSA_
intDerblock = != 0);
}
ssl/openssl/dh.h>
    #otiaree");erSzpoly", 0ssl/op idx =      CYd waalInc #endif /* min E[i],SE.  See     CYASSL_U General PubrsaSSL* ssl = NwolfSInc.
 *
SSL* ssl = Nde Licesl->optionsSz <Foundation, Inc
    (void)ret;
    CYASSL_ENTER(s_ReadCtx  = &ssl->rfd;
    ssl->IOCB_WriteCt,DYN= Rsas.usingNonDecode(YASSL&idx, (RsaKey4 wolfSInc.
 *
 *ER
   le is part,DYN<NT_END)
        err = CyaS return err;
}


#i faileed in (totalInc < leERVERenssl/evp.h>
#eSetRsaExc.
 *
ifnd)nt CyaSSL_GetObjectSize(void", sizeof(SuitES
    printf("sizeof suits distributed in 1;
        s* objeS

   1      ssl->buffersany laterthe hope that it will beL_SUCCESS oD ok */
int DyaSSL_negotiate(CYASSL* ssl)
{
    int err = SSL_FATAL_ERROR;

D   CYASSL_ENTER("Cex;  dnegotiate");
#ifndef NO_CYASSL_SERVER
    if (ssl->options.side == CYASSL_SERVER_END)
        err = CyaSSLes3        U General Pubdndef NO_CYASSLdCLIENT
    if (ssl->options.side == CYASSL_CLIENT_END)
        err = CyaSSL_connect(ssl);
#endif

    CYASSL_LEAVE("CyaSSL_negotiate", err);

   Dreturn err;
}


#ifndef CYASSL_DEANPSK
eof chacha   e based on build */
int CyaSSL_GetObjectSize(void         = %lu\n", ES
    printf("sizeof suites           = %lu\n", Dizeof(Suited));
    printf("sizeof ciphers(2) ;
#endif
#i\n", sizeof(Ciphers));
#ifndef NO_RC4
    printf("    eof chaarc4         = %lu\n", sizeof(Arc4));
#endif
    = %lll be
he hope thad CyaSSLEXTRintf("    fferSESSION_CERTS

k */Get peer's certific
   chain
#ens free X509_CHAINuffers.dtt ch%lu\_84));block =* sslpoly", 0);
      err = CyaSSL   printf("   edistribpartHA512 (totalInc < le&ssl->session.84));;
static CyaSSTX_free     = %lu\n", sizeof(Sha384));
total counYNAMI       CyaSt ch84));_sizeoblock = def CYASSL_S84));12       = %lu\n", sizeof(Sha512)intf("sizeo    printf(" %lu\n" (totalInc < le84));->sizeof(Buffers));
    printf("sizeof OptASN.1 DER, siitif(Sha3at index (idx)("SSgth in#inclsf(Options));
    printf("* Add e Arrays           = %lu\ied wa = %", sizeof(Arrays));
#ifndef NO_RSA
   {
        sizeof RsaKey           = %lu\n", sizeerts[idx].u\n", saKey));
#endif
#ifdef HAVE_ECC
    printf("sizeof ecc_key          = %l*/
incluns));
    printf("serof Arrays           = %lu\u\n", sizeof(CYASSL_CIPHER));
    printf("sizeofsizeL_SESSION   = %lu\n", sizeof(CYASSL_SESSION));
    pbuff
   Buffers));
    printf("sizeof Optul,
 * def ASSL));
    printf("sizeof CYAS Arrays    TX       = %lu\n", def eof CYASSL_CIPHER    = %lu\n", sizeof(CYASYASSL_S 0) {
   ions */
stati  consxgnedide ==;->buffers.dtlsCtMALL{
  CKESSIO}


#idCert*, sizetTmpDH"); ssl.c
 *NULL || g = , siz[1]rn BUFFER_E;
 of(Arrays));
#ifndef NO_RSA
   def tf("sizeof RsaKey Cyaense for mor;
    if (ssl == NULL || p == Inc +ULL) r(NULL || g ==)X= NUOC(S__
voiNULL || g =)CyaSSL_

int CyaSSL_dtls_set_peer(CYASSL*     if (ssl->buffers.DYNAMI      _TMP_BUFFERrintf("sizeof Rs if  (ssl->bfers.s = GetCiphrs.sR) \
         ITHONULL || g =nDH)
,rs, SSL_SUCCESS on ok */
 ssl->ctx->heap, DYNAMIC_TYPE_DH);
 L_SESSION));
    printf(CyaSSLaSSL_set_socketbpart*/
in= Parse g =Relativeap, DYNSHA3 ssl-, 0erverDH)    0          )
        err = CyaSF
    ludeppSz,.weOwifth Floor, Bost_EXTRA) || defined( NULSL_SetTeof CYASSL_CREE(ssl->buffers.L_ENTER("Cybuffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
    if (ssl->buffers.sfers.serverDH_G.bufs.serctx;

    ctx = (CpartSL_Seticense for more de                   DYNAMIC_TYPEallocsignectx, method) < 0) {
/

#ifdef ffers.serverDH_P.buffer == NULLuffer, sg, inSL_S, 1aSSL_set_socketber = (byte*)XMALLOCCop
}


#idToTYPE_DH);
 DH)
        r, ssl->ctx->heap, DYNA           DYNAMIC_TYPE_DHcopy duffersctx, method) < 0) {
buffer, ENTER(DH);
 aSSL_s                                     == NULL)
     mpDH")    if (ssl->buffersffers.serverDH_P.bffers.serverDHo.h>
#endifons.Freesl->ctx->heap, D           serverDH_P.buffer && ssl->buffers.r, p, pSz)p, DYNXMEMCPY(ssl->bufferfer && ssl->buffers.wssl->buffers.se_MSG("Init CTX faileSL_S  printf("sizeof OptPEMsizeof ecc_key          = %,ET)
    ude k */
 DYNinLen bigionsenougherverDur optinssl/d(-1Asig,
    u\n", sissize*outLenionste(CYASSL* ssl)okf(OptionX       = %lu\n", size_pemeof CYASSL_CIPHER    = %lu\n", siz ssl->ctx->heap, DYNAMIC_TYPE_DH)nssl/dh.h>
    bufu\n", s->opied w*ET)
L
    #inclt even>
   header[] = "-ta =BEGIN     IFICATEta ==\n"tions.  if (ssl =footLL || data ==END || sz < 0)
        reyte haveR= NULL>opt=OS__
voi= NULL) -    te haveRRG;

# SendData(sslRG;

#, sz);

    CYAi;

    CYAer
int Cya(CYASSL);
}
#endif


#ifndef NO_DH
 !NO    printf("!84));
|| !write(ic inbuf           = %lu\fd;
    ssl->ItCipherNdon't even try  ssl->opt#incshorYNAMIC_TYpartl->opt<  ret = Sen+ASSL_LEAVE(+now */
    ssl->buffers.sinternal(CYASSL* ssl, void* data, int s= NULLclude <cXMEMCPY(   CY= NULLRNO_H
  te();

     =  ret = Seata, int sbodyclude <c"CyaSSL =L_ENTEsizeofin       Base64_EnrintfYASSL_ENTER the Li>dtls_expectedRsaKeyTYPE_DH);

    ssl->buffers.weOwnDH = 1;  /*ow */
    ssl->buffers.serbuf + i#include *)write();
              = %lu\     0;
#en+=sl->optiata, int sRG;

#_rx = max(sz +iernal()");

) >L_ENTEinternal(CYASSL* ssl, void* dat
#ifdef HAVE_ER      RG;

#YASSL_LErno = 0;
#l->optio+dif
#ifdef ernal()");

      = %lu\n", sizeof(Arc4))intf(get %lu\n", ID_rx 
    #incluns));
    pr%lu\n",IDCYASSL_CTX* ct sizeof*   else
eof(CYASSL_CIPHER));
    printf("aSSL_peek    printf("s, int sz#ifdef __MORPHOSlu\n",= %lu\n",IDint CyaSSL_Set       n--e hope tha sizeof SHA38
#endtf("   HAVE_FUZZER
            SetFuzzerCb sizeof SHA5, Callback");

  cbf= NULL) fC : b;
    tf("size
        Cya  = f);

     =(ssltions.haveIUM

/* let'ic L sz,  printf(d", SSL_S    sizeof aSHA384tf("    CYASSPK_CALLBACKSz)
{
    CYASSECC{
     ffers.dt

  SetEccSign   returnNTY; withou_read_insl->dev cbFALSE);
}


a : bor, Boston, Msl->devIduse c 0) {
     aSSL_read()sl->devItx return CyaSSL usef*a : b;
    tf("sizeof BufferIUM

ium(CYASSLuse t Cy #includt;
}


inGavium(CYASSL_CTX* ctx, i
    if (ctx == NULL)
   _MORPHOS    return BADeds CyaSSL_CTX_new(CYASSL_MEFUNC_ARG;

    ssl-VerifyId = devId;

    return SSL_SUCtype, ;
}


/* let's use cavium, SSL_SUCCEtype, cook */
int CyaSSL_CTX_UseCaviumtype, cSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        ret->extensi_FUNC_ARG;

    ctx->devId = de->extensions, type, dL_SUCCESS;
}


#endif /* HAVE_CAVIUM */
->extensi}


int CyaSSL_read(CYAe hope tha   returt sz)
{
UCCESS on okseSNI(CYASSL* ssl, byRsa>devId = devId;

    return SSL_

void ;
}


/* let's use cavium, SSL_SU

void Cyok */
int CyaSSL_CTX_UseCav

void CSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        SX_SNI_Set_FUNC_ARG;

    ctx->devId =SX_SNI_SetOptions(ssl-L_SUCCESS;
}


#endif /* HAVE_CAVIUM SX_SNI_Set HAVE_SNI

int CyaSSL_UseSNI(CYASSL* ssl, byRsatype, const void* data, word16 siztions);
}byte type, byte options)
{
    if (sFUNC_ARG;

    return TLSX_UseSNI(&_Status(ssetOptions(ssl->extensions, type, options);
}

void CyaSSL_CTX* ctx, byte type, const void* datatype);
}

word16 CyaSSL_ns)
{
    if (ctx && ctx->extensions)
  G;

    return TLSX_UseSNI(&ctx-extensions, type, optioEnc

byte CyaSSL_SNI_Status(CYASSLEncbyte type, byte options)
{
    if (s0;
}
 ? ssl->extensions : NULL, typ0;
}etOptions(ssl->extensions, type, options);
}

void CyaSSL_      
    if (data)
        *data =                   ns)
{
    if (ctx && ctx->extensions)
        est(ssl->extensions, type, data);

    return De
}

int CyaSSL_SNI_GetFromBufferDeonst byte* clientHello, word32 helloSz);

 ? ssl->extensions : NULL, typz);
etOptions(ssl->extensions, type, options);
}

void CyaSSL_MENT
#
    if (data)
        *data = MENT
#ifndef NO_CYns)
{
    if (ctx && ctx->extensions)
  MENT
#}


int CyaSSL_read(CYASSL* ssl, vt it will b>extensions, tyf (ssl == NU_rx e hope that ia, int sz)->buffers.dtlsCCYASSWOLFSCEPtCipherNUsed by autoconf    se  sslwolfAD_F_LEAavailabld_rx = ma useful,
 * gment(&c}
#end {seCavium(C= NULL)
        retu     SERVICEUNC_ARG;

    return TLSX_UseMaxFraDH)
 servicetx->extensions, mfl);
}
#endif /*     CLIENT
SL_CLIENT */
#endi