/* cyassl_protos.h
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

#ifndef CLIB_CYASSL_PROTOS_H
#define CLIB_CYASSL_PROTOS_H

#ifndef EXEC_LIBRARIES_H
# include <exec/libraries.h>
#endif

#ifndef LIBRARIES_CYASSL_H
# include <libraries/cyassl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* need to call once to load library (session cache) */
int CyaSSL_Init(void);
/* call when done to cleanup/free session cache mutex / resources  */
int CyaSSL_Cleanup(void);

/* turn logging on, only if compiled in */
int  CyaSSL_Debugging_ON(void);
/* turn logging off */
void CyaSSL_Debugging_OFF(void);

CYASSL_METHOD *CyaSSLv3_server_method(void);
CYASSL_METHOD *CyaSSLv3_client_method(void);
CYASSL_METHOD *CyaTLSv1_server_method(void);
CYASSL_METHOD *CyaTLSv1_client_method(void);
CYASSL_METHOD *CyaTLSv1_1_server_method(void);
CYASSL_METHOD *CyaTLSv1_1_client_method(void);
CYASSL_METHOD *CyaTLSv1_2_server_method(void);
CYASSL_METHOD *CyaTLSv1_2_client_method(void);
CYASSL_METHOD* CyaSSLv23_client_method(void);
CYASSL_METHOD *CyaSSLv23_server_method(void);
CYASSL_METHOD* CyaSSLv2_client_method(void);
CYASSL_METHOD* CyaSSLv2_server_method(void);

CYASSL_CTX* CyaSSL_CTX_new(CYASSL_METHOD*);
void CyaSSL_CTX_free(CYASSL_CTX*);

void CyaSSL_CTX_set_verify(CYASSL_CTX*, int, VerifyCallback verify_callback);

CYASSL* CyaSSL_new(CYASSL_CTX*);
void CyaSSL_free(CYASSL*);

void CyaSSL_set_socketbase(CYASSL*, struct Library *);
int CyaSSL_set_fd(CYASSL*, int);
void CyaSSL_set_using_nonblock(CYASSL*, int);
int CyaSSL_get_fd(const CYASSL*);
int CyaSSL_get_using_nonblock(CYASSL*);
int CyaSSL_get_ciphers(char*, int);

int CyaSSL_connect(CYASSL*);
int CyaSSL_write(CYASSL*, const void*, int);
int CyaSSL_read(CYASSL*, void*, int);
int CyaSSL_peek(CYASSL*, void*, int);
int CyaSSL_accept(CYASSL*);
int CyaSSL_shutdown(CYASSL*);
int CyaSSL_send(CYASSL*, const void*, int sz, int flags);
int CyaSSL_recv(CYASSL*, void*, int sz, int flags);

int CyaSSL_get_error(CYASSL*, int);
int CyaSSL_get_alert_history(CYASSL*, CYASSL_ALERT_HISTORY *);

int CyaSSL_set_session(CYASSL* ssl,CYASSL_SESSION* session);
CYASSL_SESSION* CyaSSL_get_session(CYASSL* ssl);
void CyaSSL_flush_sessions(CYASSL_CTX *ctx, long tm);
int CyaSSL_SetServerID(CYASSL* ssl, const unsigned char*, int, int);

char* CyaSSL_ERR_error_string(unsigned long,char*);

#ifdef __cplusplus
}
#endif


#endif /* CLIB_CYASSL_PROTOS_H */
