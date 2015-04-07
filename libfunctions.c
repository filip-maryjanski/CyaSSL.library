/* libfuncitons.c
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


#include "libdata.h"

/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/
/***********************************************************************/

#include <cyassl/ssl.h>

/*** NOTE: The use of __saveds is important to save/restore r13! ***/

int __saveds LIB_CyaSSL_Init(void)
{
	return CyaSSL_Init();
}

int __saveds LIB_CyaSSL_Cleanup(void)
{
	return CyaSSL_Cleanup();
}

int __saveds LIB_CyaSSL_Debugging_ON(void)
{
	return CyaSSL_Debugging_ON();
}

void __saveds LIB_CyaSSL_Debugging_OFF(void)
{
	CyaSSL_Debugging_OFF();
}

CYASSL_CTX* __saveds LIB_CyaSSL_CTX_new(CYASSL_METHOD* method)
{
	return CyaSSL_CTX_new(method);
}

void __saveds LIB_CyaSSL_CTX_free(CYASSL_CTX *ctx)
{
	CyaSSL_CTX_free(ctx);
}

CYASSL_METHOD* __saveds LIB_CyaSSLv3_server_method(void)
{
	return CyaSSLv3_server_method();
}

CYASSL_METHOD* __saveds LIB_CyaSSLv3_client_method(void)
{
	return CyaSSLv3_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_server_method(void)
{
	return CyaTLSv1_server_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_client_method(void)
{
	return CyaTLSv1_1_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_1_server_method(void)
{
	return CyaTLSv1_1_server_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_1_client_method(void)
{
	return CyaTLSv1_1_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_2_server_method(void)
{
	return CyaTLSv1_2_server_method();
}

CYASSL_METHOD* __saveds LIB_CyaTLSv1_2_client_method(void)
{
	return CyaTLSv1_2_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaSSLv23_client_method(void)
{
	return CyaSSLv23_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaSSLv23_server_method(void)
{
	return CyaSSLv23_server_method();
}

CYASSL_METHOD* __saveds LIB_CyaSSLv2_client_method(void)
{
	return CyaSSLv2_client_method();
}

CYASSL_METHOD* __saveds LIB_CyaSSLv2_server_method(void)
{
	return CyaSSLv2_server_method();
}

CYASSL* __saveds LIB_CyaSSL_new(CYASSL_CTX *ctx)
{
	return CyaSSL_new(ctx);
}

void __saveds LIB_CyaSSL_free(CYASSL *ssl)
{
	return CyaSSL_free(ssl);
}

void __saveds LIB_CyaSSL_CTX_set_verify(CYASSL_CTX *ctx, int type, VerifyCallback verify_callback)
{
	CyaSSL_CTX_set_verify(ctx, type, verify_callback);
}

void __saveds LIB_CyaSSL_set_socketbase(CYASSL *ssl, struct Library *socketbase)
{
	CyaSSL_set_socketbase(ssl, socketbase);
}

int __saveds LIB_CyaSSL_set_fd(CYASSL *ssl, int fd)
{
	return CyaSSL_set_fd(ssl, fd);
}

void __saveds LIB_CyaSSL_set_using_nonblock(CYASSL *ssl, int nonblock)
{
	CyaSSL_set_using_nonblock(ssl, nonblock);
}

int __saveds LIB_CyaSSL_get_fd(const CYASSL *ssl)
{
	return CyaSSL_get_fd(ssl);
}

int __saveds LIB_CyaSSL_get_using_nonblock(CYASSL *ssl)
{
	return CyaSSL_get_using_nonblock(ssl);
}

int __saveds LIB_CyaSSL_get_ciphers(char *buf, int len)
{
	return CyaSSL_get_ciphers(buf, len);
}

int __saveds LIB_CyaSSL_connect(CYASSL *ssl)
{
	return CyaSSL_connect(ssl);
}

int __saveds LIB_CyaSSL_write(CYASSL *ssl, const void *data, int len)
{
	return CyaSSL_write(ssl, data, len);
}

int __saveds LIB_CyaSSL_read(CYASSL *ssl, void *b, int len)
{
	return CyaSSL_read(ssl, b, len);
}

int __saveds LIB_CyaSSL_peek(CYASSL *ssl, void *data, int sz)
{
	return CyaSSL_peek(ssl, data, sz);
}

int __saveds LIB_CyaSSL_accept(CYASSL *ssl)
{
	return CyaSSL_accept(ssl);
}

int __saveds LIB_CyaSSL_shutdown(CYASSL *ssl)
{
	return CyaSSL_shutdown(ssl);
}

int __saveds LIB_CyaSSL_send(CYASSL *ssl, const void *data, int len, int flags)
{
	return CyaSSL_send(ssl, data, len, flags);
}

int __saveds LIB_CyaSSL_recv(CYASSL *ssl, void *buf, int len, int flags)
{
	return CyaSSL_recv(ssl, buf, len, flags);
}

int __saveds LIB_CyaSSL_get_error(CYASSL *ssl, int ret)
{
	return CyaSSL_get_error(ssl, ret);
}

int __saveds LIB_CyaSSL_get_alert_history(CYASSL *ssl, CYASSL_ALERT_HISTORY *history)
{
	return CyaSSL_get_alert_history(ssl, history);
}

int __saveds LIB_CyaSSL_set_session(CYASSL *ssl, CYASSL_SESSION *session)
{
	return CyaSSL_set_session(ssl, session);
}

CYASSL_SESSION* __saveds LIB_CyaSSL_get_session(CYASSL* ssl)
{
	return CyaSSL_get_session(ssl);
}

void __saveds LIB_CyaSSL_flush_sessions(CYASSL_CTX *ctx, long tm)
{
	CyaSSL_flush_sessions(ctx, tm);
}

int __saveds LIB_CyaSSL_SetServerID(CYASSL *ssl, const unsigned char *id, int len, int newsession)
{
	return CyaSSL_SetServerID(ssl, id, len, newsession);
}

char* __saveds LIB_CyaSSL_ERR_error_string(unsigned long err, char* buf)
{
	return CyaSSL_ERR_error_string(err, buf);
}
