/* libfunctable.c
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



void LIB_Open(void);
void LIB_Close(void);
void LIB_Expunge(void);
void LIB_Reserved(void);
void LIB_CyaSSL_Init(void);
void LIB_CyaSSL_Cleanup(void);
void LIB_CyaSSL_Debugging_ON(void);
void LIB_CyaSSL_Debugging_OFF(void);
void LIB_CyaSSL_CTX_new(void);
void LIB_CyaSSL_CTX_free(void);
void LIB_CyaSSL_CTX_set_verify(void);
void LIB_CyaSSLv3_server_method(void);
void LIB_CyaSSLv3_client_method(void);
void LIB_CyaTLSv1_server_method(void);
void LIB_CyaTLSv1_client_method(void);
void LIB_CyaTLSv1_1_server_method(void);
void LIB_CyaTLSv1_1_client_method(void);
void LIB_CyaTLSv1_2_server_method(void);
void LIB_CyaTLSv1_2_client_method(void);
void LIB_CyaSSLv23_client_method(void);
void LIB_CyaSSLv2_client_method(void);
void LIB_CyaSSLv2_server_method(void);
void LIB_CyaSSLv23_server_method(void);
void LIB_CyaSSL_new(void);
void LIB_CyaSSL_free(void);
void LIB_CyaSSL_set_socketbase(void);
void LIB_CyaSSL_set_fd(void);
void LIB_CyaSSL_set_using_nonblock(void);
void LIB_CyaSSL_get_fd(void);
void LIB_CyaSSL_get_using_nonblock(void);
void LIB_CyaSSL_get_ciphers(void);
void LIB_CyaSSL_connect(void);
void LIB_CyaSSL_write(void);
void LIB_CyaSSL_read(void);
void LIB_CyaSSL_peek(void);
void LIB_CyaSSL_accept(void);
void LIB_CyaSSL_shutdown(void);
void LIB_CyaSSL_send(void);
void LIB_CyaSSL_recv(void);
void LIB_CyaSSL_get_error(void);
void LIB_CyaSSL_get_alert_history(void);
void LIB_CyaSSL_set_session(void);
void LIB_CyaSSL_get_session(void);
void LIB_CyaSSL_flush_sessions(void);
void LIB_CyaSSL_SetServerID(void);
void LIB_CyaSSL_ERR_error_string(void);

ULONG LibFuncTable[]=
{
	FUNCARRAY_BEGIN,
		FUNCARRAY_32BIT_NATIVE,
		(IPTR) &LIB_Open, /* Old ABOX Library ABI Function Block */
		(IPTR) &LIB_Close,
		(IPTR) &LIB_Expunge,
		(IPTR) &LIB_Reserved,
		0xffffffff,

		FUNCARRAY_32BIT_SYSTEMV,
		(IPTR) &LIB_CyaSSL_Init,
		(IPTR) &LIB_CyaSSL_Cleanup,
		(IPTR) &LIB_CyaSSL_Debugging_ON,
		(IPTR) &LIB_CyaSSL_Debugging_OFF,
		(IPTR) &LIB_CyaSSL_CTX_new,
		(IPTR) &LIB_CyaSSL_CTX_free,
		(IPTR) &LIB_CyaSSL_CTX_set_verify,
		(IPTR) &LIB_CyaSSLv3_server_method,
		(IPTR) &LIB_CyaSSLv3_client_method,
		(IPTR) &LIB_CyaTLSv1_server_method,
		(IPTR) &LIB_CyaTLSv1_client_method,
		(IPTR) &LIB_CyaTLSv1_1_server_method,
		(IPTR) &LIB_CyaTLSv1_1_client_method,
		(IPTR) &LIB_CyaTLSv1_2_server_method,
		(IPTR) &LIB_CyaTLSv1_2_client_method,
		(IPTR) &LIB_CyaSSLv23_client_method,
		(IPTR) &LIB_CyaSSLv23_server_method,
		(IPTR) &LIB_CyaSSLv2_client_method,
		(IPTR) &LIB_CyaSSLv2_server_method,
		(IPTR) &LIB_CyaSSL_new,
		(IPTR) &LIB_CyaSSL_free,
		(IPTR) &LIB_CyaSSL_set_socketbase,
		(IPTR) &LIB_CyaSSL_set_fd,
		(IPTR) &LIB_CyaSSL_set_using_nonblock,
		(IPTR) &LIB_CyaSSL_get_fd,
		(IPTR) &LIB_CyaSSL_get_using_nonblock,
		(IPTR) &LIB_CyaSSL_get_ciphers,
		(IPTR) &LIB_CyaSSL_connect,
		(IPTR) &LIB_CyaSSL_write,
		(IPTR) &LIB_CyaSSL_read,
		(IPTR) &LIB_CyaSSL_peek,
		(IPTR) &LIB_CyaSSL_accept,
		(IPTR) &LIB_CyaSSL_shutdown,
		(IPTR) &LIB_CyaSSL_send,
		(IPTR) &LIB_CyaSSL_recv,
		(IPTR) &LIB_CyaSSL_get_error,
		(IPTR) &LIB_CyaSSL_get_alert_history,
		(IPTR) &LIB_CyaSSL_set_session,
		(IPTR) &LIB_CyaSSL_get_session,
		(IPTR) &LIB_CyaSSL_flush_sessions,
		(IPTR) &LIB_CyaSSL_SetServerID,
		(IPTR) &LIB_CyaSSL_ERR_error_string,
		0xffffffff,
	FUNCARRAY_END
};

