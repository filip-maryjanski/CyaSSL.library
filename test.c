/* test.c
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


#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <proto/socket.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>

#define MAXBUF  1024

#include <exec/libraries.h>
#include <proto/exec.h>
#include <proto/cyassl.h>

int callback_test(int a, CYASSL_X509_STORE_CTX* ctx)
{
	printf("callback_test()\n");

	return 1;
}

int main(void)
{
	struct Library *CyaSSLBase;

	if((CyaSSLBase = OpenLibrary("cyassl.library", 0)))
	{
		CYASSL_METHOD *method;
		int sockfd, bytes_read;
		struct sockaddr_in dest;
		struct hostent *he = (struct hostent *)gethostbyname("google.com");
		char buffer[MAXBUF];
		CYASSL_CTX *ctx;

		CyaSSL_Debugging_ON();

		if(CyaSSL_Init() != SSL_SUCCESS)
			return -1; 

		method = CyaSSLv3_client_method();

		if((ctx = CyaSSL_CTX_new(method)))
		{
			if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0)
			{
				CYASSL *ssl;

				CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, callback_test);

				if((ssl = CyaSSL_new(ctx)))
				{
					CyaSSL_set_socketbase(ssl, SocketBase);
					CyaSSL_set_fd(ssl, sockfd);

					/*---Initialize server address/port struct---*/
					bzero(&dest, sizeof(dest));
					dest.sin_family = AF_INET;
					dest.sin_port = htons(443); /*default HTTP Server port */
					dest.sin_addr = *((struct in_addr *) he->h_addr);

					/*---Connect to server---*/
					if(connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) >= 0)
					{
						if(CyaSSL_connect(ssl) == SSL_SUCCESS)
						{
							LONG c = 1000;
							sprintf(buffer, "GET / HTTP/1.0\n\n");
							PutStr(buffer);
							if(CyaSSL_write(ssl, buffer, strlen(buffer)) < 0)
								PutStr("Failed to write...\n");

							/*---While there's data, read and print it---*/
							do
							{
								bzero(buffer, sizeof(buffer));
								if((bytes_read = CyaSSL_read(ssl, buffer, sizeof(buffer))) < 0)
								{
									Printf("res: %d\n", bytes_read);
									Printf("errno: %d\n", errno);
								}
								else
									printf("%s", buffer);
							}
							while(bytes_read > 0);
						}
						else
							PutStr("ssl connect failed\n");
					}
					else
						PutStr("Connect failed\n");

					CyaSSL_free(ssl);
				}
				else
					PutStr("failed to create ssl\n");
					
				/*---Clean up---*/
				CloseSocket(sockfd);
			}
			else
				PutStr("failed to obtain socket\n");

			CyaSSL_CTX_free(ctx);
		}
		else
			PutStr("failed to create ctx\n");
		
		CyaSSL_Cleanup();
		CloseLibrary(CyaSSLBase);
	}
	else
		printf("Error: Couldn't open cyassl.library\n");

	return 0;
}
