/* lib_shared.c
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

#include <proto/exec.h>
#include <constructor.h>

#include "cyassl.library.h"

struct Library *CyaSSLBase;

static CONSTRUCTOR_P(init_CyaSSLBase, 101)
{
	CyaSSLBase = OpenLibrary("cyassl.library", VERSION);

	return (CyaSSLBase == NULL);
}

static DESTRUCTOR_P(cleanup_CyaSSLBase, 101)
{
	CloseLibrary(CyaSSLBase);
}

