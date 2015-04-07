/* libdata.h
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

#include <exec/types.h>
#include <exec/tasks.h>
#include <exec/ports.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>
#include <exec/execbase.h>
#include <exec/alerts.h>
#include <exec/libraries.h>
#include <exec/interrupts.h>
#include <exec/resident.h>
#include <dos/dos.h>

#include <emul/emulinterface.h>
#include <emul/emulregs.h>

#include <proto/exec.h>

#include <clib/debug_protos.h>


struct TaskNode
{
	struct MinNode Node;
	struct Task *Task;
};

struct LibBase
{
	struct Library  Lib;
	UWORD           Pad;
	void            *DataSeg; // Don't change the position of this. The offset must stay
	                          // at 36, or __restore_r13 in lib(data).c must be adjusted.

	BPTR            SegList;
	struct ExecBase *SBase;

	ULONG           DataSize;
	struct LibBase  *Parent;

	union
	{
		struct MinList TaskList;	/* For parent */
		struct TaskNode TaskNode;	/* For child */
	} TaskContext;
};


BOOL __saveds InitData(struct LibBase *);
void __saveds UnInitData(struct LibBase *);
