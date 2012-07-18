
/*
 * Copyright (c) 2002-2004  Abraham vd Merwe <abz@blio.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <debug/log.h>
#include <debug/hex.h>

static __inline__ int printable (int c)
{
   return ((c >= 32 && c <= 126) ||
		   (c >= 174 && c <= 223) ||
		   (c >= 242 && c <= 243) ||
		   (c >= 252 && c <= 253));
}

static void dump16 (char *buf,const uint8_t *s,uintptr_t offset,size_t len)
{
   if (len)
	 {
		size_t i,n;

		n = sprintf (buf,"%08x - ",(unsigned int)offset);

		for (i = 0; i < len; i++)
		  {
			 if (i && !(i & 3))
			   buf[n++] = ' ';

			 n += sprintf (buf + n,"%02x ",s[i]);
		  }

		for ( ; i < 16; i++)
		  {
			 if (i && !(i & 3))
			   buf[n++] = ' ';

			 buf[n++] = ' ';
			 buf[n++] = ' ';
			 buf[n++] = ' ';
		  }

		buf[n++] = ' ';

		for (i = 0; i < len; i++)
		  buf[n++] = printable (s[i]) ? s[i] : '.';

		buf[n++] = '\n';
		buf[n] = '\0';
	 }
}

void hexdump_stub (const char *filename,int line,const char *function,int level,
				   const void *ptr,size_t size)
{
   char buf[81];
   const uint8_t *s = ptr;
   size_t i;

   for (i = 0; i < size >> 4; i++, s += 16)
	 {
		dump16 (buf,s,(uintptr_t) s - (uintptr_t) ptr,16);
		log_puts_stub (filename,line,function,level,buf);
	 }

   dump16 (buf,s,(uintptr_t) s - (uintptr_t) ptr,size & 15);
   log_puts_stub (filename,line,function,level,buf);
}

