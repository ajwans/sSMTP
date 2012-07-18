#ifndef _DEBUG_LOG_H
#define _DEBUG_LOG_H

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

#include <stdarg.h>

enum
{
   _LOG_QUIET   = 0,
   _LOG_ERROR   = 1,
   _LOG_WARNING = 2,
   _LOG_NORMAL  = 3,
   _LOG_VERBOSE = 4,
   _LOG_DEBUG   = 5,
   _LOG_NOISY   = 6
};

/*
 * This unfortunate hack is necessary in order to include
 * syslog.h in the library itself. The syslog header defines
 * conflicting symbols (LOG_DEBUG, LOG_WARNING, etc), so we
 * have to use different names inside the library.
 */

#ifndef _DEBUG_LOG_C
#define LOG_QUIET	_LOG_QUIET
#define LOG_ERROR	_LOG_ERROR
#define LOG_WARNING	_LOG_WARNING
#define LOG_NORMAL	_LOG_NORMAL
#define LOG_VERBOSE	_LOG_VERBOSE
#define LOG_DEBUG	_LOG_DEBUG
#define LOG_NOISY	_LOG_NOISY
#endif	/* #ifndef _DEBUG_LOG_C */

#define LOG_LEVELS	(_LOG_NOISY - _LOG_QUIET + 1)

/*
 * The LOG_HAVE_LOGFILE and LOG_USE_SYSLOG flags are appended
 * automatically by log_open() if the specified logfile is not
 * NULL (otherwise, the flags are removed).
 */

#define LOG_HAVE_LOGFILE		0x01
#define LOG_HAVE_COLORS			0x02
#define LOG_PRINT_FUNCTION		0x04
#define LOG_DEBUG_PREFIX_ONLY	0x08
#define LOG_DETECT_DUPLICATES	0x10
#define LOG_DETECT_FLOODING		0x20
#define LOG_USE_SYSLOG			0x40

/*
 * Initialize the log system.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
extern int log_open (const char *logfile,int loglevel,int flags);

/*
 * Close the log system. Any calls to the print routines after this call
 * is undefined.
 */
extern void log_close (void);

/*
 * Close and reopen the log file if necessary. This function may fail
 * and if it does, the log system is uninitialized.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#define log_reset() log_reset_stub(__FILE__,__LINE__,__FUNCTION__)
extern int log_reset_stub (const char *filename,int line,const char *function);

/*
 * Print all the data that is currently pending.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#define log_flush() log_flush_stub (__FILE__,__LINE__,__FUNCTION__)
extern int log_flush_stub (const char *filename,int line,const char *function);

/*
 * printf() replacement.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#if __STDC_VERSION__ >= 199901L
#define log_printf(level,format,...) log_printf_stub(__FILE__,__LINE__,__FUNCTION__,level,format,__VA_ARGS__)
#else
#define log_printf(level,format,args...) log_printf_stub(__FILE__,__LINE__,__FUNCTION__,level,format,## args)
#endif
extern int log_printf_stub (const char *filename,int line,const char *function,int level,const char *format,...)
  __attribute__ ((format (printf,5,6)));

/*
 * vprintf() replacement.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#define log_vprintf(level,format,ap) log_vprintf_stub(__FILE__,__LINE__,__FUNCTION__,level,format,ap)
extern int log_vprintf_stub (const char *filename,int line,const char *function,int level,const char *format,va_list ap);

/*
 * putc() replacement.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#define log_putc(level,c) log_putc_stub(__FILE__,__LINE__,__FUNCTION__,level,c)
extern int log_putc_stub (const char *filename,int line,const char *function,int level,int c);

/*
 * puts() equivalent.
 *
 * Returns 0 if successful, -1 otherwise. Check errno to see what
 * error occurred.
 */
#define log_puts(level,str) log_puts_stub(__FILE__,__LINE__,__FUNCTION__,level,str)
extern int log_puts_stub (const char *filename,int line,const char *function,int level,const char *str);

#define MARKER() log_printf_stub(__FILE__,__LINE__,__FUNCTION__,LOG_DEBUG,"MARKER\n")

#endif	/* #ifndef _DEBUG_LOG_H */
