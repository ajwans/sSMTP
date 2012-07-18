
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

#define _DEBUG_LOG_C

/* vsnprintf() */
#define _ISOC99_SOURCE

/* facilitynames */
#define SYSLOG_NAMES

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <debug/log.h>

#ifndef DEBUG_LOG
#define mem_alloc malloc
#define mem_realloc realloc
#define mem_free free
#else	/* #ifndef DEBUG_LOG */
#include <debug/memory.h>
#endif	/* #ifndef DEBUG_LOG */

/* va_copy is __va_copy in older versions of GCC. */
#if defined __GNUC__ && __GNUC__ < 3
#define va_copy(d,s) __va_copy(d,s)
#endif

/* ANSI escape sequence */
#define ESC_STR	"\033["

/* ANSI color definitions */
#define RED		"1;31"
#define GREEN	"1;32"
#define YELLOW	"1;33"
#define BLUE	"1;34"
#define MAGENTA	"1;35"
#define CYAN	"1;36"
#define WHITE	"1;37"
#define BROWN	"40;33"

struct cache
{
   int fd;				/* file descriptor associated with cached line				*/
   char *cache;			/* previous line											*/
   int hits;			/* number of consecutive identical lines					*/
   char buf[256];		/* buffer used for saving "Message repeated..." messages	*/
};

struct log_private
{
   int level;			/* maximum allowed log level								*/
   int flags;			/* flags passed to log_open()								*/
   char *str;			/* where we store partially printed strings					*/

   /* these fields are only defined if LOG_HAVE_LOGFILE is set */
   char *filename;		/* filename of log file										*/
   int fd;				/* file descriptor of log file								*/
   struct cache cache;

   /* these fields are only defined if LOG_USE_SYSLOG is set */
   char *ident;			/* process identifier										*/
   int syslvl;			/* syslog level												*/
};

/*
 * Print fmt and it's arguments (vprintf-style) to a newly allocated
 * buffer and return a pointer to that buffer if successful, NULL
 * if we ran out of memory.
 */
static char *vbprintf (const char *fmt,va_list ap)
{
   /* guess we need no more than 100 bytes */
   int n,size = 100;
   char *buf,*ptr;
   va_list ap_copy;

   if (fmt == NULL) return (NULL);

   if (*fmt == '\0')
	 {
		if ((buf = mem_alloc (sizeof (char))) == NULL)
		  return (NULL);
		*buf = '\0';
		return (buf);
	 }

   if ((buf = mem_alloc (size * sizeof (char))) == NULL)
	 return (NULL);

   for (;;)
	 {
		/* try to print in the allocated space */
		va_copy (ap_copy,ap);
		n = vsnprintf (buf,size,fmt,ap_copy);
		va_end (ap_copy);

		/* if that worked, we're finished */
		if (n > -1 && n < size) break;

		/* else try again with more space */
		if (n > -1)		/* glibc 2.1 */
		  size = n + 1;	/* precisely what is needed */
		else			/* glibc 2.0 */
		  size *= 2;	/* twice the old size */

		if ((ptr = mem_realloc (buf,size * sizeof (char))) == NULL)
		  {
			 int saved = errno;
			 mem_free (buf);
			 errno = saved;
			 return (NULL);
		  }
		else buf = ptr;
	 }

   return (buf);
}

/*
 * Print fmt and it's arguments (printf-style) to a newly allocated
 * buffer and return a pointer to that buffer if successful, NULL
 * if we ran out of memory.
 */
static char *bprintf (const char *fmt, ...)
{
   char *buf;
   va_list ap;
   va_start (ap,fmt);
   buf = vbprintf (fmt,ap);
   va_end (ap);
   return (buf);
}

static char *prefix (struct log_private *priv,const char *filename,int line,const char *function,int level)
{
   static const char *colors[] = { NULL, RED, WHITE, NULL, GREEN, BROWN, YELLOW };
   static const char *levels[] =
	 {
		[_LOG_QUIET]   = "  QUIET",
		[_LOG_ERROR]   = "  ERROR",
		[_LOG_WARNING] = "WARNING",
		[_LOG_NORMAL]  = " NORMAL",
		[_LOG_VERBOSE] = "VERBOSE",
		[_LOG_DEBUG]   = "  DEBUG",
		[_LOG_NOISY]   = "  NOISY"
	 };
   static const int syslvl[] =
	 {
		[_LOG_QUIET]   = 0,
		[_LOG_ERROR]   = LOG_ERR,
		[_LOG_WARNING] = LOG_WARNING,
		[_LOG_NORMAL]  = LOG_NOTICE,
		[_LOG_VERBOSE] = LOG_INFO,
		[_LOG_DEBUG]   = LOG_DEBUG,
		[_LOG_NOISY]   = LOG_DEBUG
	 };
   int have_prefix = (!(priv->flags & LOG_DEBUG_PREFIX_ONLY) && priv->level >= _LOG_DEBUG) || ((priv->flags & LOG_DEBUG_PREFIX_ONLY) && level >= _LOG_DEBUG);
   int i,n = 0;
   char *buf[5];
   size_t len = 0;

   if (have_prefix)
	 {
		buf[n++] = (priv->flags & LOG_HAVE_COLORS) &&
		  ((priv->flags & LOG_USE_SYSLOG) || isatty (priv->fd)) &&
		  colors[level] != NULL ?
		  bprintf (ESC_STR "%sm%s: " ESC_STR "0m",colors[level],levels[level]) :
		  bprintf ("%s: ",levels[level]);
	 }

   if (priv->flags & LOG_HAVE_LOGFILE)
	 {
		time_t tc = time (NULL);
		struct tm *tv = localtime (&tc);

		buf[n++] = bprintf ("%.4d-%.2d-%.2d %.2d:%.2d:%.2d ",
						  tv->tm_year + 1900,tv->tm_mon + 1,tv->tm_mday,
						  tv->tm_hour,tv->tm_min,tv->tm_sec);
	 }

   if (have_prefix)
	 {
		buf[n++] = bprintf ("%s:%d:",filename,line);
		buf[n++] = priv->flags & LOG_PRINT_FUNCTION ? bprintf ("%s(): ",function) : bprintf (" ");
	 }

   for (i = 0; i < n; i++)
	 {
		if (buf[i] == NULL)
		  {
			 int saved = errno;

			 for (i = 0; i < n; i++)
			   if (buf[i] != NULL)
				 mem_free (buf[i]);

			 errno = saved;

			 return (NULL);
		  }

		len += strlen (buf[i]);
	 }

   if ((buf[4] = mem_alloc ((len + 1) * sizeof (char))) == NULL)
	 {
		int saved = errno;
		for (i = 0; i < n; i++)
		  if (buf[i] != NULL)
			mem_free (buf[i]);
		errno = saved;
		return (NULL);
	 }

   *buf[4] = '\0';

   for (i = 0; i < n; i++)
	 {
		strcat (buf[4],buf[i]);
		mem_free (buf[i]);
	 }

   priv->syslvl = syslvl[level];

   return (buf[4]);
}

/******************************************
 ***    Logging backend (no locking)    ***
 ******************************************/

static int line_append (struct log_private *priv,const char *str)
{
   size_t len = strlen (str) + 1;
   char *ptr;

   if (priv->str != NULL)
	 {
		if ((ptr = mem_realloc (priv->str,(len + strlen (priv->str)) * sizeof (char))) == NULL)
		  return (-1);

		priv->str = ptr;
		strcat (priv->str,str);
	 }
   else
	 {
		if ((priv->str = mem_alloc (len * sizeof (char))) == NULL)
		  return (-1);
		strcpy (priv->str,str);
	 }

   return (0);
}

static int line_begin (struct log_private *priv,const char *filename,int line,const char *function,int level,const char *str)
{
   char *tmp;

   if ((tmp = prefix (priv,filename,line,function,level)) == NULL)
	 return (-1);

   if (line_append (priv,tmp) < 0)
	 {
		int saved = errno;
		mem_free (tmp);
		errno = saved;
		return (-1);
	 }

   mem_free (tmp);

   return (line_append (priv,str));
}

static int savetodisk (int fd,const char *str)
{
   ssize_t n,len = strlen (str);

   while (len && (n = write (fd,str,len)) != len)
	 {
		if (n < 0) return (-1);

		if (!n)
		  {
			 errno = EIO;
			 return (-1);
		  }

		len -= n;
	 }

   return (0);
}

static int flush_cache (struct log_private *priv,const char *filename,int line,const char *function)
{
   int saved;

   if (priv->cache.cache == NULL || !(priv->flags & LOG_DETECT_DUPLICATES))
	 return (0);

   if (savetodisk (priv->cache.fd,priv->cache.cache) < 0)
	 {
		error:
		saved = errno;
		mem_free (priv->cache.cache);
		priv->cache.cache = NULL;
		errno = saved;
		return (-1);
	 }

   if (priv->cache.hits)
	 {
		char *buf = prefix (priv,filename,line,function,_LOG_WARNING);

		if (buf == NULL)
		  goto error;

		if (savetodisk (priv->cache.fd,buf) < 0)
		  {
			 saved = errno;
			 mem_free (buf);
			 errno = saved;
			 goto error;
		  }

		mem_free (buf);

		sprintf (priv->cache.buf,"Message repeated %d times\n",priv->cache.hits + 1);

		if (savetodisk (priv->cache.fd,priv->cache.buf) < 0)
		  goto error;
	 }

   mem_free (priv->cache.cache);
   priv->cache.cache = NULL;

   return (0);
}

static void save_to_cache (struct log_private *priv)
{
   priv->cache.fd = priv->fd;
   priv->cache.hits = 0;
   priv->cache.cache = priv->str;
   priv->str = NULL;
}

static int line_end (struct log_private *priv,const char *filename,int line,const char *function)
{
   int saved;

   if (priv->flags & LOG_USE_SYSLOG)
	 {
		syslog (priv->syslvl,"%s",priv->str);
		mem_free (priv->str);
		priv->str = NULL;
		return (0);
	 }

   if (line_append (priv,"\n") < 0)
	 return (-1);

   if (priv->flags & LOG_DETECT_DUPLICATES)
	 {
		if (priv->cache.cache != NULL)
		  {
			 if (strcmp (priv->str,priv->cache.cache))
			   {
				  if (flush_cache (priv,filename,line,function) < 0)
					goto error;

				  save_to_cache (priv);
			   }
			 else
			   {
				  mem_free (priv->str);
				  priv->str = NULL;
				  priv->cache.hits++;
			   }
		  }
		else save_to_cache (priv);
	 }
   else
	 {
		if (savetodisk (priv->fd,priv->str) < 0)
		  {
			 error:
			 saved = errno;
			 mem_free (priv->str);
			 priv->str = NULL;
			 errno = saved;
			 return (-1);
		  }

		mem_free (priv->str);
		priv->str = NULL;
	 }

   return (0);
}

static int newline = 1;

static __inline__ void fd_update (struct log_private *priv,int level)
{
   if (!(priv->flags & (LOG_HAVE_LOGFILE | LOG_USE_SYSLOG)))
	 priv->fd = level <= _LOG_WARNING ? STDERR_FILENO : STDOUT_FILENO;
}

static int write_string (struct log_private *priv,const char *filename,int line,const char *function,int level,char *str)
{
   char *s,*tmp;
   static int prevlevel = _LOG_QUIET;

   if (level != prevlevel)
	 {
		fd_update (priv,prevlevel);
		if (!newline && line_end (priv,filename,line,function) < 0) goto error;
		newline = 1;
		prevlevel = level;
	 }

   fd_update (priv,level);

   for (s = str; (tmp = strchr (s,'\n')) != NULL; s = tmp + 1)
	 {
		*tmp = '\0';

		if (s == str && !newline)
		  {
			 newline = 1;
			 if (line_append (priv,s) < 0) goto error;
		  }
		else if (line_begin (priv,filename,line,function,level,s) < 0)
		  goto error;

		if (line_end (priv,filename,line,function) < 0) goto error;
	 }

   if (*s)
	 {
		if (newline)
		  {
			 if (line_begin (priv,filename,line,function,level,s) < 0)
			   goto error;
		  }
		else if (line_append (priv,s) < 0)
		  goto error;

		newline = 0;
	 }

   return (0);

error:
   if (priv->str != NULL)
	 {
		mem_free (priv->str);
		priv->str = NULL;
	 }
   return (-1);
}

static int print_one_line (struct log_private *priv,const char *filename,int line,const char *function,int level,const char *str)
{
   while (level != _LOG_QUIET && priv->level != _LOG_QUIET && level <= priv->level)
	 {
		fd_update (priv,level);

		if (!newline && line_end (priv,filename,line,function) < 0)
		  break;

		newline = 1;

		if (line_begin (priv,filename,line,function,level,str) < 0 || line_end (priv,filename,line,function) < 0)
		  break;

		return (flush_cache (priv,filename,line,function));
	 }

   if (priv->str != NULL)
	 {
		mem_free (priv->str);
		priv->str = NULL;
	 }

   return (-1);
}

/******************************************
 *** Application Programmer's Interface ***
 ******************************************/

static struct log_private log_private;
static int initialized = 0;

static int log_open_syslog (const char *str)
{
   char *facility;
   size_t i;

   if ((log_private.ident = mem_alloc (strlen (str) + 1)) == NULL)
	 return (-1);

   strcpy (log_private.ident,str);

   if ((facility = strchr (log_private.ident,'.')) == NULL)
	 return (-1);

   *facility++ = '\0';

   for (i = 0; facilitynames[i].c_name != NULL; i++)
	 if (!strcmp (facility,facilitynames[i].c_name))
	   {
		  openlog (log_private.ident,LOG_PID,facilitynames[i].c_val);
		  return (0);
	   }

   return (-1);
}

int log_open (const char *logfile,int loglevel,int flags)
{
   if (initialized)
	 {
		errno = EBUSY;
		return (-1);
	 }

   if (logfile != NULL)
	 {
		flags &= ~(LOG_HAVE_COLORS | LOG_HAVE_LOGFILE | LOG_USE_SYSLOG);
		flags |= !log_open_syslog (logfile) ? LOG_USE_SYSLOG : LOG_HAVE_LOGFILE;

		if (flags & LOG_USE_SYSLOG)
		  flags &= ~LOG_DETECT_DUPLICATES;
	 }
   else flags &= ~(LOG_HAVE_LOGFILE | LOG_USE_SYSLOG);

   if (flags & LOG_HAVE_LOGFILE)
	 {
		int saved;

		if ((log_private.filename = mem_alloc ((strlen (logfile) + 1) * sizeof (char))) == NULL)
		  return (-1);

		if ((log_private.fd = open (logfile,O_CREAT | O_APPEND | O_WRONLY,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
		  {
			 saved = errno;
			 mem_free (log_private.filename);
			 errno = saved;
			 return (-1);
		  }

		strcpy (log_private.filename,logfile);
	 }

   log_private.level = loglevel;
   log_private.flags = flags;
   log_private.str = NULL;

   if (flags & LOG_DETECT_DUPLICATES)
	 log_private.cache.cache = NULL;

   print_one_line (&log_private,__FILE__,__LINE__,__FUNCTION__,_LOG_VERBOSE,"Starting to log output.");

   initialized = 1;

   return (0);
}

void log_close (void)
{
   if (initialized)
	 {
		initialized = 0;

		print_one_line (&log_private,__FILE__,__LINE__,__FUNCTION__,_LOG_VERBOSE,"Stopped logging output.");

		if (log_private.flags & LOG_HAVE_LOGFILE)
		  {
			 close (log_private.fd);
			 mem_free (log_private.filename);
		  }

		if (log_private.flags & LOG_USE_SYSLOG)
		  {
			 closelog ();
			 mem_free (log_private.ident);
		  }
	 }
}

int log_reset_stub (const char *filename,int line,const char *function)
{
   if (!initialized || filename == NULL || function == NULL)
	 {
		errno = EINVAL;
		return (-1);
	 }

   if ((log_private.flags & LOG_HAVE_LOGFILE))
	 {
		print_one_line (&log_private,filename,line,function,_LOG_VERBOSE,"Attempting to reload log file.");
		print_one_line (&log_private,filename,line,function,_LOG_VERBOSE,"Stopped logging output.");

		close (log_private.fd);

		if ((log_private.fd = open (log_private.filename,O_CREAT | O_APPEND | O_WRONLY,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
		  {
			 int saved = errno;
			 mem_free (log_private.filename);
			 errno = saved;
			 return (-1);
		  }

		print_one_line (&log_private,filename,line,function,_LOG_VERBOSE,"Starting to log output again.");
		print_one_line (&log_private,filename,line,function,_LOG_VERBOSE,"Reload succeeded.");
	 }

   return (0);
}

int log_vprintf_stub (const char *filename,int line,const char *function,int level,const char *format,va_list ap)
{
   int result;
   char *buf;

   if (!initialized || filename == NULL || function == NULL)
	 {
		errno = EINVAL;
		return (-1);
	 }

   if (level == _LOG_QUIET || log_private.level == _LOG_QUIET || level > log_private.level)
	 return (0);

   if ((buf = vbprintf (format,ap)) == NULL)
	 return (-1);

   result = write_string (&log_private,filename,line,function,level,buf);

   mem_free (buf);

   return (result);
}

int log_printf_stub (const char *filename,int line,const char *function,int level,const char *format,...)
{
   va_list ap;
   int result;

   va_start (ap,format);
   result = log_vprintf_stub (filename,line,function,level,format,ap);
   va_end (ap);

   return (result);
}

int log_putc_stub (const char *filename,int line,const char *function,int level,int c)
{
   char s[2] = { c, '\0' };

   if (!initialized || filename == NULL || function == NULL)
	 {
		errno = EINVAL;
		return (-1);
	 }

   if (level == _LOG_QUIET || log_private.level == _LOG_QUIET || level > log_private.level)
	 return (0);

   return (write_string (&log_private,filename,line,function,level,s));
}

int log_puts_stub (const char *filename,int line,const char *function,int level,const char *str)
{
   char *s;
   int result;

   if (!initialized || filename == NULL || function == NULL)
	 {
		errno = EINVAL;
		return (-1);
	 }

   if (level == _LOG_QUIET || log_private.level == _LOG_QUIET || level > log_private.level)
	 return (0);

   if ((s = mem_alloc (sizeof (char) * (strlen (str) + 1))) == NULL)
	 return (-1);

   strcpy (s,str);
   result = write_string (&log_private,filename,line,function,level,s);
   mem_free (s);

   return (result);
}

int log_flush_stub (const char *filename,int line,const char *function)
{
   int saved;

   if (!initialized || filename == NULL || function == NULL)
	 {
		errno = EINVAL;
		return (-1);
	 }

   if (log_private.flags & LOG_USE_SYSLOG)
	 return (0);

   if (flush_cache (&log_private,filename,line,function))
	 return (-1);

   if (log_private.str != NULL)
	 {
		if (savetodisk (log_private.fd,log_private.str))
		  {
			 saved = errno;
			 mem_free (log_private.str);
			 log_private.str = NULL;
			 errno = saved;
			 return (-1);
		  }

		mem_free (log_private.str);
		log_private.str = NULL;

		if (log_private.flags & LOG_DETECT_DUPLICATES)
		  save_to_cache (&log_private);
	 }

   return (0);
}

