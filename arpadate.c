/*
 *  arpadate.c - arpadate functions for sSMTP
 *
 *  Copyright (C) 2010 Brane F. Gracnar
 *
 *  Inspired by smail source code by Ronald S. Karr and
 *  Landon Curt Noll and original arpadate.c by Hugo Haas
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/**
 * NOTE: original functions were removed becouse every
 *       UNIX system supports proper implementation of
 *       strftime(3) in libc. New ones are just more
 *       handy to use.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "arpadate.h"

#define DATE_FORMAT "%a, %e %b %Y %H:%M:%S %z"
#define DATE_FORMAT_TZ "%a, %e %b %Y %H:%M:%S %z (%Z)"

#define DATE_BUF_LEN 50
char date_buf[DATE_BUF_LEN];

char *get_arpadate (char *dst, size_t max, time_t *t, int with_tz) {
	struct tm *date;
	char *format = NULL;
	date = localtime(t);

	/** select format */
	format = (with_tz) ? DATE_FORMAT_TZ : DATE_FORMAT;

	/** sanitize destination buffer */
	memset(dst, '\0', max);

	/** just format the goddamn string... */
	strftime(dst, max, format, date);

	/** return destination buffer */
	return dst;
}

char *get_arpadate_now (void) {
	time_t now;
	now = time(NULL);
	return get_arpadate(date_buf, sizeof(date_buf), &now, 0);
}

char *get_arpadate_now_tz (void) {
	time_t now;
	now = time(NULL);
	return get_arpadate(date_buf, sizeof(date_buf), &now, 1);
}
