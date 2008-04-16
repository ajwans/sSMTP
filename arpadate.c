/*
 *  arpadate.c - get_arpadate() is a function returning the date in the
 *               ARPANET format (see RFC822 and RFC1123)
 *  Copyright (C) 1998 Hugo Haas
 *  
 *  Inspired by smail source code by Ronald S. Karr and Landon Curt Noll
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

#define ARPADATE_LENGTH	32

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void 
get_arpadate (char *d_string)
{
  struct tm *date;
#ifdef USE_OLD_ARPADATE
  static char *week_day[] =
  {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static char *month[] =
  {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
   "Aug", "Sep", "Oct", "Nov", "Dec"};
  static char timezone[3];

  time_t current;
  int offset, gmt_yday, gmt_hour, gmt_min;

  /* Get current time */
  (void) time (&current);

  /* Get GMT and then local dates */
  date = gmtime ((const time_t *) &current);
  gmt_yday = date->tm_yday;
  gmt_hour = date->tm_hour;
  gmt_min = date->tm_min;
  date = localtime ((const time_t *) &current);

  /* Calculates offset */

  offset = (date->tm_hour - gmt_hour) * 60 + (date->tm_min - gmt_min);
  /* Be careful, there can be problems if the day has changed between the
     evaluation of local and gmt's one */
  if (date->tm_yday != gmt_yday)
    {
      if (date->tm_yday == (gmt_yday + 1))
	offset += 1440;
      else if (date->tm_yday == (gmt_yday - 1))
	offset -= 1440;
      else
	offset += (date->tm_yday > gmt_yday) ? -1440 : 1440;
    }

  if (offset >= 0)
    sprintf (timezone, "+%02d%02d", offset / 60, offset % 60);
  else
    sprintf (timezone, "-%02d%02d", -offset / 60, -offset % 60);

  sprintf (d_string, "%s, %d %s %04d %02d:%02d:%02d %s",
	   week_day[date->tm_wday],
	   date->tm_mday, month[date->tm_mon], date->tm_year + 1900,
	   date->tm_hour, date->tm_min, date->tm_sec, timezone);
#else
	time_t now;

	/* RFC822 format string borrowed from GNU shellutils date.c */
	/* Using %d instead of %_d, the second one isn't portable */
	const char *format = "%a, %d %b %Y %H:%M:%S %z";

	now = time(NULL);

	date = localtime((const time_t *)&now);
	(void)strftime(d_string, ARPADATE_LENGTH, format, date);
#endif
}
