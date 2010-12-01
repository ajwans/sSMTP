/**
 *  arpadate.h - ssmtp arpadate functions
 *
 *  Copyright (C) 2010 Brane F. Gracnar
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

char *get_arpadate (char *dst, size_t max, time_t *t, int with_tz);
char *get_arpadate_now (void);
char *get_arpadate_now_tz (void);
