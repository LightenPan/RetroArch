/*  RetroArch - A frontend for libretro.
 *  Copyright (C) 2011-2017 - Daniel De Matteis
 *
 *  RetroArch is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  RetroArch is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with RetroArch.
 *  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QUICK_KID__
#define QUICK_KID__

#include <stdlib.h>
#include <boolean.h>


#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif


// ºº×Ö×ª¾Å¹¬¸ñÊý×Ö
void chs_to_ninenum2(const char *keyword, bool only_first, char *out_str, int out_len);

#endif
