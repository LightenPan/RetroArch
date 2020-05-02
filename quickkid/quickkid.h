/*  RetroArch - A frontend for libretro.
 *  Copyright (C) 2010-2014 - Hans-Kristian Arntzen
 *  copyright (c) 2011-2017 - Daniel De Matteis
 *  copyright (c) 2016-2019 - Brad Parker
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

<<<<<<< HEAD:quickkid/quickkid.h
#ifndef QUICK_KID__
#define QUICK_KID__

#include <stdlib.h>
#include <boolean.h>


#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif


// ºº×Ö×ª¾Å¹¬¸ñÊý×Ö
int chs_to_ninenum(const char *keyword, bool only_first, char *out_str, int out_len);

=======
#ifndef __NETWORK_VIDEO_COMMON_H
#define __NETWORK_VIDEO_COMMON_H

typedef struct network
{
   unsigned video_width;
   unsigned video_height;
   unsigned screen_width;
   unsigned screen_height;
   void *ctx_data;
   const gfx_ctx_driver_t *ctx_driver;
   char address[256];
   uint16_t port;
   int fd;
} network_video_t;

>>>>>>> remotes/upstream/odroidgo2_drm_ctx_hw_scaling:gfx/common/network_common.h
#endif
