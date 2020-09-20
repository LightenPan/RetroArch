/*  RetroArch - A frontend for libretro.
 *  Copyright (C) 2014-2017 - Jean-André Santoni
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

#include <compat/strl.h>
#include <file/file_path.h>
#include <string/stdstring.h>
#include <lists/string_list.h>
#include <retro_miscellaneous.h>
#include <configuration.h>
#include <verbosity.h>
#include <features/features_cpu.h>

#include <libretro.h>
#include "../wifi_driver.h"
#include "../../retroarch.h"
#ifdef HAVE_GFX_WIDGETS
#include "../../gfx/gfx_widgets.h"
#endif

#define CACHE_INTERVAL_US 2000000

typedef struct {
   retro_time_t last_cache_update;
   struct string_list* ssids;
   struct string_list* active_ssids;
} nmcli_t;

static void *nmcli_init(void)
{
   nmcli_t *nmcli = (nmcli_t*)calloc(1, sizeof(nmcli_t));

   if (nmcli)
   {
       nmcli->ssids = string_list_new();
       nmcli->active_ssids = string_list_new();
       nmcli->last_cache_update = 0;
   }

   return nmcli;
}

static void nmcli_free(void *data)
{
   nmcli_t *nmcli = (nmcli_t*)data;
   if (nmcli)
   {
      if (nmcli->ssids)
         string_list_free(nmcli->ssids);
      if (nmcli->active_ssids)
         string_list_free(nmcli->active_ssids);
      free(nmcli);
   }
}

static bool nmcli_start(void *data)
{
   (void)data;
   return true;
}

static void nmcli_stop(void *data)
{
   (void)data;
}

static void nmcli_scan(void *data)
{
   nmcli_t *nmcli = (nmcli_t*)data;
   char line[512];
   FILE *cmd_file = NULL;
   union string_list_elem_attr attr;

   attr.i = RARCH_FILETYPE_UNSET;

   if (nmcli->ssids)
      string_list_free(nmcli->ssids);
   nmcli->ssids = string_list_new();

   cmd_file = popen("nmcli -f SSID dev wifi | tail -n+2", "r");
   while (fgets(line, 512, cmd_file))
   {
      string_trim_whitespace(line);
      if (string_list_find_elem(nmcli->ssids, line) == 0)
         string_list_append(nmcli->ssids, line, attr);
   }
   pclose(cmd_file);

   runloop_msg_queue_push(msg_hash_to_str(MSG_WIFI_SCAN_COMPLETE),
         1, 180, true, NULL, MESSAGE_QUEUE_ICON_DEFAULT,
         MESSAGE_QUEUE_CATEGORY_INFO);
}

static void nmcli_get_ssids(void *data, struct string_list *ssids)
{
   nmcli_t *nmcli = (nmcli_t*)data;
   unsigned i;
   union string_list_elem_attr attr;

   attr.i = RARCH_FILETYPE_UNSET;

   for (i = 0; i < nmcli->ssids->size; i++)
      string_list_append(ssids, nmcli->ssids->elems[i].data, attr);
}

static bool nmcli_ssid_is_online(void *data, unsigned idx)
{
   nmcli_t *nmcli = (nmcli_t*)data;
   char line[512];
   FILE *cmd_file = NULL;
   union string_list_elem_attr attr;

   retro_time_t curTs = cpu_features_get_time_usec();
   if (curTs > nmcli->last_cache_update + CACHE_INTERVAL_US)
   {
      nmcli->last_cache_update = curTs;

      if (nmcli->active_ssids)
         string_list_free(nmcli->active_ssids);
      nmcli->active_ssids = string_list_new();

      cmd_file = popen("nmcli -f NAME c show --active | tail -n+2", "r");

      attr.i = RARCH_FILETYPE_UNSET;
      while (fgets(line, 512, cmd_file))
         string_list_append(nmcli->active_ssids, string_trim_whitespace(line), attr);
      pclose(cmd_file);
   }

   return !!string_list_find_elem(nmcli->active_ssids, nmcli->ssids->elems[idx].data);
}

static bool nmcli_connect_ssid(void *data, unsigned idx, const char* passphrase)
{
   nmcli_t *nmcli = (nmcli_t*)data;
   char line[512];
   FILE *cmd_file = NULL;
   char cmd[256];

   snprintf(cmd, sizeof(cmd), "nmcli dev wifi connect \"%s\" password \"%s\" 2>&1",
         nmcli->ssids->elems[idx].data, passphrase);

   cmd_file = popen(cmd, "r");
   while (fgets(line, sizeof(line), cmd_file))
   {
#ifdef HAVE_GFX_WIDGETS
      if (!gfx_widgets_ready())
#endif
         runloop_msg_queue_push(line, 1, 180, true,
               NULL, MESSAGE_QUEUE_ICON_DEFAULT,
               MESSAGE_QUEUE_CATEGORY_INFO);
   }

   pclose(cmd_file);
   return true;
}

static void nmcli_tether_start_stop(void* data, bool start, char* configfile)
{
   (void)data;
   (void)start;
   (void)configfile;
}

wifi_driver_t wifi_nmcli = {
   nmcli_init,
   nmcli_free,
   nmcli_start,
   nmcli_stop,
   nmcli_scan,
   nmcli_get_ssids,
   nmcli_ssid_is_online,
   nmcli_connect_ssid,
   nmcli_tether_start_stop,
   "nmcli",
};
