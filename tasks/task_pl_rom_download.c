/*  RetroArch - A frontend for libretro.
 *  Copyright (C) 2011-2017 - Daniel De Matteis
 *  Copyright (C) 2014-2017 - Jean-André Santoni
 *  Copyright (C) 2016-2019 - Brad Parker
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <string/stdstring.h>
#include <file/file_path.h>
#include <net/net_http.h>

#include "tasks_internal.h"
#include "task_file_transfer.h"

#include "../configuration.h"
#include "../file_path_special.h"
#include "../playlist.h"
#include "../libretro-common/include/rhash.h"
#include "../config.def.h"

#ifdef RARCH_INTERNAL
#ifdef HAVE_MENU
#include "../menu/menu_thumbnail_path.h"
#include "../menu/menu_cbs.h"
#include "../menu/menu_driver.h"
#endif
#endif

enum pl_rom_status
{
   PL_ROM_BEGIN = 0,
   PL_ROM_ITERATE_ENTRY,
   PL_ROM_ITERATE_TYPE,
   PL_ROM_END
};

typedef struct pl_rom_handle
{
   char *system;
   char *playlist_path;
   char *dir_thumbnails;
   playlist_t *playlist;
   menu_thumbnail_path_data_t *thumbnail_path_data;
   retro_task_t *http_task;
   size_t list_size;
   size_t list_index;
   unsigned type_idx;
   bool overwrite;
   enum pl_rom_status status;
   char *title;
} pl_rom_handle_t;

typedef struct pl_entry_rom_id
{
   char *playlist_path;
   size_t idx;
} pl_entry_rom_id_t;

typedef struct yun_save_rom_state_handle
{
   char save_state_path[1024];
   retro_task_t *http_task;
   void *save_state_buf;
   size_t save_state_buf_size;
   char save_state_buf_md5[64];
   size_t seq;
   size_t uploaded_file_size;
   bool only_fragment_failed;
   uint32_t fragment_buf_size;
} yun_save_rom_state_handle_t;

typedef struct get_ext_game_info_handle
{
   char taskid[1024];
   retro_task_t *http_task;
   char system[1024];
   char crc32[1024];
   playlist_t *playlist;
   uint32_t selected;
} get_ext_game_info_handle_t;

enum rom_download_status
{
   ROM_DOWNLOAD_BEGIN = 0,
   ROM_DOWNLOAD_NORMAL,
   ROM_DOWNLOAD_ZIP,
   ROM_DOWNLOAD_P7Z,
   ROM_DOWNLOAD_END
};

typedef struct rom_download_handle
{
   char rom_path[1024];
   char label[1024];
   char system[1024];
   char download_dir[1024];
   retro_task_t *http_task;
   enum rom_download_status download_status;
} rom_download_handle_t;

/*********************/
/* Utility Functions */
/*********************/

void md5_hexdigest(char *input, size_t input_len, char *output, size_t output_len)
{
   uint8_t hash[16] = {0};
   MD5_CTX ctx;
   MD5_Init(&ctx);
   MD5_Update(&ctx, (void*)input, input_len);
   MD5_Final(hash, &ctx);
   snprintf(output, output_len, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      hash[ 0], hash[ 1], hash[ 2], hash[ 3], hash[ 4], hash[ 5], hash[ 6], hash[ 7],
      hash[ 8], hash[ 9], hash[10], hash[11],hash[12], hash[13], hash[14], hash[15]);
}

void clac_retrogame_allinone_sign(char *url_query, int len)
{
   settings_t *settings = config_get_ptr();
   if (settings == NULL)
   {
      return;
   }

   // sign计算方法：
   // 1、获取password的md5: pwdmd5=md5(password)
   // 2、获取password的用户加盐userpwdmd5: md5(username+pwdmd5)
   // 3、获取最终签名sign=md5(username+time+userpwdmd5)
   uint32_t now = (uint32_t)time(NULL);
   char *username = settings->arrays.retrogame_allinone_username;
   char *password = settings->arrays.retrogame_allinone_password;
   char *mcode = settings->arrays.retrogame_allinone_mcode;

   // 1、获取password的md5: pwdmd5=md5(password)
   char plain_pwd[1024] = {0};
   char pwdm5[64] = {0};
   snprintf(plain_pwd, sizeof(plain_pwd), "%s", password);
   md5_hexdigest(plain_pwd, strlen(plain_pwd), pwdm5, sizeof(pwdm5));

   // 2、获取password的用户加盐userpwdmd5: md5(username+pwdmd5)
   char plain_userpwdmd5[1024] = {0};
   char userpwdmd5[64] = {0};
   snprintf(plain_userpwdmd5, sizeof(plain_userpwdmd5), "%s %s", username, pwdm5);
   md5_hexdigest(plain_userpwdmd5, strlen(plain_userpwdmd5), userpwdmd5, sizeof(userpwdmd5));

   // 3、获取最终签名sign=md5(username+time+userpwdmd5)
   char plain_sign[1024] = {0};
   char sign[64] = {0};
   snprintf(plain_sign, sizeof(plain_sign), "%s %u %s", username, now, userpwdmd5);
   md5_hexdigest(plain_sign, strlen(plain_sign), sign, sizeof(sign));

   RARCH_LOG("clac_retrogame_allinone_sign log info. acc: %s, time: %u, pwd: %s, pwdm5: %s, userpwdmd5: %s, sign: %s\n",
      username, now, password, pwdm5, userpwdmd5, sign);

   // 组合账号密码参数
   char fmt[1024] = {0};
   snprintf(fmt, sizeof(fmt), "acc=%s&time=%u&sign=%s&mcode=%s", username, now, sign, mcode);
   strncpy(url_query, fmt, len);
}

char *genYunSaveStateUrl(const char *savename, const char *save_buf_md5)
{
   char save_state_url[PATH_MAX_LENGTH];
   char acc_query_str[1024] = {0};
   clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
   snprintf(save_state_url, sizeof(save_state_url),
      "%s/api/UserGameData/SaveState?%s&savename=%s&save_buf_md5=%s",
      network_wiki_api_url, acc_query_str, savename, save_buf_md5);
   return strdup(save_state_url);
}

char *genYunSaveStateFragmentUrl(const char *savename, const char *save_buf_md5, int seq,
                                 const char *fragment_save_buf_md5)
{
   char save_state_url[PATH_MAX_LENGTH];
   char acc_query_str[1024] = {0};
   clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
   snprintf(save_state_url, sizeof(save_state_url),
      "%s/api/UserGameData/SaveStateFragment?%s&savename=%s&save_buf_md5=%s&seq=%u&save_buf_md5_fragment=%s",
      network_wiki_api_url, acc_query_str, savename, save_buf_md5, seq, fragment_save_buf_md5);
   return strdup(save_state_url);
}

void cpyYunSaveStateFragmentUrl(const char *savename, const char *save_buf_md5, int seq,
                                 const char *fragment_save_buf_md5, char *outurl, int outlen)
{
   char save_state_url[PATH_MAX_LENGTH];
   char acc_query_str[1024] = {0};
   clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
   snprintf(save_state_url, sizeof(save_state_url),
      "%s/api/UserGameData/SaveStateFragment?%s&savename=%s&save_buf_md5=%s&seq=%u&save_buf_md5_fragment=%s",
      network_wiki_api_url, acc_query_str, savename, save_buf_md5, seq, fragment_save_buf_md5);
   strlcpy(outurl, save_state_url, outlen);
}

char *genYunLoadStateUrl(char *loadname)
{
   char load_state_url[PATH_MAX_LENGTH];
   char acc_query_str[1024] = {0};
   clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
   snprintf(load_state_url, sizeof(load_state_url),
      "%s/api/UserGameData/LoadState?%s&loadname=%s",
      network_wiki_api_url, acc_query_str, loadname);
   return strdup(load_state_url);
}

/* Fetches local and remote paths for current thumbnail
 * of current type */
static bool get_rom_paths(
   pl_rom_handle_t *pl_thumb,
   char *path, size_t path_size,
   char *url, size_t url_size)
{
   RARCH_LOG("get_rom_paths start\n");
   const char *system      = NULL;
   const char *db_name     = NULL;
   const char *img_name    = NULL;
   const char *sub_dir     = NULL;
   const char *system_name = NULL;
   char content_dir[PATH_MAX_LENGTH];
   char raw_url[2048];
   char tmp_buf[PATH_MAX_LENGTH];
   settings_t *settings = config_get_ptr();

   content_dir[0] = '\0';
   raw_url[0]     = '\0';
   tmp_buf[0]     = '\0';

   if (!pl_thumb->thumbnail_path_data)
      return false;

   if (string_is_empty(pl_thumb->dir_thumbnails))
      return false;

   /* Extract required strings */
   menu_thumbnail_get_system(pl_thumb->thumbnail_path_data, &system);
   menu_thumbnail_get_db_name(pl_thumb->thumbnail_path_data, &db_name);
   if (!menu_thumbnail_get_basename(pl_thumb->thumbnail_path_data, &img_name))
      return false;

   /* Dermine system name */
   if (string_is_empty(db_name))
   {
      if (string_is_empty(system))
         return false;

      /* If this is a content history or favorites playlist
       * then the current 'path_data->system' string is
       * meaningless. In this case, we fall back to the
       * content directory name */
      if (string_is_equal(system, "history") ||
          string_is_equal(system, "favorites"))
      {
         if (!menu_thumbnail_get_content_dir(
               pl_thumb->thumbnail_path_data, content_dir, sizeof(content_dir)))
            return false;

         system_name = content_dir;
      }
      else
         system_name = system;
   }
   else
      system_name = db_name;

   /* Generate local path */
   fill_pathname_join(tmp_buf, pl_thumb->dir_thumbnails, system_name, path_size);
   if (!path_is_valid(tmp_buf))
   {
      path_mkdir(tmp_buf);
   }
   fill_pathname_join(path, tmp_buf, img_name, path_size);

   if (string_is_empty(path))
      return false;

   /* Generate remote path */
   strlcpy(raw_url, file_path_str(FILE_PATH_ROM_URL), sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, system_name, sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, img_name, sizeof(raw_url));

   if (string_is_empty(raw_url))
      return false;

   net_http_urlencode_full(url, raw_url, url_size);

   char url_query[1024] = {0};
   clac_retrogame_allinone_sign(url_query, sizeof(url_query));
   strlcat(url, "?", url_size);
   strlcat(url, url_query, url_size);

   RARCH_LOG("get_rom_paths log result. url: %s, path: %s, url_query: %s\n", url, path, url_query);

   if (string_is_empty(url))
      return false;

   return true;
}

/* Download thumbnail of the current type for the current
 * playlist entry */
static void download_pl_rom(pl_rom_handle_t *pl_thumb)
{
   RARCH_LOG("download_pl_rom start\n");
   char path[PATH_MAX_LENGTH];
   char url[2048];

   path[0] = '\0';
   url[0] = '\0';

   /* Check if paths are valid */
   if (get_rom_paths(pl_thumb, path, sizeof(path), url, sizeof(url)))
   {
      /* Only download missing thumbnails */
      if (!path_is_valid(path) || pl_thumb->overwrite)
      {
         file_transfer_t *transf = (file_transfer_t*)calloc(1, sizeof(file_transfer_t));
         if (!transf)
            return; /* If this happens then everything is broken anyway... */

         /* Initialise file transfer */
         transf->enum_idx = MENU_ENUM_LABEL_CB_SINGLE_ROM;
         strlcpy(transf->path, path, sizeof(transf->path));
         if (pl_thumb && pl_thumb->title)
         {
            strlcpy(transf->title, pl_thumb->title, sizeof(transf->title));
            // strlcat(transf->title, "（下载需要设置魔改账号）", sizeof(transf->title));
         }
         RARCH_LOG("download_pl_rom. url: %s, path: %s, title: %s\n", url, path, transf->title);

         /* Note: We don't actually care if this fails since that
          * just means the file is missing from the server, so it's
          * not something we can handle here... */
         pl_thumb->http_task = (retro_task_t*)task_push_http_transfer(url, false, NULL, cb_generic_download, transf);
      }
   }
}

void yun_save_rom_state_cb(retro_task_t *task, void *task_data, void *user_data, const char *error)
{
   http_transfer_data_t *data         = (http_transfer_data_t*)task_data;
   char status[1024]                  = {0};
   char message[1024]                 = {0};
   char errmsg[1024]                  = {0};

   // 遍历json的变量
   char* body_copy                   = NULL;
   char curr                         = 0;
   int i                             = 0;
   int start                         = -1;
   char* found_string                = NULL;
   int curr_state                    = 0;

   if (!data || error)
      goto finish;

   data->data = (char*)realloc(data->data, data->len + 1);
   if (!data->data)
      goto finish;

   data->data[data->len] = '\0';

   /* Parse JSON body for the image and sound data */
   body_copy = strdup(data->data);
   while (true)
   {
      curr = (char)*(body_copy+i);
      if (curr == '\0')
          break;
      if (curr == '\"')
      {
         if (start == -1)
            start = i;
         else
         {
            found_string = (char*)malloc(i-start);
            strncpy(found_string, body_copy+start+1, i-start-1);
            *(found_string+i-start-1) = '\0';
            if (curr_state == 1)
            {
               strncpy(status, found_string, sizeof(status) - 1);
               curr_state = 0;
            }
            else if (curr_state == 2)
            {
               strncpy(message, found_string, sizeof(message) - 1);
               curr_state = 0;
            }
            else if (strcmp(found_string, "status")==0)
            {
              curr_state = 1;
              free(found_string);
            }
            else if (strcmp(found_string, "message")==0)
            {
              curr_state = 2;
              free(found_string);
            }
            else
              curr_state = 0;
            start = -1;
         }
      }
      i++;
   }

   if (found_string)
       free(found_string);

   if (body_copy)
      free(body_copy);

   if (strcmp(status, "SUCCESS") == 0)
   {
      runloop_msg_queue_push(
         "云存档成功",
         2, 180, true,
         NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_SUCCESS);
   }
   else
   {
      snprintf(errmsg, sizeof(errmsg), "云存档失败，服务器错误信息为：%s", message);
      runloop_msg_queue_push(
         errmsg,
         2, 180, true,
         NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_ERROR);
   }

finish:
   if (error)
      RARCH_ERR("%s: %s\n", msg_hash_to_str(MSG_DOWNLOAD_FAILED), error);

   if (data)
   {
      if (data->data)
         free(data->data);
      free(data);
   }
   if (user_data)
      free(user_data);

   if (body_copy)
      free(body_copy);
}

bool yun_save_rom_state(char *path)
{
   settings_t *settings = config_get_ptr();
   bool isopen = settings->bools.network_on_demand_yunsavestate;
   char show_errmsg[1024] = {0};
   const char *savename = path_basename(path);
   RARCH_LOG("yun_save_rom_state begin. savyun_save_rom_state log infoename: %s, savepath: %s, isopen: %d\n", savename, path, isopen);

   if (!isopen)
   {
      return true;
   }

   const int64_t max_buf_size = 10*1024*1024;
   void *file_buf = NULL;
   int64_t file_buf_size = 0;
   char *b64_file_buf = NULL;
   int b64_file_buf_len = 0;

   if (!path_is_valid(path))
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "存档文件无效：%s", path);
      return false;
   }

   filestream_read_file(path, &file_buf, &file_buf_size);
   if (string_is_empty(file_buf) || file_buf_size == 0)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "读取存档文件失败：%s", path);
      goto finish;
   }

   if (file_buf_size > max_buf_size)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "存档文件太大：%s", path);
      goto finish;
   }

   b64_file_buf = base64(file_buf, (int)file_buf_size, &b64_file_buf_len);
   if (!b64_file_buf)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "存档文件编码成Base64错误：%s", path);
      goto finish;
   }

   // 计算存档MD5保证存档是正确的
   char save_buf_md5[64] = {0};
   md5_hexdigest(file_buf, file_buf_size, save_buf_md5, sizeof(save_buf_md5));

   char *save_state_url = genYunSaveStateUrl(savename, save_buf_md5);
   {
      RARCH_LOG("yun_save_rom_state log info. url: %s, b64_len: %u\n", save_state_url, b64_file_buf_len);
      task_push_http_post_transfer(save_state_url, b64_file_buf, false, NULL, yun_save_rom_state_cb, NULL);
   }
   free(save_state_url);

finish:
   if (strlen(show_errmsg) > 0)
   {
      runloop_msg_queue_push(show_errmsg,2, 180, true,
         NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_ERROR);
   }

   if (b64_file_buf)
      free(b64_file_buf);
   if (file_buf)
      free(file_buf);

   return true;
}

void yun_load_rom_state_cb(retro_task_t *task, void *task_data, void *user_data, const char *error)
{
   RARCH_LOG("yun_load_rom_state_cb bgein. error: %s\n", error);

   char show_errmsg[1024] = {0};
   struct sram_block *blocks = NULL;
   settings_t *settings = config_get_ptr();
   bool resume = false;
   file_transfer_t *transf = (file_transfer_t*)user_data;
   http_transfer_data_t *data = (http_transfer_data_t*)task_data;

   if (!transf && !transf->path)
      goto finish;

   if (error && strlen(error) > 0 && transf->title)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "云存档%s下载失败", transf->title);
      goto finish;
   }

   if (!data || !data->data)
      goto finish;

   RARCH_LOG("yun_load_rom_state_cb begin. savepath: %s, data_len: %u\n", transf->path, data->len);

   // 保存存档文件
   if (!filestream_write_file(transf->path, data->data, data->len))
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "保存存档文件失败：%s", transf->path);
      goto finish;
   }

   // 处理加载存档逻辑
   retro_ctx_serialize_info_t serial_info;
   serial_info.data_const = data->data;
   serial_info.size = data->len;
   if (!core_unserialize(&serial_info))
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "当前核心加载存档数据失败：%s", transf->path);
      goto finish;
   }

   if (settings && settings->bools.menu_savestate_resume)
   {
      generic_action_ok_command(CMD_EVENT_RESUME);
   }

finish:
   if (strlen(show_errmsg) > 0)
   {
      runloop_msg_queue_push(show_errmsg,2, 180, true,
         NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_ERROR);
   }

   if (data)
   {
      if (data->data)
         free(data->data);
      free(data);
   }

   if (transf)
      free(transf);
}

bool yun_load_rom_state(char *path)
{
   char *loadname = path_basename(path);
   RARCH_LOG("yun_load_rom_state begin. loadname: %s, path: %s\n", loadname, path);

   file_transfer_t *transf = (file_transfer_t*)calloc(1, sizeof(file_transfer_t));
   if (!transf)
   {
      RARCH_ERR("yun_load_rom_state calloc failed. loadname: %s\n", loadname);
      return false;
   }
   // 设置存档文件的保存文件路径
   snprintf(transf->title, sizeof(transf->title), "%s", loadname);
   strlcpy(transf->path, path, sizeof(transf->path));

   char *load_state_url = genYunLoadStateUrl(loadname);
   {
      RARCH_LOG("yun_load_rom_state log http info. url: %s, loadname: %s, path: %s\n", load_state_url, loadname, path);
      task_push_http_transfer(load_state_url, false, NULL, yun_load_rom_state_cb, transf);
   }
   free(load_state_url);
   return true;
}

void task_push_rom_download(bool iszip, const char *title, const char *url, const char *savepath)
{
   file_transfer_t *transf = (file_transfer_t*)calloc(1, sizeof(file_transfer_t));
   if (!transf)
      return; /* If this happens then everything is broken anyway... */

   transf->enum_idx = MENU_ENUM_LABEL_CB_SINGLE_ROM;
   if (iszip) {
      transf->enum_idx = MENU_ENUM_LABEL_CB_SINGLE_ZIPROM;
   }
   strlcpy(transf->path, savepath, sizeof(transf->path));
   strlcpy(transf->title, title, sizeof(transf->title));
   // strlcat(transf->title, "（下载需要设置魔改账号）", sizeof(transf->title));
	RARCH_LOG("task_push_rom_download. url: %s, savepath: %s, title: %s\n", url, savepath, transf->title);
   task_push_http_transfer(url, false, NULL, cb_generic_download, transf);
}

void task_push_rom_download_multi(rom_download_handle_t *pHandle, bool iszip, const char *basename)
{
   char local_save_path[1024] = {0};
   fill_pathname_join(local_save_path, pHandle->download_dir, basename, sizeof(local_save_path));
   // 获取rom下载地址
   char url_query[1024] = {0};
   clac_retrogame_allinone_sign(url_query, sizeof(url_query));
   char raw_url[1024] = {0};
   strlcpy(raw_url, file_path_str(FILE_PATH_ROM_URL), sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, pHandle->system, sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, basename, sizeof(raw_url));
   strlcat(raw_url, "?", sizeof(raw_url));
   strlcat(raw_url, url_query, sizeof(raw_url));

   file_transfer_t *transf = (file_transfer_t*)calloc(1, sizeof(file_transfer_t));
   if (!transf)
      return; /* If this happens then everything is broken anyway... */

   transf->enum_idx = MENU_ENUM_LABEL_CB_SINGLE_ROM;
   if (iszip) {
      transf->enum_idx = MENU_ENUM_LABEL_CB_SINGLE_ZIPROM;
   }
   strlcpy(transf->path, local_save_path, sizeof(transf->path));
   strlcpy(transf->title, pHandle->label, sizeof(transf->title));
   // strlcat(transf->title, "（下载需要设置魔改账号）", sizeof(transf->title));
   RARCH_LOG("task_push_rom_download_multi log info. "
      "raw_url: %s, rom_path: %s, system: %s"
      ", download_dir: %s, iszip: %u, save_path: %s, title: %s\n",
      raw_url, pHandle->rom_path, pHandle->system, pHandle->download_dir, iszip, local_save_path, transf->title);
   task_push_http_transfer(raw_url, false, NULL, cb_generic_download, transf);
}

static void free_rom_download_handle(rom_download_handle_t *pHandle)
{
   if (!pHandle)
      return;

   free(pHandle);
   pHandle = NULL;
}

static void task_rom_download_handler(retro_task_t *task)
{
   if (!task)
      goto task_finished;

   if (task_get_cancelled(task))
      goto task_finished;

   rom_download_handle_t *pHandle = (rom_download_handle_t*)task->state;
   if (!pHandle)
      goto task_finished;

   // 状态结束
   if (pHandle->download_status == ROM_DOWNLOAD_END)
   {
      goto task_finished;
   }

   // 确保只有一个http任务在执行
   if (pHandle->http_task && !task_get_finished(pHandle->http_task))
   {
      return;
   }

   bool iszip = false;
   char new_basename[256] = {0};
   const char *basename = path_basename(pHandle->rom_path);
   if (strcmp(path_get_extension(basename), "cue") == 0)
   {
      iszip = true;
   }

   switch (pHandle->download_status)
   {
   case ROM_DOWNLOAD_BEGIN:
      {
         pHandle->download_status = ROM_DOWNLOAD_NORMAL;
         if (iszip)
         {
            pHandle->download_status = ROM_DOWNLOAD_ZIP;
         }
      }
      break;
   case ROM_DOWNLOAD_NORMAL:
      {
         strlcpy(new_basename, basename, sizeof(new_basename));
         task_push_rom_download_multi(pHandle, iszip, new_basename);
         pHandle->download_status = ROM_DOWNLOAD_END;
      }
      break;
   case ROM_DOWNLOAD_ZIP:
      {
         // zip解压后最终目录是，两个文件名的目录
         // 例如PCECD游戏hero.cue，则最终目录是downloads/PCECD/hero/hero.cue
         char filename_buf[256] = {0};
         strlcpy(filename_buf, basename, sizeof(filename_buf));
         char *filename = path_remove_extension(filename_buf);
         strlcpy(new_basename, filename, sizeof(new_basename));
         strlcat(new_basename, ".zip", sizeof(new_basename));
         task_push_rom_download_multi(pHandle, iszip, new_basename);
         pHandle->download_status = ROM_DOWNLOAD_P7Z;
      }
      break;
   case ROM_DOWNLOAD_P7Z:
      {
         // p7z解压后最终目录是，两个文件名的目录
         // 例如PCECD游戏hero.cue，则最终目录是downloads/PCECD/hero/hero.cue
         char filename_buf[256] = {0};
         strlcpy(filename_buf, basename, sizeof(filename_buf));
         char *filename = path_remove_extension(filename_buf);
         strlcpy(new_basename, filename, sizeof(new_basename));
         strlcat(new_basename, ".7z", sizeof(new_basename));
         task_push_rom_download_multi(pHandle, iszip, new_basename);
         pHandle->download_status = ROM_DOWNLOAD_END;
      }
   case ROM_DOWNLOAD_END:
   default:
      break;
   }
   return;

task_finished:
   if (task)
      task_set_finished(task, true);

   free_rom_download_handle(pHandle);
}

static bool task_rom_download_finder(retro_task_t *task, void *user_data)
{
   if (!task || !user_data)
      return false;

   if (task->handler != task_rom_download_handler)
      return false;

   rom_download_handle_t *pHandle = (rom_download_handle_t*)task->state;
   if (!pHandle)
      return false;

   return string_is_equal((const char*)user_data, pHandle->rom_path);
}

bool task_push_pl_entry_rom_download(
      const char *system,
      playlist_t *playlist,
      unsigned idx,
      bool overwrite,
      bool mute)
{
   RARCH_LOG("task_push_pl_entry_rom_download start\n");
   settings_t *settings = config_get_ptr();
   if (!settings)
      return false;

   /* Sanity check */
   if (!playlist)
      return false;

   if (string_is_empty(system))
      return false;

   if (idx >= playlist_size(playlist))
      return false;

   /* Only parse supported playlist types */
   if (string_is_equal(system, "images_history") ||
      string_is_equal(system, "music_history") ||
      string_is_equal(system, "video_history"))
      return false;

   struct playlist_entry *p_playlist_entry = NULL;
   playlist_get_index(playlist, idx, &p_playlist_entry);
   if (p_playlist_entry == NULL)
   {
      return false;
   }

   char real_rom_path[1024] = {0};
   playlist_get_exist_rom_path(p_playlist_entry, real_rom_path, sizeof(real_rom_path));
   RARCH_LOG("task_push_pl_entry_rom_download log path: %s, real_rom_path: %s\n",
      p_playlist_entry->path, real_rom_path);

   // 如果文件存在，就不需要再下载
   if (path_is_valid(real_rom_path))
   {
      succ_msg_queue_push("游戏已下载");
      return true;
   }

   // 一些常量初始化
   char db_name[1024] = {0};
   strlcpy(db_name, p_playlist_entry->db_name, sizeof(db_name));
   char *system_name = path_remove_extension(db_name);
   char *basename = path_basename(p_playlist_entry->path);
   char url_query[1024] = {0};
   clac_retrogame_allinone_sign(url_query, sizeof(url_query));

   // 获取本地文件地址
   char tmp_buf[1024] = {0};
   char local_rom_path[1024] = {0};
   fill_pathname_join(tmp_buf, settings->paths.directory_core_assets, system_name, sizeof(tmp_buf));
   if (!path_is_valid(tmp_buf))
   {
      path_mkdir(tmp_buf);
   }

   // 如果扩展名是.cue，需要去下载mgzip包，并解压到子文件夹
   bool iszip = false;
   char new_basename[256] = {0};
   if (strcmp(path_get_extension(basename), "cue") == 0)
   {
      // mgzip解压后最终目录是，两个文件名的目录
      // 例如PCECD游戏hero.cue，则最终目录是downloads/PCECD/hero/hero.cue
      char filename_buf[256] = {0};
      strlcpy(filename_buf, basename, sizeof(filename_buf));
      char *filename = path_remove_extension(filename_buf);
      strlcpy(new_basename, filename, sizeof(new_basename));
      strlcat(new_basename, ".zip", sizeof(new_basename));
      iszip = true;
   }
   else
   {
      strlcpy(new_basename, basename, sizeof(new_basename));
   }
   fill_pathname_join(local_rom_path, tmp_buf, new_basename, sizeof(local_rom_path));
   RARCH_LOG("task_push_pl_entry_rom_download log info. basename: %s, system_name: %s, local_rom_path: %s\n",
      basename, system_name, local_rom_path);

   // 获取正常rom下载地址
   char raw_url[1024] = {0};
   strlcpy(raw_url, file_path_str(FILE_PATH_ROM_URL), sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, system_name, sizeof(raw_url));
   strlcat(raw_url, "/", sizeof(raw_url));
   strlcat(raw_url, new_basename, sizeof(raw_url));
   strlcat(raw_url, "?", sizeof(raw_url));
   strlcat(raw_url, url_query, sizeof(raw_url));
   if (!string_is_empty(raw_url))
   {
      RARCH_LOG("task_push_pl_entry_rom_download log info. iszip: %d, basename: %s, system_name: %s, local_rom_path: %s, raw_url: %s\n",
         iszip, new_basename, system_name, local_rom_path, raw_url);
      task_push_rom_download(iszip, p_playlist_entry->label, raw_url, local_rom_path);
   }
   return true;
}

bool task_push_pl_entry_rom_download_new_with_p7z(
      const char *system,
      playlist_t *playlist,
      unsigned idx,
      bool overwrite,
      bool mute)
{
   RARCH_LOG("task_push_pl_entry_rom_download start\n");
   settings_t *settings = config_get_ptr();
   if (!settings)
      return false;

   /* Sanity check */
   if (!playlist)
      return false;

   if (string_is_empty(system))
       return false;

   if (idx >= playlist_size(playlist))
      return false;

   /* Only parse supported playlist types */
   if (string_is_equal(system, "images_history") ||
       string_is_equal(system, "music_history") ||
       string_is_equal(system, "video_history"))
       return false;

   const struct playlist_entry *p_playlist_entry = NULL;
   playlist_get_index(playlist, idx, &p_playlist_entry);
   if (p_playlist_entry == NULL)
   {
      return false;
   }

   char real_rom_path[1024] = {0};
   playlist_get_exist_rom_path(p_playlist_entry, real_rom_path, sizeof(real_rom_path));
   RARCH_LOG("task_push_pl_entry_rom_download log path: %s, real_rom_path: %s\n",
      p_playlist_entry->path, real_rom_path);

   // 如果文件存在，就不需要再下载
   if (path_is_valid(real_rom_path))
   {
      succ_msg_queue_push("游戏已下载");
      return true;
   }

   // 分配任务上下文
   rom_download_handle_t *pHandle = (rom_download_handle_t*)malloc(sizeof(rom_download_handle_t));
   if (!pHandle)
   {
      error_msg_queue_push("分配任务上下文失败：%s", real_rom_path);
      goto error;
   }

   // 获取该文件下载目录
   char download_dir[1024] = {0};
   char local_rom_path[1024] = {0};
   fill_pathname_join(download_dir, settings->paths.directory_core_assets, system, sizeof(download_dir));
   if (!path_is_valid(download_dir))
   {
      path_mkdir(download_dir);
   }

   // 获取rom列表上的系统名
   char db_name[1024] = {0};
   strlcpy(db_name, p_playlist_entry->db_name, sizeof(db_name));
   char *system_name = path_remove_extension(db_name);

   strncpy(pHandle->rom_path, real_rom_path, sizeof(pHandle->rom_path));
   strncpy(pHandle->download_dir, download_dir, sizeof(pHandle->download_dir));
   strncpy(pHandle->label, p_playlist_entry->label, sizeof(pHandle->label));
   strncpy(pHandle->system, system_name, sizeof(pHandle->system));
   pHandle->http_task = NULL;
   pHandle->download_status = ROM_DOWNLOAD_BEGIN;

   // 后台任务变量
   task_finder_data_t find_data;
   retro_task_t *task = task_init();

   /* Concurrent download of thumbnails for the same
    * playlist is not allowed */
   find_data.func                = task_rom_download_finder;
   find_data.userdata            = (void*)pHandle->rom_path;
   if (task_queue_find(&find_data))
      goto error;

   /* Configure task */
   task->handler                 = task_rom_download_handler;
   task->state                   = pHandle;
   task->title                   = strdup(pHandle->label);
   task->alternative_look        = true;
   task->progress                = 0;
   task_queue_push(task);
   return true;

error:
   if (task)
   {
      if (task->title)
      {
         free(task->title);
         task->title = NULL;
      }

      free(task);
      task = NULL;
   }

   if (pHandle)
   {
      free(pHandle);
      pHandle = NULL;
   }
   return false;
}

void upload_yun_save_state_fragment_cb(retro_task_t *task, void *task_data, void *user_data, const char *error)
{
   RARCH_LOG("upload_yun_save_state_fragment_cb begin\n");
   http_transfer_data_t *data = (http_transfer_data_t*)task_data;
   yun_save_rom_state_handle_t *ysrsh = (yun_save_rom_state_handle_t *)user_data;
   char status[1024] = {0};
   char message[1024] = {0};
   char errmsg[1024] = {0};

   // 遍历json的变量
   char* body_copy                   = NULL;
   char curr                         = 0;
   int i                             = 0;
   int start                         = -1;
   char* found_string                = NULL;
   int curr_state                    = 0;

   if (!data || error || !ysrsh)
      goto finish;

   data->data = (char*)realloc(data->data, data->len + 1);
   if (!data->data)
      goto finish;

   data->data[data->len] = '\0';

   /* Parse JSON body for the image and sound data */
   body_copy = strdup(data->data);
   while (true)
   {
      curr = (char)*(body_copy+i);
      if (curr == '\0')
         break;
      if (curr == '\"')
      {
         if (start == -1)
            start = i;
         else
         {
            found_string = (char*)malloc(i-start);
            strncpy(found_string, body_copy+start+1, i-start-1);
            *(found_string+i-start-1) = '\0';
            if (curr_state == 1)
            {
               strncpy(status, found_string, sizeof(status) - 1);
               curr_state = 0;
            }
            else if (curr_state == 2)
            {
               strncpy(message, found_string, sizeof(message) - 1);
               curr_state = 0;
            }
            else if (strcmp(found_string, "status")==0)
            {
               curr_state = 1;
               free(found_string);
            }
            else if (strcmp(found_string, "message")==0)
            {
               curr_state = 2;
               free(found_string);
            }
            else
               curr_state = 0;
            start = -1;
         }
      }
      i++;
   }

   if (found_string)
      free(found_string);

   if (strcmp(status, "SUCCESS") == 0)
   {
      // snprintf(errmsg, sizeof(errmsg), "云存档成功");
      // runloop_msg_queue_push(errmsg, 2, 180, true,
      //    NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_SUCCESS);
      ysrsh->uploaded_file_size = ysrsh->uploaded_file_size + ysrsh->fragment_buf_size;
      ysrsh->seq++;
      RARCH_LOG("upload_yun_save_state_fragment_cb succ. path: %s, next_seq: %u, uploaded_file_size: %u, save_state_buf_size: %u\n",
         ysrsh->save_state_path, ysrsh->seq, ysrsh->uploaded_file_size, ysrsh->save_state_buf_size);
   }
   else
   {
      snprintf(errmsg, sizeof(errmsg), "云存档失败，服务器错误信息为：%s", message);
      runloop_msg_queue_push(errmsg, 2, 180, true,
         NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_ERROR);
      // 上传接口出错，需要释放hander
      ysrsh->only_fragment_failed = true;
   }

finish:
   if (error)
      RARCH_ERR("%s: %s\n", msg_hash_to_str(MSG_DOWNLOAD_FAILED), error);

   if (data)
   {
      if (data->data)
         free(data->data);
      free(data);
   }

   if (body_copy)
      free(body_copy);
}

bool upload_yun_save_state_fragment(yun_save_rom_state_handle_t *ysrsh)
{
   if (!ysrsh)
      return false;

   if (ysrsh->uploaded_file_size >= ysrsh->save_state_buf_size)
      return false;

   const char show_errmsg[1024] = {0};
   char *fragment_buf = ysrsh->save_state_buf + ysrsh->uploaded_file_size;
   size_t fragment_buf_size = ysrsh->fragment_buf_size;
   if (ysrsh->uploaded_file_size + ysrsh->fragment_buf_size > ysrsh->save_state_buf_size)
   {
      // 剩余未上传内容不足ysrsh->uploaded_file_size，则只上传剩余内容
      fragment_buf_size = ysrsh->save_state_buf_size - ysrsh->uploaded_file_size;
   }
   RARCH_LOG("upload_yun_save_state_fragment log init info."
      " fragment_buf_size: %u, uploaded_file_size: %u, save_state_buf_size: %u\n",
      fragment_buf_size, ysrsh->uploaded_file_size, ysrsh->save_state_buf_size);

#ifdef HAVE_LIBNX
   // switch libnx 如果多调用几个malloc，会崩溃，不知道是什么问题，这里用特殊逻辑计算base64
   int b64_file_buf_len = 0;
   char *b64_file_buf = NULL;
   {
      //定义base64编码表
      const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

      //计算经过base64编码后的字符串长度
      int str_len = fragment_buf_size;
      const char *str = fragment_buf;
      int len = 0;
      if(str_len % 3 == 0)
         len = str_len/3*4;
      else
         len = (str_len/3+1)*4;

      char *res = (char *)malloc(len + 1);
      res[len] = '\0';

      //以3个8位字符为一组进行编码
      int i = 0, j = 0;
      for(i = 0, j = 0; i < len - 2; j += 3, i += 4)
      {
         res[i] = base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符
         res[i+1] = base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符
         res[i+2] = base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
         res[i+3] = base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符
      }

      switch(str_len % 3)
      {
      case 1:
         res[i - 2] = '=';
         res[i - 1] = '=';
         break;
      case 2:
         res[i - 1] = '=';
         break;
      }

      b64_file_buf = res;
      b64_file_buf_len = len;
      // RARCH_LOG("upload_yun_save_state_fragment log base64. b64_file_buf_len: %u, i: %u, b64_file_buf: %s\n",
      //    b64_file_buf_len, i, b64_file_buf);
   }
#else
   int b64_file_buf_len = 0;
   char *b64_file_buf = base64(fragment_buf, (int)fragment_buf_size, &b64_file_buf_len);
   if (NULL == b64_file_buf || b64_file_buf_len == 0)
   {
      RARCH_LOG("upload_yun_save_state_fragment base64 failed.\n");
      return false;
   }
#endif

   // 计算存档MD5保证存档是正确的
   char fragment_buf_md5[64] = {0};
   md5_hexdigest(fragment_buf, fragment_buf_size, fragment_buf_md5, sizeof(fragment_buf_md5));
   const char *savename = path_basename(ysrsh->save_state_path);
   char save_state_url[1024] = {0};
   cpyYunSaveStateFragmentUrl(savename, ysrsh->save_state_buf_md5, ysrsh->seq, fragment_buf_md5, save_state_url, sizeof(save_state_url));
   RARCH_LOG("upload_yun_save_state_fragment log info. "
      "url: %s, save_state_buf_md5: %s, seq: %u"
      ", fragment_buf_md5: %s, fragment_buf_size: %u, b64_len: %u, uploaded_file_size: %u\n",
      save_state_url, ysrsh->save_state_buf_md5, ysrsh->seq,
      fragment_buf_md5, fragment_buf_size, b64_file_buf_len, ysrsh->uploaded_file_size);
   ysrsh->http_task = (retro_task_t*)task_push_http_post_transfer(
      save_state_url, b64_file_buf, true, NULL, upload_yun_save_state_fragment_cb, ysrsh);
   free(b64_file_buf);
   return true;
}

static void task_push_yun_save_rom_state_handle_free(yun_save_rom_state_handle_t *ysrsh)
{
   if (!ysrsh)
      return;

   if (ysrsh->save_state_buf)
   {
      free(ysrsh->save_state_buf);
      ysrsh->save_state_buf = NULL;
   }

   free(ysrsh);
   ysrsh = NULL;
}

static void task_push_yun_save_rom_state_handler(retro_task_t *task)
{
   if (!task)
      goto task_finished;

   if (task_get_cancelled(task))
      goto task_finished;

   yun_save_rom_state_handle_t *ysrsh = (yun_save_rom_state_handle_t*)task->state;
   if (!ysrsh)
      goto task_finished;

   // 任意片段上传错误，认为上传失败
   if (ysrsh->only_fragment_failed)
      goto task_finished;

   // 确保只有一个http任务在执行
   if (ysrsh->http_task && !task_get_finished(ysrsh->http_task))
   {
      return;
   }

   RARCH_LOG("task_push_yun_save_rom_state_handler log info. path: %s, seq: %u, uploaded_file_size: %u, save_state_buf_size: %u\n",
      ysrsh->save_state_path, ysrsh->seq, ysrsh->uploaded_file_size, ysrsh->save_state_buf_size);
   // 如果上传内容没有完成，继续开启http任务上传
   if (ysrsh->uploaded_file_size < ysrsh->save_state_buf_size)
   {
      // 发起新上传存档请求
      upload_yun_save_state_fragment(ysrsh);
      task_set_progress(task, (ysrsh->uploaded_file_size * 100) / ysrsh->save_state_buf_size);
      return;
   }

   task_set_progress(task, 100);
   runloop_msg_queue_push("保存云存档成功", 2, 180, true,
      NULL, MESSAGE_QUEUE_ICON_DEFAULT, MESSAGE_QUEUE_CATEGORY_SUCCESS);
   goto task_finished;

task_finished:   
   if (task)
      task_set_finished(task, true);

   task_push_yun_save_rom_state_handle_free(ysrsh);
}

static bool task_push_yun_save_rom_state_finder(retro_task_t *task, void *user_data)
{
   if (!task || !user_data)
      return false;

   if (task->handler != task_push_yun_save_rom_state_handler)
      return false;

   yun_save_rom_state_handle_t *ysrsh = (yun_save_rom_state_handle_t*)task->state;
   if (!ysrsh)
      return false;

   return string_is_equal((const char*)user_data, ysrsh->save_state_path);
}

bool task_push_yun_save_rom_state(char *path)
{
   settings_t *settings = config_get_ptr();
   bool isopen = settings->bools.network_on_demand_yunsavestate;
   char show_errmsg[1024] = {0};
   const char *savename = path_basename(path);
   RARCH_LOG("task_push_yun_save_rom_state begin. savename: %s, savepath: %s, isopen: %d\n", savename, path, isopen);

   if (!isopen)
   {
      return true;
   }

   char *save_state_buf = NULL;
   int64_t save_state_buf_size = 0;
   if (!path_is_valid(path))
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "存档文件无效：%s", path);
      goto error;
   }

   filestream_read_file(path, (void**)&save_state_buf, &save_state_buf_size);
   if (string_is_empty(save_state_buf) || save_state_buf_size == 0)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "读取存档文件失败：%s", path);
      goto error;
   }
   char save_state_buf_md5[64] = {0};
   md5_hexdigest(save_state_buf, save_state_buf_size, save_state_buf_md5, sizeof(save_state_buf_md5));

   // 后台任务变量
   task_finder_data_t find_data;
   retro_task_t *task = task_init();

   /* Concurrent download of thumbnails for the same
    * playlist is not allowed */
   find_data.func                = task_push_yun_save_rom_state_finder;
   find_data.userdata            = (void*)path;
   if (task_queue_find(&find_data))
      goto error;

   // 分配任务上下文
   yun_save_rom_state_handle_t *ysrsh = (yun_save_rom_state_handle_t*)malloc(sizeof(yun_save_rom_state_handle_t));
   if (!ysrsh)
   {
      snprintf(show_errmsg, sizeof(show_errmsg), "分配任务上下文失败：%s", path);
      goto error;
   }
   strncpy(ysrsh->save_state_path, path, sizeof(ysrsh->save_state_path) - 1);
   strncpy(ysrsh->save_state_buf_md5, save_state_buf_md5, sizeof(ysrsh->save_state_buf_md5) - 1);
   ysrsh->save_state_buf = save_state_buf;
   ysrsh->save_state_buf_size = save_state_buf_size;
   ysrsh->uploaded_file_size = 0;
   ysrsh->seq = 0;
   ysrsh->only_fragment_failed = false;
   ysrsh->http_task = NULL;
   ysrsh->fragment_buf_size = 100*1024;

   /* Configure task */
   task->handler                 = task_push_yun_save_rom_state_handler;
   task->state                   = ysrsh;
   task->title                   = strdup(savename);
   task->alternative_look        = true;
   task->progress                = 0;
   task_queue_push(task);
   return true;

error:
   if (task && task->title)
   {
      free(task->title);
      task->title = NULL;
   }

   if (task)
   {
      free(task);
      task = NULL;
   }

   if (ysrsh)
   {
      free(ysrsh);
      ysrsh = NULL;
   }

   if (save_state_buf)
   {
      free(save_state_buf);
   }
   return false;
}


void task_push_pl_entry_get_ext_game_info_cb(retro_task_t *task, void *task_data, void *user_data, const char *error)
{
   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb bgein. error: %s\n", error);

   http_transfer_data_t *data         = (http_transfer_data_t*)task_data;
   file_transfer_t *file_transfer     = (file_transfer_t *)user_data;
   char status[1024]                  = {0};
   char message[1024]                 = {0};
   char has_achievements[1024]        = {0};
   char errmsg[1024]                  = {0};

   // 遍历json的变量
   char* body_copy                   = NULL;
   char curr                         = 0;
   int i                             = 0;
   int start                         = -1;
   char* found_string                = NULL;
   int curr_state                    = 0;

   if (!data || error)
      goto finish;

   if (!file_transfer)
      goto finish;

   data->data = (char*)realloc(data->data, data->len + 1);
   if (!data->data)
      goto finish;

   data->data[data->len] = '\0';

   /* Parse JSON body for the image and sound data */
   body_copy = strdup(data->data);
   while (true)
   {
      curr = (char)*(body_copy+i);
      if (curr == '\0')
          break;
      if (curr == '\"')
      {
         if (start == -1)
            start = i;
         else
         {
            found_string = (char*)malloc(i-start);
            strncpy(found_string, body_copy+start+1, i-start-1);
            *(found_string+i-start-1) = '\0';
            if (curr_state == 1)
            {
               strncpy(status, found_string, sizeof(status) - 1);
               curr_state = 0;
            }
            else if (curr_state == 2)
            {
               strncpy(message, found_string, sizeof(message) - 1);
               curr_state = 0;
            }
            else if (curr_state == 3)
            {
               strncpy(has_achievements, found_string, sizeof(has_achievements) - 1);
               curr_state = 0;
            }
            else if (strcmp(found_string, "status")==0)
            {
              curr_state = 1;
              free(found_string);
            }
            else if (strcmp(found_string, "message")==0)
            {
              curr_state = 2;
              free(found_string);
            }
            else if (strcmp(found_string, "has_achievements")==0)
            {
              curr_state = 3;
              free(found_string);
            }
            else
              curr_state = 0;
            start = -1;
         }
      }
      i++;
   }

   if (found_string)
      free(found_string);

   if (body_copy)
      free(body_copy);

   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb log result. "
      "status: %s, message: %s, has_achievements: %s\n",
      status, message, has_achievements);

   if (strcmp(status, "SUCCESS") != 0)
      goto finish;
   
   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb log result1. "
      "status: %s, message: %s, has_achievements: %s\n",
      status, message, has_achievements);
   // 修改游戏信息
   get_ext_game_info_handle_t *handle = (get_ext_game_info_handle_t *)file_transfer->user_data;
   if (!handle)
      goto finish;
   
   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb log result2. "
      "selected: %u, playlist_size: %u\n",
      handle->selected, playlist_size(handle->playlist));
   if (handle->selected >= playlist_size(handle->playlist))
      goto finish;
   
   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb log result3. "
      "status: %s, message: %s, has_achievements: %s\n",
      status, message, has_achievements);
   struct playlist_entry *entry = NULL;
   playlist_get_index(handle->playlist, handle->selected, &entry);
   if (!entry)
      goto finish;

   RARCH_LOG("task_push_pl_entry_get_ext_game_info_cb log result4. "
      "status: %s, message: %s, has_achievements: %s\n",
      status, message, has_achievements);
   if (0 == strcmp(has_achievements, "yes"))
   {
      succ_msg_queue_push("%s ☆☆有成就☆☆", entry->label);
   }

finish:
   if (data)
   {
      if (data->data)
      {
         free(data->data);
         data->data = NULL;
      }
      free(data);
      data = NULL;
   }

   if (file_transfer)
   {
      free(file_transfer);
      file_transfer = NULL;
   }
}

static void task_push_pl_entry_get_ext_game_info_handle_free(get_ext_game_info_handle_t *handle)
{
   if (!handle)
      return;

   free(handle);
   handle = NULL;
}

static void task_push_pl_entry_get_ext_game_info_handler(retro_task_t *task)
{
   if (!task)
   {
      RARCH_LOG("task_push_pl_entry_get_ext_game_info_handler invalid task.\n");
      goto task_finished;
   }

   if (task_get_cancelled(task))
   {
      RARCH_LOG("task_push_pl_entry_get_ext_game_info_handler task_get_cancelled.\n");
      goto task_finished;
   }

   get_ext_game_info_handle_t *handle = (get_ext_game_info_handle_t*)task->state;
   if (!handle)
   {
      RARCH_LOG("task_push_pl_entry_get_ext_game_info_handler invalid handle.\n");
      goto task_finished;
   }

   // 确保只有一个http任务在执行
   if (handle->http_task)
   {
      if (task_get_finished(handle->http_task))
      {
         RARCH_LOG("task_push_pl_entry_get_ext_game_info_handler http_task finished.\n");
         goto task_finished;
      }
      return;
   }

   // 没有任务，创建一个新任务，获取正常rom下载地址
   char url[2048] = {0};
   snprintf(url, sizeof(url),
      "%s/api/RetroGameWiki/extGameInfo?platform=%s&crc32=%s",
      file_path_str(FILE_PATH_WIKI_API_URL), handle->system, handle->crc32);
   RARCH_LOG("task_push_pl_entry_get_ext_game_info log http transfer. url: %s\n", url);

   // 新建的http任务，需要透传get_ext_game_info_handle_t
   file_transfer_t *file_transfer = (file_transfer_t *)malloc(sizeof(file_transfer_t));
   if (!file_transfer)
      goto task_finished;
   file_transfer->user_data = handle;
   handle->http_task = task_push_http_transfer(url, true, NULL, task_push_pl_entry_get_ext_game_info_cb, file_transfer);
   return;

task_finished:
   RARCH_LOG("task_push_pl_entry_get_ext_game_info_handler finished.\n");
   if (task)
   {
      task_set_finished(task, true);
   }
   task_push_pl_entry_get_ext_game_info_handle_free(handle);
}

static bool task_push_pl_entry_get_ext_game_info_finder(retro_task_t *task, void *user_data)
{
   if (!task || !user_data)
      return false;

   if (task->handler != task_push_pl_entry_get_ext_game_info_handler)
      return false;

   if (!task->state)
      return false;

   get_ext_game_info_handle_t *handle = (get_ext_game_info_handle_t*)task->state;
   if (!handle)
      return false;

   RARCH_LOG("task_push_pl_entry_get_ext_game_info_finder bgein. user_data: %s, taskid: %s\n",
      (const char*)user_data, handle->taskid);
   return string_is_equal((const char*)user_data, handle->taskid);
}

bool task_push_pl_entry_get_ext_game_info(
      const char *system,
      playlist_t *playlist,
      unsigned idx,
      bool mute)
{
   settings_t *settings = config_get_ptr();
   if (!settings)
      return false;
   
   bool cheevos_enable = settings->bools.cheevos_enable;
   RARCH_LOG("task_push_pl_entry_get_ext_game_info begin. "
      "system: %s, cheevos_enable: %d, mute: %d\n",
      system, cheevos_enable, mute);
   
   if (!cheevos_enable)
      return true;
   
   if (!settings)
      return false;

   /* Sanity check */
   if (!playlist)
      return false;

   if (string_is_empty(system))
      return false;

   if (idx >= playlist_size(playlist))
      return false;

   /* Only parse supported playlist types */
   if (string_is_equal(system, "images_history") ||
      string_is_equal(system, "music_history") ||
      string_is_equal(system, "video_history") ||
      string_is_equal(system, "favorites") ||
      string_is_equal(system, "history"))
      return false;

   struct playlist_entry *entry = NULL;
   playlist_get_index(playlist, idx, &entry);
   if (!entry)
      return false;
   
   char crc32[1024] = {0};
   fill_pathname_base_noext(crc32, entry->path, sizeof(crc32));
   
   char system_name[1024] = {0};
   fill_pathname_base_noext(system_name, entry->db_name, sizeof(system_name));

   // 后台任务变量
   task_finder_data_t find_data;
   retro_task_t *task = task_init();

   /* Concurrent download of thumbnails for the same
    * playlist is not allowed */
   char taskid[1024] = {0};
   snprintf(taskid, sizeof(taskid), "%s_%s", system, crc32);
   find_data.func                = task_push_pl_entry_get_ext_game_info_finder;
   find_data.userdata            = (void*)strdup(taskid);
   if (task_queue_find(&find_data))
      goto error;

   // 分配任务上下文
   get_ext_game_info_handle_t *handle = (get_ext_game_info_handle_t*)malloc(sizeof(get_ext_game_info_handle_t));
   if (!handle)
      goto error;

   handle->http_task = NULL; // 必须初始化位空，不然会导致崩溃
   snprintf(handle->taskid, sizeof(handle->taskid), "%s", taskid);
   snprintf(handle->system, sizeof(handle->system), "%s", system);
   snprintf(handle->crc32, sizeof(handle->crc32), "%s", crc32);
   handle->playlist = playlist;
   handle->selected = idx;
   
   /* Configure task */
   task->handler                 = task_push_pl_entry_get_ext_game_info_handler;
   task->state                   = handle;
   task->title                   = strdup(entry->label);
   task->alternative_look        = true;
   task->progress                = 0;
   task->mute                    = true;
   task_queue_push(task);
   return true;

error:
   if (task && task->title)
   {
      free(task->title);
      task->title = NULL;
   }

   if (task)
   {
      free(task);
      task = NULL;
   }

   if (handle)
   {
      free(handle);
      handle = NULL;
   }
   return false;
}

