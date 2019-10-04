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

/*********************/
/* Utility Functions */
/*********************/

void md5_hexdigest(char *input, int input_len, char *output, int *output_len)
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
	uint32_t now = time(NULL);
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

char *genYunSaveStateUrl(char *savename, char *save_buf_md5)
{
	char save_state_url[PATH_MAX_LENGTH];
	char acc_query_str[1024] = {0};
	clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
	snprintf(save_state_url, sizeof(save_state_url),
		"%s?%s&savename=%s&save_buf_md5=%s",
		"http://wekafei.cn/api/UserGameData/SaveState", acc_query_str, savename, save_buf_md5);
	return strdup(save_state_url);
}

char *genYunLoadStateUrl(char *loadname)
{
	char load_state_url[PATH_MAX_LENGTH];
	char acc_query_str[1024] = {0};
	clac_retrogame_allinone_sign(acc_query_str, sizeof(acc_query_str));
	snprintf(load_state_url, sizeof(load_state_url),
		"%s?%s&loadname=%s",
		"http://wekafei.cn/api/UserGameData/LoadState", acc_query_str, loadname);
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
   http_transfer_data_t *data        = (http_transfer_data_t*)task_data;
	char status[1024]						 = {0};
	char message[1024]					 = {0};
	char errmsg[1024]						 = {0};

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
					strncpy(status, found_string, sizeof(status));
					curr_state = 0;
            }
            else if (curr_state == 2)
				{
					strncpy(message, found_string, sizeof(message));
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

void yun_save_rom_state(char *path)
{
	settings_t *settings = config_get_ptr();
	bool isopen = settings->bools.network_on_demand_yunsavestate;
	char *show_errmsg[1024] = {0};
	char *savename = path_basename(path);
	RARCH_LOG("yun_save_rom_state begin. savename: %s, savepath: %s, isopen: %d\n", savename, path, isopen);

	if (!isopen)
	{
		return;
	}

	const int64_t max_buf_size = 10*1024*1024;
	char *file_buf = NULL;
	int64_t file_buf_size = 0;
	char *b64_file_buf = NULL;
	int b64_file_buf_len = 0;

	if (!path_is_valid(path))
	{
		snprintf(show_errmsg, sizeof(show_errmsg), "存档文件无效：%s", path);
		return false;
	}

	filestream_read_file(path, (void**)&file_buf, &file_buf_size);
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

   b64_file_buf = base64((void *)file_buf, (int)file_buf_size, &b64_file_buf_len);
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

	return;
}

void yun_load_rom_state_cb(retro_task_t *task, void *task_data, void *user_data, const char *error)
{
	RARCH_LOG("yun_load_rom_state_cb bgein. error: %s\n", error);

	char *show_errmsg[1024] = {0};
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

static void free_pl_rom_handle(pl_rom_handle_t *pl_thumb, bool free_playlist)
{
   if (!pl_thumb)
      return;

   if (!string_is_empty(pl_thumb->system))
   {
      free(pl_thumb->system);
      pl_thumb->system = NULL;
   }

   if (!string_is_empty(pl_thumb->playlist_path))
   {
      free(pl_thumb->playlist_path);
      pl_thumb->playlist_path = NULL;
   }

   if (!string_is_empty(pl_thumb->dir_thumbnails))
   {
      free(pl_thumb->dir_thumbnails);
      pl_thumb->dir_thumbnails = NULL;
   }

   if (pl_thumb->playlist && free_playlist)
   {
      playlist_free(pl_thumb->playlist);
      pl_thumb->playlist = NULL;
   }

   if (pl_thumb->thumbnail_path_data)
   {
      free(pl_thumb->thumbnail_path_data);
      pl_thumb->thumbnail_path_data = NULL;
   }

   free(pl_thumb);
   pl_thumb = NULL;
}

/*******************************/
/* Playlist Thumbnail Download */
/*******************************/

static void task_pl_rom_download_handler(retro_task_t *task)
{
   pl_rom_handle_t *pl_thumb = NULL;

   if (!task)
      goto task_finished;

   pl_thumb = (pl_rom_handle_t*)task->state;

   if (!pl_thumb)
      goto task_finished;

   if (task_get_cancelled(task))
      goto task_finished;

   switch (pl_thumb->status)
   {
      case PL_ROM_BEGIN:
         {
            /* Load playlist */
            if (!path_is_valid(pl_thumb->playlist_path))
               goto task_finished;

            pl_thumb->playlist = playlist_init(pl_thumb->playlist_path, COLLECTION_SIZE);

            if (!pl_thumb->playlist)
               goto task_finished;

            pl_thumb->list_size = playlist_size(pl_thumb->playlist);

            if (pl_thumb->list_size < 1)
               goto task_finished;

            /* Initialise thumbnail path data */
            pl_thumb->thumbnail_path_data = menu_thumbnail_path_init();

            if (!pl_thumb->thumbnail_path_data)
               goto task_finished;

            if (!menu_thumbnail_set_system(
                  pl_thumb->thumbnail_path_data, pl_thumb->system, pl_thumb->playlist))
               goto task_finished;

            /* All good - can start iterating */
            pl_thumb->status = PL_ROM_ITERATE_ENTRY;
         }
         break;
      case PL_ROM_ITERATE_ENTRY:
         {
            /* Set current thumbnail content */
            if (menu_thumbnail_set_content_playlist(
                  pl_thumb->thumbnail_path_data, pl_thumb->playlist, pl_thumb->list_index))
            {
               const char *label = NULL;

               /* Update progress display */
               task_free_title(task);
               if (menu_thumbnail_get_label(pl_thumb->thumbnail_path_data, &label))
                  task_set_title(task, strdup(label));
               else
                  task_set_title(task, strdup(""));
               // task_set_progress(task, (pl_thumb->list_index * 100) / pl_thumb->list_size);

               /* Start iterating over thumbnail type */
               pl_thumb->type_idx = 1;
               pl_thumb->status = PL_ROM_ITERATE_TYPE;
            }
            else
            {
               /* Current playlist entry is broken - advance to
                * the next one */
               pl_thumb->list_index++;
               if (pl_thumb->list_index >= pl_thumb->list_size)
                  pl_thumb->status = PL_ROM_END;
            }
         }
         break;
      case PL_ROM_ITERATE_TYPE:
         {
            /* Ensure that we only enqueue one transfer
             * at a time... */
            if (pl_thumb->http_task)
            {
               if (task_get_finished(pl_thumb->http_task))
                  pl_thumb->http_task = NULL;
               else
                  break;
            }

            /* Check whether all thumbnail types have been processed */
            if (pl_thumb->type_idx > 1)
            {
               /* Time to move on to the next entry */
               pl_thumb->list_index++;
               if (pl_thumb->list_index < pl_thumb->list_size)
                  pl_thumb->status = PL_ROM_ITERATE_ENTRY;
               else
                  pl_thumb->status = PL_ROM_END;
               break;
            }

            /* Download current thumbnail */
            if (pl_thumb)
               download_pl_rom(pl_thumb);

            /* Increment thumbnail type */
            pl_thumb->type_idx++;
         }
         break;
      case PL_ROM_END:
      default:
         // task_set_progress(task, 100);
         goto task_finished;
         break;
   }

   return;

task_finished:

   if (task)
      task_set_finished(task, true);

   free_pl_rom_handle(pl_thumb, true);
}

static bool task_pl_rom_finder(retro_task_t *task, void *user_data)
{
   pl_rom_handle_t *pl_thumb = NULL;

   if (!task || !user_data)
      return false;

   if (task->handler != task_pl_rom_download_handler)
      return false;

   pl_thumb = (pl_rom_handle_t*)task->state;
   if (!pl_thumb)
      return false;

   return string_is_equal((const char*)user_data, pl_thumb->playlist_path);
}

bool task_push_pl_rom_download(
      const char *system, const char *playlist_path)
{
   task_finder_data_t find_data;
   settings_t *settings          = config_get_ptr();
   retro_task_t *task            = task_init();
   pl_rom_handle_t *pl_thumb   = (pl_rom_handle_t*)calloc(1, sizeof(pl_rom_handle_t));
   const char *playlist_file     = path_basename(playlist_path);

   /* Sanity check */
   if (!settings || !task || !pl_thumb)
      goto error;

   if (string_is_empty(system) ||
       string_is_empty(playlist_path) ||
       string_is_empty(playlist_file) ||
       string_is_empty(settings->paths.directory_thumbnails))
      goto error;

   /* Only parse supported playlist types */
   if (string_is_equal(playlist_file, file_path_str(FILE_PATH_CONTENT_HISTORY)) ||
       string_is_equal(playlist_file, file_path_str(FILE_PATH_CONTENT_FAVORITES)) ||
       string_is_equal(playlist_file, file_path_str(FILE_PATH_CONTENT_MUSIC_HISTORY)) ||
       string_is_equal(playlist_file, file_path_str(FILE_PATH_CONTENT_VIDEO_HISTORY)) ||
       string_is_equal(playlist_file, file_path_str(FILE_PATH_CONTENT_IMAGE_HISTORY)) ||
       string_is_equal(system, "history") ||
       string_is_equal(system, "favorites") ||
       string_is_equal(system, "images_history"))
      goto error;

   /* Concurrent download of thumbnails for the same
    * playlist is not allowed */
   find_data.func                = task_pl_rom_finder;
   find_data.userdata            = (void*)playlist_path;

   if (task_queue_find(&find_data))
      goto error;

   /* Configure task */
   task->handler                 = task_pl_rom_download_handler;
   task->state                   = pl_thumb;
   task->title                   = strdup(system);
   task->alternative_look        = true;
   task->progress                = 0;

   /* Configure handle */
   pl_thumb->system              = strdup(system);
   pl_thumb->playlist_path       = strdup(playlist_path);
   pl_thumb->dir_thumbnails      = strdup(settings->paths.directory_thumbnails);
   pl_thumb->playlist            = NULL;
   pl_thumb->thumbnail_path_data = NULL;
   pl_thumb->http_task           = NULL;
   pl_thumb->list_size           = 0;
   pl_thumb->list_index          = 0;
   pl_thumb->type_idx            = 1;
   pl_thumb->overwrite           = false;
   pl_thumb->status              = PL_ROM_BEGIN;

   task_queue_push(task);

   return true;

error:

   if (task)
   {
      free(task);
      task = NULL;
   }

   if (pl_thumb)
   {
      free(pl_thumb);
      pl_thumb = NULL;
   }

   return false;
}

static void task_pl_entry_rom_free(retro_task_t *task)
{
   pl_rom_handle_t *pl_thumb = NULL;

   if (!task)
      return;

   pl_thumb = (pl_rom_handle_t*)task->state;

   free_pl_rom_handle(pl_thumb, false);
}

static void task_pl_entry_rom_download_handler(retro_task_t *task)
{
   pl_rom_handle_t *pl_thumb = NULL;

   if (!task)
      return;

   pl_thumb = (pl_rom_handle_t*)task->state;

   if (!pl_thumb)
      goto task_finished;

   if (task_get_cancelled(task))
      goto task_finished;

   switch (pl_thumb->status)
   {
      case PL_ROM_BEGIN:
         {
            const char *label                = NULL;
            const char *right_thumbnail_path = NULL;
            const char *left_thumbnail_path  = NULL;

            /* Initialise thumbnail path data */
            pl_thumb->thumbnail_path_data = menu_thumbnail_path_init();

            if (!pl_thumb->thumbnail_path_data)
               goto task_finished;

            if (!menu_thumbnail_set_system(
                  pl_thumb->thumbnail_path_data, pl_thumb->system, pl_thumb->playlist))
               goto task_finished;

            if (!menu_thumbnail_set_content_playlist(
                  pl_thumb->thumbnail_path_data, pl_thumb->playlist, pl_thumb->list_index))
               goto task_finished;

            /* Set task title */
            task_free_title(task);
            if (menu_thumbnail_get_label(pl_thumb->thumbnail_path_data, &label))
               task_set_title(task, strdup(label));
            else
               task_set_title(task, strdup(""));
            // task_set_progress(task, 0);

            /* All good - can start iterating */
            pl_thumb->status = PL_ROM_ITERATE_TYPE;
         }
         break;
      case PL_ROM_ITERATE_TYPE:
         {
            /* Ensure that we only enqueue one transfer
             * at a time... */
            if (pl_thumb->http_task)
            {
               if (task_get_finished(pl_thumb->http_task))
                  pl_thumb->http_task = NULL;
               else
                  break;
            }

            /* Check whether all thumbnail types have been processed */
            if (pl_thumb->type_idx > 1)
            {
               pl_thumb->status = PL_ROM_END;
               break;
            }

            /* Update progress */
            // task_set_progress(task, ((pl_thumb->type_idx - 1) * 100));

            /* Download current thumbnail */
            if (pl_thumb)
               download_pl_rom(pl_thumb);

            /* Increment thumbnail type */
            pl_thumb->type_idx++;
         }
         break;
      case PL_ROM_END:
      default:
         // task_set_progress(task, 100);
         goto task_finished;
         break;
   }

   return;

task_finished:

   if (task)
      task_set_finished(task, true);
}

static bool task_pl_entry_rom_finder(retro_task_t *task, void *user_data)
{
   pl_entry_rom_id_t *entry_id     = NULL;
   pl_rom_handle_t *pl_thumb = NULL;

   if (!task || !user_data)
      return false;

   if (task->handler != task_pl_entry_rom_download_handler)
      return false;

   entry_id = (pl_entry_rom_id_t*)user_data;
   if (!entry_id)
      return false;

   pl_thumb = (pl_rom_handle_t*)task->state;
   if (!pl_thumb)
      return false;

   return (entry_id->idx == pl_thumb->list_index) &&
          string_is_equal(entry_id->playlist_path, pl_thumb->playlist_path);
}

bool task_push_pl_entry_rom_download(
      const char *system,
      playlist_t *playlist,
      unsigned idx,
      bool overwrite,
      bool mute)
{
   task_finder_data_t find_data;
   settings_t *settings          = config_get_ptr();
   retro_task_t *task            = task_init();
   pl_rom_handle_t *pl_thumb   = (pl_rom_handle_t*)calloc(1, sizeof(pl_rom_handle_t));
   pl_entry_rom_id_t *entry_id       = (pl_entry_rom_id_t*)calloc(1, sizeof(pl_entry_rom_id_t));
   char *playlist_path           = NULL;

   RARCH_LOG("task_push_pl_entry_rom_download start\n");

   /* Sanity check */
   if (!settings || !task || !pl_thumb || !playlist || !entry_id)
      goto error;

   if (string_is_empty(system) ||
       string_is_empty(settings->paths.directory_thumbnails) ||
       string_is_empty(playlist_get_conf_path(playlist)))
      goto error;

   if (idx >= playlist_size(playlist))
      goto error;

   /* Only parse supported playlist types */
   if (string_is_equal(system, "images_history") ||
       string_is_equal(system, "music_history") ||
       string_is_equal(system, "video_history"))
      goto error;

   /* Copy playlist path
    * (required for task finder and menu refresh functionality) */
   playlist_path = strdup(playlist_get_conf_path(playlist));

   /* Concurrent download of thumbnails for the same
    * playlist entry is not allowed */
   entry_id->playlist_path       = playlist_path;
   entry_id->idx                 = idx;

   find_data.func                = task_pl_entry_rom_finder;
   find_data.userdata            = (void*)entry_id;

   if (task_queue_find(&find_data))
      goto error;

   free(entry_id);
   entry_id = NULL;

   /* Configure task */
   task->handler                 = task_pl_entry_rom_download_handler;
   task->state                   = pl_thumb;
   task->title                   = strdup(system);
   task->alternative_look        = true;
   task->mute                    = mute;
   task->progress                = 0;
   task->callback                = NULL;
   task->cleanup                 = task_pl_entry_rom_free;

   /* Configure handle */
   pl_thumb->system              = strdup(system);
   pl_thumb->playlist_path       = playlist_path;
   pl_thumb->dir_thumbnails      = strdup(settings->paths.directory_core_assets);
   pl_thumb->playlist            = playlist;
   pl_thumb->thumbnail_path_data = NULL;
   pl_thumb->http_task           = NULL;
   pl_thumb->list_size           = playlist_size(playlist);
   pl_thumb->list_index          = idx;
   pl_thumb->type_idx            = 1;
   pl_thumb->overwrite           = overwrite;
   pl_thumb->status              = PL_ROM_BEGIN;

   struct playlist_entry *p_playlist_entry = NULL;
   playlist_get_index(playlist, idx, &p_playlist_entry);
   if (p_playlist_entry != NULL)
   {
	   pl_thumb->title = p_playlist_entry->label;
   }

   task_queue_push(task);

   return true;

error:

   if (task)
   {
      free(task);
      task = NULL;
   }

   if (pl_thumb)
   {
      free(pl_thumb);
      pl_thumb = NULL;
   }

   if (entry_id)
   {
      free(entry_id);
      entry_id = NULL;
   }

   if (!string_is_empty(playlist_path))
   {
      free(playlist_path);
      playlist_path = NULL;
   }

   return false;
}
