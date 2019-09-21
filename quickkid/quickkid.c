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

#include "pinyin.h"
#include "utf8vector.h"
#include "linereader.h"


#if 0
#define DEBUG_LOG
#endif


// 汉字转拼音
int chs_to_pinyin(const char *keyword, bool only_first, char *line, int line_length)
{
	int keyword_len = strlen(keyword);
	if (keyword_len == 0)
	{
		return -1;
	}

// 	RARCH_LOG("chs_to_pinyin log begin. keyword: %s, keyword_len: %d, only_first: %d, line: %s, line_length %d\n",
// 		keyword, strlen(keyword), only_first, line, line_length);

	wchar_t keyword_char;
	int keyword_index = 0;
	char finnal_pinyins[1024] = {0};
	char *raw = NULL;
	int raw_len = 0;
	utf8vector keyword_vector = utf8vector_create(keyword, -1);
	while((keyword_char = utf8vector_next_unichar_with_raw(keyword_vector, &raw, &raw_len)) != '\0')
	{
		// RARCH_LOG("chs_to_pinyin log keyword_char. unicode: %s\n", raw);

		if (!pinyin_ishanzi(keyword_char) && !pinyin_isabc(keyword_char))
		{
			continue;
		}

		keyword_char = pinyin_lowercase(keyword_char);
		if (pinyin_isabc(keyword_char))
		{
			char abc = (char)keyword_char;
			// RARCH_LOG("chs_to_pinyin hit abc: %c\n", abc);
			finnal_pinyins[strlen(finnal_pinyins)] = abc;
			continue;
		}

		// RARCH_LOG("chs_to_pinyin hit hanzi: %s\n", raw);
		const char **pinyins;
		int count = pinyin_get_pinyins_by_unicode(keyword_char, &pinyins);
		if (count == 0)
		{
			continue;
		}

		if (only_first)
		{
			char first_latter = pinyins[0][0];
			// RARCH_LOG("chs_to_pinyin hit pinyin first latter: %c\n", first_latter);
			finnal_pinyins[strlen(finnal_pinyins)] = first_latter;
		}
		else
		{
			for (int i = 0; i < count; i++)
			{
				const char *pinyin = pinyins[i];
				// RARCH_LOG("chs_to_pinyin hit pinyin all. index: %d, pinyin: %s\n", i, pinyin);
				strlcat(finnal_pinyins, pinyin, sizeof(finnal_pinyins));
			}
		}
		free(pinyins);
	}

	utf8vector_free(keyword_vector);
	strlcpy(line, finnal_pinyins, line_length);
	return 1;
}

unsigned char char_to_ninenum(char ch)
{
	unsigned char num = -1;
	if (ch >= 65 && ch <= 90) {
		num = ch - 65;
	}

	if (ch >= 97 && ch <= 122) {
		num = ch - 97;
	}

	if (num < 0) {
		return num;
	}

	// 一个数字，可以表示三个字母，计算出最终下标，从1开始
	return '1' + (num / 3);
}

// 拼音转九宫格数字
int pinyin_to_ninenum(const char *in_str, char *out_str, int out_len)
{
	// RARCH_LOG("pinyin_to_ninenum begin. in_str: %s\n", in_str);
	int i = 0;
	int j = 0;
	while(in_str[i] != '\0') {
		unsigned char ninenum = char_to_ninenum(in_str[i]);
		if (ninenum > 0 && j < out_len - 1) {
			out_str[j++] = ninenum;
			out_str[j] = '\0';
		}
		++i;
	}
	// RARCH_LOG("pinyin_to_ninenum finish. out_str: %s\n", out_str);
	return 0;
}

int chs_to_ninenum(const char *keyword, bool only_first, char *out_str, int out_len)
{
	char line[1024] = {0};
	int count = chs_to_pinyin(keyword, only_first, line, 1024);
	if (count < 0)
	{
		return count;
	}
	pinyin_to_ninenum(line, out_str, out_len);
}
