/*
 * Asterisk VoiceKit modules
 *
 * Copyright (c) JSC Tinkoff Bank, 2018 - 2019
 *
 * Grigoriy Okopnik <g.e.okopnik@tinkoff.ru>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#ifndef GRPCTTS_CONF_H
#define GRPCTTS_CONF_H

#define typeof __typeof__
#include <stddef.h>
#include <stdint.h>

#include "grpctts.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <asterisk.h>
#include <asterisk/utils.h>


enum grpctts_voice_gender {
	GRPCTTS_VOICE_GENDER_UNSPECIFIED = 0,
	GRPCTTS_VOICE_GENDER_MALE = 1,
	GRPCTTS_VOICE_GENDER_FEMALE = 2,
	GRPCTTS_VOICE_GENDER_NEUTRAL = 3,
};

struct grpctts_buffer_size {
	double fraction;
	double seconds;
};

struct grpctts_job_conf {
	double speaking_rate;
	double pitch;
	double volume_gain_db;
	char *voice_language_code;
	char *voice_name;
	enum grpctts_voice_gender voice_gender;
	enum grpctts_frame_format remote_frame_format;
	struct grpctts_buffer_size initial_buffer_size;
};

struct grpctts_conf {
	char *endpoint;
	int ssl_grpc;
	char *ca_data;
	char *authorization_api_key;
	char *authorization_secret_key;
	char *authorization_issuer;
	char *authorization_subject;
	char *authorization_audience;

	struct grpctts_job_conf job_conf;
};

#define GRPCTTS_JOB_CONF_INITIALIZER {				\
	.speaking_rate = 1.0,					\
	.pitch = 0.0,						\
	.volume_gain_db = 0.0,					\
	.voice_language_code = NULL,				\
	.voice_name = NULL,					\
	.voice_gender = GRPCTTS_VOICE_GENDER_UNSPECIFIED,	\
	.remote_frame_format = GRPCTTS_FRAME_FORMAT_SLINEAR16,	\
}

#define GRPCTTS_CONF_INITIALIZER {			\
	.endpoint = NULL,				\
	.ssl_grpc = 0,					\
	.ca_data = NULL,				\
	.authorization_api_key = NULL,			\
	.authorization_secret_key = NULL,		\
	.authorization_issuer = NULL,			\
	.authorization_subject = NULL,			\
	.authorization_audience = NULL,			\
							\
	.job_conf = GRPCTTS_JOB_CONF_INITIALIZER,	\
}


extern void grpctts_conf_global_init(void);

extern void grpctts_conf_global_uninit(void);


extern char *grpctts_load_ca_from_file(
	const char *relative_fname);

extern int grpctts_parse_buffer_size(
	struct grpctts_buffer_size *buffer_size,
	const char *str);

extern void grpctts_job_conf_init(
	struct grpctts_job_conf *conf);

extern void grpctts_job_conf_clear(
	struct grpctts_job_conf *conf);

extern struct grpctts_job_conf *grpctts_job_conf_cpy(
	struct grpctts_job_conf *dest,
	const struct grpctts_job_conf *src);


extern void grpctts_conf_init(
	struct grpctts_conf *conf);

extern void grpctts_conf_clear(
	struct grpctts_conf *conf);

extern int grpctts_conf_load(
	struct grpctts_conf *conf,
	ast_mutex_t *mutex,
	const char *fname,
	int reload);

extern struct grpctts_conf *grpctts_conf_cpy(
	struct grpctts_conf *dest,
	const struct grpctts_conf *src,
	ast_mutex_t *src_mutex);

#ifdef __cplusplus
};
#endif
#endif
