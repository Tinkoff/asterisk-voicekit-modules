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

#ifndef GRPCTTS_H
#define GRPCTTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct grpctts_channel;
struct grpctts_job;
struct grpctts_job_conf;

typedef void (*grpctts_stream_error_callback_t)(const char *message);

enum grpctts_frame_format {
	GRPCTTS_FRAME_FORMAT_ALAW = 0,
	GRPCTTS_FRAME_FORMAT_MULAW = 1,
	GRPCTTS_FRAME_FORMAT_SLINEAR16 = 2,
	GRPCTTS_FRAME_FORMAT_OPUS = 3,
};

struct grpctts_job_input {
	const char *text;
};

extern void grpctts_set_stream_error_callback(
	grpctts_stream_error_callback_t callback);

extern void grpctts_init(void);

extern void grpctts_shutdown(void);

extern struct grpctts_channel *grpctts_channel_create(
	const char *endpoint,
	const char *ca_data,
	const char *authorization_api_key, const char *authorization_secret_key,
	const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience);

extern void grpctts_channel_destroy(
	struct grpctts_channel *channel);

extern struct grpctts_job *grpctts_channel_start_job(
	struct grpctts_channel *channel,
	const struct grpctts_job_conf *job_conf,
	const struct grpctts_job_input *job_input);

extern void grpctts_job_destroy(
	struct grpctts_job *job);

extern int grpctts_job_event_fd(
	struct grpctts_job *job);

extern int grpctts_job_collect(
	struct grpctts_job *job);

extern size_t grpctts_job_buffer_size(
	struct grpctts_job *job);

extern int grpctts_job_take_block(
	struct grpctts_job *job,
	size_t byte_count,
	void *data);

extern size_t grpctts_job_take_tail(
	struct grpctts_job *job,
	size_t byte_count,
	void *data);

extern int grpctts_job_termination_called(
	struct grpctts_job *job);

extern int grpctts_job_completion_success(
	struct grpctts_job *job);

#ifdef __cplusplus
};
#endif
#endif
