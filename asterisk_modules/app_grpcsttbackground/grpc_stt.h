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

#ifndef GRPC_STT_H
#define GRPC_STT_H

#ifdef __cplusplus
extern "C" {
#endif

struct ast_channel;

enum grpc_stt_frame_format {
	GRPC_STT_FRAME_FORMAT_ALAW = 0,
	GRPC_STT_FRAME_FORMAT_MULAW = 1,
	GRPC_STT_FRAME_FORMAT_SLINEAR16 = 2,
};

extern void grpc_stt_run(
	int terminate_event_fd,
	const char *target,
	const char *authorization_api_key,
	const char *authorization_secret_key,
	const char *authorization_issuer,
	const char *authorization_subject,
	const char *authorization_audience,
	const char *x_request_id,
	struct ast_channel *chan,
	int ssl_grpc,
	const char *ca_data,
	const char *language_code,
	int max_alternatives,
	enum grpc_stt_frame_format frame_format,
	int vad_disable,
	double vad_min_speech_duration,
	double vad_max_speech_duration,
	double vad_silence_duration_threshold,
	double vad_silence_prob_threshold,
	double vad_aggressiveness,
	int interim_results_enable,
	double interim_results_interval,
	int enable_gender_identification);

#ifdef __cplusplus
};
#endif

#endif
