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

#ifndef STREAM_LAYERS_H
#define STREAM_LAYERS_H

#define typeof __typeof__

#include "grpctts.h"
#include "grpctts_conf.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <asterisk.h>
#ifdef __cplusplus
};
#endif
#include <time.h>


struct grpctts_channel;
struct grpctts_job;


struct stream_source_file {
	struct ast_filestream *filestream;
	struct ast_frame *buffered_frame;
	int buffered_frame_off;
};

struct stream_source_sleep {
	int sample_count;
};

struct stream_source_synthesis {
	struct ast_channel *chan;
	struct grpctts_job *job;
	struct ast_frame *buffered_frame;
	int buffered_frame_off;
	int duration_announced;
};

enum stream_source_type {
	STREAM_SOURCE_NONE = 0,
	STREAM_SOURCE_FILE = 1,
	STREAM_SOURCE_SLEEP = 2,
	STREAM_SOURCE_SYNTHESIS = 3,
};

struct stream_source {
	enum stream_source_type type;
	union {
		struct stream_source_file file;
		struct stream_source_sleep sleep;
		struct stream_source_synthesis synthesis;
	} source;
};

struct stream_job {
	char *command;
	struct stream_job *next;
};

struct stream_layer {
	int override;
	struct stream_job *jobs;
	struct stream_job *last_job;
	struct stream_source source;
};

struct stream_state {
	struct ast_channel *chan;
	struct grpctts_channel *tts_channel;
	struct grpctts_job_conf job_conf;
	int efd;
	struct timespec next_frame_time;
};

extern void stream_layers_global_init(void);

extern void stream_layers_global_uninit(void);

extern void stream_layer_init(
	struct stream_layer *layer);

extern void stream_layer_uninit(
	struct stream_layer *layer);

extern void stream_layer_add_job(
	struct stream_layer *layer,
	const char *command);

extern void stream_layer_override(
	struct stream_layer *layer);

extern void stream_state_init(
	struct stream_state *state,
	struct ast_channel *chan,
	int efd);

extern void stream_state_uninit(
	struct stream_state *state);

/* Returns: -1 on error or hangup; 0 on stream finished; 1 on efd triggered */
extern int stream_layers(
	struct stream_state *state,
	struct stream_layer *layers,
	int layer_count);

#endif
