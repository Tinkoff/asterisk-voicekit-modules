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

/*! \file
 *
 * \brief Queued background playback application
 *
 * \author Grigoriy Okopnik <g.e.okopnik@tinkoff.ru>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

extern struct ast_module *AST_MODULE_SELF_SYM(void);
#define AST_MODULE_SELF_SYM AST_MODULE_SELF_SYM

#define _GNU_SOURCE 1
#include "stream_layers.h"
#include "grpctts.h"
#include "grpctts_conf.h"

#include <asterisk.h>

#include <asterisk/pbx.h>
#include <asterisk/app.h>
#include <asterisk/module.h>
#include <asterisk/manager.h>
#include <asterisk/utils.h>
#include <asterisk/dlinkedlists.h>
#include <asterisk/channel.h>
#include <asterisk/channel_internal.h>
#include <asterisk/mod_format.h>
#include <asterisk/format_cache.h>
#include <asterisk/paths.h>

#include <sys/eventfd.h>
#include <sys/stat.h>
#include <math.h>

/*** DOCUMENTATION
	<application name="PlayBackgroundInitGRPCTTS" language="en_US">
		<synopsis>
			Initialize TTS channel with specified parameters in background.
		</synopsis>
		<syntax>
			<parameter name="conf_fname" required="false">
				<para>Specifies custom configuration filename for current TTS session (used by &quot;PlayBackground(say:*)&quot;). By default&quot;grpctts.conf&quot; is used.</para>
			</parameter>
			<parameter name="endpoint" required="false">
				<para>Specifies endpointg for GRPC TTS service (must be specified here or at configuration file)</para>
			</parameter>
			<parameter name="ca_file" required="false">
				<para>Specifies CA filename to load as alternative list of CA (by default builtin CA list is used).</para>
			</parameter>
			<parameter name="remote_frame_format" required="false">
				<para>Specifies remote audio frame format. Allowed values are "slin" and "opus". Default: "slin"</para>
			</parameter>
		</syntax>
		<description>
			<para>This application is necessary to allow &quot;PlayBackground&quot; application call for speech synthesis using &quot;say:*&quot; command.</para>
		</description>
		<see-also>
			<ref type="application">PlayBackground</ref>
		</see-also>
	</application>
	<application name="PlayBackground" language="en_US">
		<synopsis>
			Play a specified files or execute playback commands in background.
		</synopsis>
		<syntax>
			<parameter name="[LAYER_N@][&amp;][COMMAND_NAME,OPTIONS,DATA]" required="true" />
		</syntax>
		<description>
			<para>This application will enqueue specified action sequence for playing in background.</para>
			<para>Each command is addressed to single audio layer which can be specified by 'LAYER_N@' prefix where LAYER_N is digit from 0 to 3 (default layer is 0).</para>
			<para>If command starts with '&amp;' character, following commands will be added to queue.</para>
			<para>Otherwise current playback will be stopped if present and following command will be added to queue and executed immediately.</para>
			<para>Available commands:</para>
			<para>- sleep,,TIMEOUT - pause for specified TIMEOUT seconds (specified as double precision floating point number)</para>
			<para>- play,,FILENAME - playback file specified by FILENAME (without extension)</para>
			<para>- say,[OPTION1=VALUE1[:OPTION2=VALUE2[...]]],INPUT - playback phrase specified by INPUT in JSON format and configured with OPTION=VALUE option set,
			for OPTIONS ',', ':', '(' and ')' characters must be backslash-escaped, INPUT must NOT be escaped</para>
			<para>When playback is finished at each layer empty frames are NOT being sent.</para>
			<para><emphasis>At each playback begin an &quot;PlayBackgroundDuration(LAYER_N,DURATION_SECS)&quot; event is generated.</emphasis></para>
			<para><emphasis>At each playback end an &quot;PlayBackgroundFinished(LAYER_N)&quot; event is generated.</emphasis></para>
			<para><emphasis>At each playback error an &quot;PlayBackgroundError(LAYER_N)&quot; event is generated and remaining commands are dropped.</emphasis></para>
			<para><emphasis>Note that invocation with empty arguments will stop current playback.</emphasis></para>
			<example title="Play single file">
			 PlayBackgorund(play,,directory1/file3); // At playback end &quot;PlayBackgroundFinished(0)&quot; event is generated
			</example>
			<example title="Play 2 files consecutively with pause of 2.5 seconds">
			 PlayBackgorund(play,,1st_file);
			 PlayBackgorund(&amp;sleep,,2.5);
			 PlayBackgorund(&amp;play,,2nd_file);
			</example>
			<example title="Play 2 files in parallel (at layers 0 and 1)">
			 PlayBackgorund(play,,message); // At playback end &quot;PlayBackgroundFinished(0)&quot; event is generated
			 PlayBackgorund(1@play,,background_music); // At playback end &quot;PlayBackgroundFinished(1)&quot; event is generated
			</example>
			<example title="Stop playback at layer 0">
			 PlayBackgorund();
			</example>
			<example title="Append file to play after 200ms pause to queue of layer 3">
			 PlayBackgorund(3@&amp;sleep,,0.2);
			 PlayBackgorund(3@&amp;play,,dir/next_file);
			</example>
			<example title="Say synthesized text">
			 PlayBackground(say,,{"text":"ложка горького"});
			</example>
		</description>
		<see-also>
			<ref type="application">PlayBackgroundInitGRPCTTS</ref>
		</see-also>
	</application>
 ***/
static const char app_initgrpctts[] = "PlayBackgroundInitGRPCTTS";
static const char app[] = "PlayBackground";

#define AUDIO_LAYER_COUNT 4

struct playback_control_message {
	char *command;
	AST_DLLIST_ENTRY(playback_control_message) list_meta;
};

struct ht_playback_layer_control {
	int override;
	AST_DLLIST_HEAD(entries, playback_control_message) entries;
};
struct ht_playback_control {
	int eventfd;
	ast_mutex_t mutex;
	struct grpctts_conf conf;
	struct ht_playback_layer_control layers[AUDIO_LAYER_COUNT];
	struct grpctts_channel *tts_channel;
	int socket_fd_pipe_fd;
};

static struct grpctts_conf dflt_grpctts_conf = GRPCTTS_CONF_INITIALIZER;
static ast_mutex_t dflt_grpctts_conf_mutex = AST_MUTEX_INIT_VALUE;


/* struct user_message methods */
static struct playback_control_message *make_playback_control_message(const char *command)
{
	size_t len = strlen(command);
	struct playback_control_message *s = ast_calloc(sizeof(struct playback_control_message) + len + 1, 1);
	s->command = memcpy((void*) (s + 1), command, len);
	s->command[len] = '\0';
	return s;
}

/* struct ht_user_message_queue methods */
static void clear_ht_playback_layer_control(struct ht_playback_layer_control *layer_control)
{
	struct playback_control_message *entry;
	while ((entry = AST_DLLIST_FIRST(&layer_control->entries))) {
		AST_DLLIST_REMOVE(&layer_control->entries, entry, list_meta);
		ast_free(entry);
	}
}
static void destroy_ht_playback_control(void *void_s)
{
	struct ht_playback_control *s = void_s;
	ast_mutex_destroy(&s->mutex);
	close(s->eventfd);
	{
		int i;
		for (i = 0; i < sizeof(s->layers)/sizeof(s->layers[0]); ++i)
			clear_ht_playback_layer_control(&s->layers[i]);
	}
	grpctts_channel_destroy(s->tts_channel);
	grpctts_conf_clear(&s->conf);
	ast_free(s);
}
static const struct ast_datastore_info playbackground_ds_info = {
	.type = "playback",
	.destroy = destroy_ht_playback_control,
};
static struct ht_playback_control *make_ht_playback_control(void)
{
	struct ht_playback_control *s = ast_calloc(sizeof(struct ht_playback_control), 1);
	s->eventfd = eventfd(0, 0);
	fcntl(s->eventfd, F_SETFL, fcntl(s->eventfd, F_GETFL) | O_NONBLOCK);
	ast_mutex_init(&s->mutex);
	grpctts_conf_init(&s->conf);
	grpctts_conf_cpy(&s->conf, &dflt_grpctts_conf, &dflt_grpctts_conf_mutex);
	s->socket_fd_pipe_fd = -1;
	return s;
}
static struct ht_playback_control *get_channel_control(struct ast_channel *chan)
{
	ast_channel_lock(chan);
	struct ast_datastore *datastore = ast_channel_datastore_find(chan, &playbackground_ds_info, NULL);
	if (!datastore) {
		ast_channel_unlock(chan);
		return NULL;
	}
	ast_channel_unlock(chan);
	return datastore->data;
}


static void eventfd_skip(int fd)
{
	eventfd_t value;
	read(fd, &value, sizeof (eventfd_t));
}
static void dispatch_jobs(struct stream_layer *layer, struct ht_playback_layer_control *layer_control, ast_mutex_t *mutex)
{
	ast_mutex_lock(mutex);
	if (layer_control->override) {
		stream_layer_override(layer);
		layer_control->override = 0;
	}
	struct playback_control_message *entry;
	while ((entry = AST_DLLIST_FIRST(&layer_control->entries))) {
		stream_layer_add_job(layer, entry->command);
		AST_DLLIST_REMOVE(&layer_control->entries, entry, list_meta);
		ast_free(entry);
	}
	ast_mutex_unlock(mutex);
}


static void *thread_routine(struct ast_channel *chan)
{
	struct ht_playback_control *control = get_channel_control(chan);
	if (!control)
		goto cleanup;

	ast_mutex_lock(&control->mutex);
	int efd = control->eventfd;
	ast_mutex_unlock(&control->mutex);

	struct stream_layer layers[AUDIO_LAYER_COUNT];
	{
		int i;
		for (i = 0; i < sizeof(layers)/sizeof(layers[0]); ++i)
			stream_layer_init(&layers[i]);
	}

	struct stream_state state;
	stream_state_init(&state, chan, efd);

	while (!ast_check_hangup_locked(chan)) {
		/* Update local GRPC TTS value */
		ast_mutex_lock(&control->mutex);
		state.tts_channel = control->tts_channel;
		grpctts_job_conf_cpy(&state.job_conf, &control->conf.job_conf);
		ast_mutex_unlock(&control->mutex);

		int ret = stream_layers(&state, layers, sizeof(layers)/sizeof(layers[0]));
		if (ret == -1) {
			if (ast_channel_errno())
				ast_log(AST_LOG_ERROR, "Streaming error #%d\n", (int) ast_channel_errno());
			else
				ast_log(AST_LOG_DEBUG, "Channel closed\n");
			break;
		}
		if (ret == 1) {
			eventfd_skip(efd);
			if (ast_check_hangup_locked(chan))
				break;
			{
				int i;
				for (i = 0; i < sizeof(layers)/sizeof(layers[0]); ++i)
					dispatch_jobs(&layers[i], &control->layers[i], &control->mutex);
			}
		}
	}

cleanup:
	ast_channel_lock(chan);
	if (!ast_check_hangup(chan))
		ast_stopstream(chan);
	ast_channel_unlock(chan);
	{
		int i;
		for (i = 0; i < sizeof(layers)/sizeof(layers[0]); ++i)
			stream_layer_uninit(&layers[i]);
	}
	ast_channel_unref(chan);
	stream_state_uninit(&state);
	ast_log(AST_LOG_DEBUG, "PlayBackground application thread finished\n");
	return NULL;
}

static struct ht_playback_control *check_get_control(struct ast_channel *chan)
{
	struct ht_playback_control *control = get_channel_control(chan);
	if (control)
		return control;

	if (!(control = make_ht_playback_control()))
		return NULL;

	struct ast_datastore *datastore = ast_datastore_alloc(&playbackground_ds_info, NULL);
	if (!datastore) {
		destroy_ht_playback_control(control);
		return NULL;
	}

	datastore->data = control;

	ast_channel_lock(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);

	ast_channel_ref(chan);

	pthread_t thread;
	ast_pthread_create_detached_background(&thread, NULL, (void*) thread_routine, chan);

	return control;
}
static int playbackgroundinitgrpctts_exec(struct ast_channel *chan, const char *data)
{
	struct ht_playback_control *control = check_get_control(chan);
	if (!control) {
		ast_log(LOG_ERROR, "Failed to initialize 'app_playbackground' control structure\n");
		return -1;
	}

	char *parse = ast_strdupa(data);
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(conf_fname);
		AST_APP_ARG(endpoint);
		AST_APP_ARG(ca_file);
		AST_APP_ARG(remote_frame_format);
	);

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.conf_fname && *args.conf_fname) {
		grpctts_conf_clear(&control->conf);
		grpctts_conf_load(&control->conf, NULL, args.conf_fname, 0);
	}

	if (args.endpoint && *args.endpoint) {
		ast_free(control->conf.endpoint);
		control->conf.endpoint = ast_strdup(args.endpoint);
	}

	if (!control->conf.endpoint) {
		ast_log(LOG_ERROR, "PlayBackgroundInitGRPCTTS: Failed to execute application: no endpoint specified\n");
		return -1;
	}

	if (args.ca_file && *args.ca_file) {
		char *ca_data = grpctts_load_ca_from_file(args.ca_file);
		if (!ca_data)
			return -1;
		ast_free(control->conf.ca_data);
		control->conf.ca_data = ca_data;
	}
	if (args.remote_frame_format && *args.remote_frame_format) {
		if (!strcmp(args.remote_frame_format, "slin")) {
			control->conf.job_conf.remote_frame_format = GRPCTTS_FRAME_FORMAT_SLINEAR16;
		} else if (!strcmp(args.remote_frame_format, "opus")) {
			control->conf.job_conf.remote_frame_format = GRPCTTS_FRAME_FORMAT_OPUS;
		} else {
			ast_log(LOG_ERROR, "PlayBackgroundInitGRPCTTS: Unknown frame format '%s'\n", args.remote_frame_format);
			return -1;
		}
	}

	ast_mutex_lock(&control->mutex);
	if (!control->tts_channel)
		control->tts_channel = grpctts_channel_create(control->conf.endpoint, control->conf.ca_data,
							      control->conf.authorization_api_key, control->conf.authorization_secret_key,
							      control->conf.authorization_issuer, control->conf.authorization_subject, control->conf.authorization_audience);
	ast_mutex_unlock(&control->mutex);

	return 0;
}
static int playbackground_exec(struct ast_channel *chan, const char *data)
{
	struct ht_playback_control *control = check_get_control(chan);
	if (!control) {
		ast_log(LOG_ERROR, "Failed to initialize 'app_playbackground' control structure\n");
		return -1;
	}

	ast_mutex_lock(&control->mutex);
	struct ht_playback_layer_control *layer_control = &control->layers[0];
	if (data[0] == '0' && data[1] == '@') {
		data += 2;
	} else if (data[0] == '1' && data[1] == '@') {
		layer_control = &control->layers[1];
		data += 2;
	} else if (data[0] == '2' && data[1] == '@') {
		layer_control = &control->layers[2];
		data += 2;
	} else if (data[0] == '3' && data[1] == '@') {
		layer_control = &control->layers[3];
		data += 2;
	}
	int empty = 0;
	if (!*data) {
		/* Empty string */
		empty = 1;
		layer_control->override = 1;
	} else if (*data == '&') {
		/* Append commands */
		++data;
	} else {
		/* Replace commands */
		struct playback_control_message *entry;
		while ((entry = AST_DLLIST_FIRST(&layer_control->entries))) {
			AST_DLLIST_REMOVE(&layer_control->entries, entry, list_meta);
			ast_free(entry);
		}
		layer_control->override = 1;
	}
	if (!empty) {
		struct playback_control_message *entry = make_playback_control_message(data);
		AST_DLLIST_INSERT_TAIL(&layer_control->entries, entry, list_meta);
	}
	eventfd_write(control->eventfd, 1);
	ast_mutex_unlock(&control->mutex);

	return 0;
}
static void stream_error_callback(const char *message)
{
	ast_log(LOG_ERROR, "%s\n", message);
}

static int unload_module(void)
{
	stream_layers_global_uninit();
	grpctts_shutdown();
	return ast_unregister_application(app);
}

static int load_module(void)
{
	grpctts_set_stream_error_callback(stream_error_callback);
	grpctts_init();
	stream_layers_global_init();
	if (grpctts_conf_load(&dflt_grpctts_conf, &dflt_grpctts_conf_mutex, "grpctts.conf", 0))
		return AST_MODULE_LOAD_DECLINE;
	return
		ast_register_application_xml(app_initgrpctts, playbackgroundinitgrpctts_exec) |
		ast_register_application_xml(app, playbackground_exec);
}

static int reload(void)
{
	if (grpctts_conf_load(&dflt_grpctts_conf, &dflt_grpctts_conf_mutex, "grpctts.conf", 1))
		return AST_MODULE_LOAD_DECLINE;
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "[" ASTERISK_MODULE_VERSION_STRING "] Background Playback Application",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
);
