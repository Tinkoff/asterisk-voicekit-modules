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
 * \brief A background Speech-To-Text recognition integration application using GRPC API
 *
 * \author Grigori Okopnik <g.e.okopnik@tinkoff.ru>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

extern struct ast_module *AST_MODULE_SELF_SYM(void);
#define AST_MODULE_SELF_SYM AST_MODULE_SELF_SYM

#include "grpc_stt.h"

#include <grpc/grpc.h>

#include <asterisk.h>
#include <asterisk/pbx.h>
#include <asterisk/app.h>
#include <asterisk/module.h>
#include <asterisk/manager.h>
#include <asterisk/utils.h>
#include <asterisk/astobj2.h>
#include <asterisk/dlinkedlists.h>
#include <asterisk/format_cache.h>
#include <asterisk/paths.h>
#include <asterisk/alaw.h>

#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <math.h>

/*** DOCUMENTATION
	<application name="GRPCSTTBackground" language="en_US">
		<synopsis>
			Recognize incoming channel speech into text.
		</synopsis>
		<syntax>
			<parameter name="endpoint" required="true">
				<para>Specifies service endpoint with HOST:PORT format</para>
			</parameter>
			<parameter name="options">
				<optionlist>
					<option name="S">
						<para>Use TLS credentials</para>
					</option>
					<option name="A">
						<para>Encode UTF-8 characters as ASCII escape sequence at generated JSON events</para>
					</option>
				</optionlist>
			</parameter>
			<parameter name="language_code">
				<para>Specifies language code for STT session</para>
			</parameter>
			<parameter name="frame_format">
				<para>Specifies STT service request frame format</para>
				<para>Allowed values: &quot;alaw&quot;, &quot;ulaw&quot; and &quot;slin&quot;</para>
			</parameter>
			<parameter name="max_alternatives">
				<para>Specifies maximum number of alternatives</para>
			</parameter>
			<parameter name="ca_file">
				<para>Specifies maximum number of alternatives</para>
			</parameter>
		</syntax>
		<description>
			<para>This application connects to STT service at specified endpoint.</para>
			<para>It then sends incomming channel audio frames and recieves recognized text.</para>
			<para>Upon each recieved recognized phrase a channel user event is generated wich may be catched with WaitEvent() application or AMI subsystem.</para>
			<para>Following events are generated (event body is specified inside braces):</para>
			<para><emphasis>At receiving heading metafields of STT session &quot;GRPCSTT_X_REQUEST_ID(X_REQUEST_ID)&quot; event is generated.</emphasis></para>
			<para><emphasis>At receiving STT recognition hypothesis &quot;GRPCSTT_ASCII(JSON)&quot; and &quot;GRPCSTT_UTF8(JSON)&quot; events are generated.</emphasis></para>
			<para><emphasis>At session close an &quot;GRPCSTT_SESSION_FINISHED(STATUS,ERROR_CODE,ERROR_MESSAGE)&quot; event is generated.</emphasis></para>
			<example title="Start streaming to STT at domain.org:300 with TLS and A-Law sample format">
			 GRPCSTTBackground(domain.org:300,S,,alaw);
			</example>
			<example title="Start streaming to STT at example.org:8080 without TLS, with ASCII-encoded Unicode characters, SLinear16 sample format and maximum of 3 alternatives">
			 GRPCSTTBackground(example.org:8080,A,,slin,3);
			</example>
			<example title="Get next event and print details if event is GRPCSTT_SESSION_FINISHED">
			 WaitEvent(${SLEEP_TIME});
			 if (${WAITEVENTNAME} == GRPCSTT_SESSION_FINISHED) {
			         Set(ARRAY(STATUS,ERROR_CODE,ERROR_MESSAGE)=${WAITEVENTBODY});
			         if (${STATUS} == SUCCESS) {
			                 Log(NOTICE,Session finished successfully);
			         } else {
			                 Log(NOTICE,Session finished with error ${ERROR_CODE}: ${ERROR_MESSAGE});
			         }
			 }
			</example>
		</description>
		<see-also>
			<ref type="application">WaitEvent</ref>
			<ref type="application">WaitEventInit</ref>
			<ref type="application">PlayBackground</ref>
			<ref type="application">GRPCSTTBackgroundFinish</ref>
		</see-also>
	</application>
	<application name="GRPCSTTBackgroundFinish" language="en_US">
		<synopsis>
			Finish speech recognition session.
		</synopsis>
		<description>
			<para>This application terminates speech recognition session previously runned by GRPCSTTBackground().</para>
			<para>It is safe to call GRPCSTTBackgroundFinish() even if no GRPCSTTBackground() was previously called.</para>
		</description>
		<see-also>
			<ref type="application">GRPCSTTBackground</ref>
		</see-also>
	</application>
 ***/
static const char app[] = "GRPCSTTBackground";
static const char app_finish[] = "GRPCSTTBackgroundFinish";

enum grpcsttbackground_flags {
	GRPCSTTBACKGROUND_FLAG_NO_SSL_GRPC = (1 << 1),
	GRPCSTTBACKGROUND_FLAG_SSL_GRPC = (1 << 2),
};

AST_APP_OPTIONS(grpcsttbackground_opts, {
	AST_APP_OPTION('s', GRPCSTTBACKGROUND_FLAG_NO_SSL_GRPC),
	AST_APP_OPTION('S', GRPCSTTBACKGROUND_FLAG_SSL_GRPC),
});

struct thread_conf {
	int terminate_event_fd;
	char *authorization_api_key;
	char *authorization_secret_key;
	char *authorization_issuer;
	char *authorization_subject;
	char *authorization_audience;
	struct ast_channel *chan;
	char *endpoint;
	int ssl_grpc;
	char *ca_data;
	char *language_code; /* optional */
	int max_alternatives;
	enum grpc_stt_frame_format frame_format;
	int vad_disable;
	double vad_min_speech_duration;
	double vad_max_speech_duration;
	double vad_silence_duration_threshold;
	double vad_silence_prob_threshold;
	double vad_aggressiveness;
	int interim_results_enable;
	double interim_results_interval;
};

static struct thread_conf dflt_thread_conf = {
	.terminate_event_fd = -1,
	.authorization_api_key = NULL,
	.authorization_secret_key = NULL,
	.authorization_issuer = NULL,
	.authorization_subject = NULL,
	.authorization_audience = NULL,
	.chan = NULL,
	.endpoint = NULL,
	.ssl_grpc = 0,
	.ca_data = NULL,
	.language_code = NULL,
	.max_alternatives = 1,
	.frame_format = GRPC_STT_FRAME_FORMAT_ALAW,
	.vad_disable = 0,
	.vad_min_speech_duration = 0.0,
	.vad_max_speech_duration = 0.0,
	.vad_silence_duration_threshold = 0.0,
	.vad_silence_prob_threshold = 0.0,
	.vad_aggressiveness = 0.0,
	.interim_results_enable = 0,
	.interim_results_interval = 0.0,
};
static ast_mutex_t dflt_thread_conf_mutex;

#define MAX_INMEMORY_FILE_SIZE (256*1024*1024)

static char *load_ca_from_file(const char *relative_fname)
{
	char fname[512];
	snprintf(fname, sizeof(fname), "%s/%s", ast_config_AST_CONFIG_DIR, relative_fname);
	FILE *fh = fopen(fname, "r");
	if (!fh) {
		ast_log(AST_LOG_ERROR, "Failed to open CA file '%s' for reading: %s\n", fname, strerror(errno));
		return NULL;
	}
	struct stat st;
	if (fstat(fileno(fh), &st)) {
		ast_log(AST_LOG_ERROR, "Failed to stat CA file '%s' for reading: %s\n", fname, strerror(errno));
		fclose(fh);
		return NULL;
	}
	size_t size = st.st_size;
	if (size > MAX_INMEMORY_FILE_SIZE) {
		ast_log(AST_LOG_ERROR, "Failed to read CA file '%s' into memory: file too big\n", fname);
		fclose(fh);
		return NULL;
	}
	char *data = (char *) ast_malloc(size + 1);
	if (!data) {
		ast_log(AST_LOG_ERROR, "Failed to read CA file '%s' into memory: failed to allocate buffer\n", fname);
		fclose(fh);
		return NULL;
	}
	if (fread(data, 1, size, fh) != size) {
		ast_log(AST_LOG_ERROR, "Failed to read CA file '%s' into memory: %s\n", fname, feof(fh) ? "unexpected EOF" : strerror(errno));
		fclose(fh);
		ast_free(data);
		return NULL;
	}
	data[size] = '\0';
	fclose(fh);
	return data;
}

static struct thread_conf *make_thread_conf(const struct thread_conf *source)
{
	size_t authorization_api_key_len = source->authorization_api_key ? (strlen(source->authorization_api_key) + 1) : 0;
	size_t authorization_secret_key_len = source->authorization_secret_key ? (strlen(source->authorization_secret_key) + 1) : 0;
	size_t authorization_issuer_len = source->authorization_issuer ? (strlen(source->authorization_issuer) + 1) : 0;
	size_t authorization_subject_len = source->authorization_subject ? (strlen(source->authorization_subject) + 1) : 0;
	size_t authorization_audience_len = source->authorization_audience ? (strlen(source->authorization_audience) + 1) : 0;
	size_t endpoint_len = strlen(source->endpoint) + 1;
	size_t language_code_len = source->language_code ? (strlen(source->language_code) + 1) : 0;
	size_t ca_data_len = source->ca_data ? (strlen(source->ca_data) + 1) : 0;
	struct thread_conf *conf = ast_malloc(sizeof(struct thread_conf) + authorization_api_key_len + authorization_api_key_len +
					      authorization_issuer_len + authorization_subject_len + authorization_audience_len +
					      endpoint_len + ca_data_len + language_code_len);
	if (!conf)
		return NULL;
	void *p = conf + 1;
	conf->terminate_event_fd = -1;
	conf->chan = source->chan;

	conf->authorization_api_key = source->authorization_api_key ? strcpy(p, source->authorization_api_key) : NULL;
	p += authorization_api_key_len;
	conf->authorization_secret_key = source->authorization_secret_key ? strcpy(p, source->authorization_secret_key) : NULL;
	p += authorization_secret_key_len;
	conf->authorization_issuer = source->authorization_issuer ? strcpy(p, source->authorization_issuer) : NULL;
	p += authorization_issuer_len;
	conf->authorization_subject = source->authorization_subject ? strcpy(p, source->authorization_subject) : NULL;
	p += authorization_subject_len;
	conf->authorization_audience = source->authorization_audience ? strcpy(p, source->authorization_audience) : NULL;
	p += authorization_audience_len;
	conf->endpoint = strcpy(p, source->endpoint);
	p += endpoint_len;
	conf->ssl_grpc = source->ssl_grpc;
	conf->ca_data = source->ca_data ? strcpy(p, source->ca_data) : NULL;
	p += ca_data_len;
	conf->language_code = source->language_code ? strcpy(p, source->language_code) : NULL;
	conf->max_alternatives = source->max_alternatives;
	conf->frame_format = source->frame_format;
	conf->vad_disable = source->vad_disable;
	conf->vad_min_speech_duration = source->vad_min_speech_duration;
	conf->vad_max_speech_duration = source->vad_max_speech_duration;
	conf->vad_silence_duration_threshold = source->vad_silence_duration_threshold;
	conf->vad_silence_prob_threshold = source->vad_silence_prob_threshold;
	conf->vad_aggressiveness = source->vad_aggressiveness;
	conf->interim_results_enable = source->interim_results_enable;
	conf->interim_results_interval = source->interim_results_interval;
	return conf;
}


static void *thread_start(struct thread_conf *conf)
{
	struct ast_channel *chan = conf->chan;
	grpc_stt_run(conf->terminate_event_fd, conf->endpoint, conf->authorization_api_key, conf->authorization_secret_key,
		     conf->authorization_issuer, conf->authorization_subject, conf->authorization_audience,
		     chan, conf->ssl_grpc, conf->ca_data, conf->language_code, conf->max_alternatives, conf->frame_format,
		     conf->vad_disable, conf->vad_min_speech_duration, conf->vad_max_speech_duration,
		     conf->vad_silence_duration_threshold, conf->vad_silence_prob_threshold, conf->vad_aggressiveness,
		     conf->interim_results_enable, conf->interim_results_interval);

	close(conf->terminate_event_fd);
	ast_channel_unref(chan);
	ast_free(conf);
	return NULL;
}

static void clear_config(void)
{
	ast_free(dflt_thread_conf.authorization_api_key);
	ast_free(dflt_thread_conf.authorization_secret_key);
	ast_free(dflt_thread_conf.authorization_issuer);
	ast_free(dflt_thread_conf.authorization_subject);
	ast_free(dflt_thread_conf.authorization_audience);
	ast_free(dflt_thread_conf.endpoint);
	ast_free(dflt_thread_conf.ca_data);
	ast_free(dflt_thread_conf.language_code);
	dflt_thread_conf.authorization_api_key = NULL;
	dflt_thread_conf.authorization_secret_key = NULL;
	dflt_thread_conf.authorization_issuer = NULL;
	dflt_thread_conf.authorization_subject = NULL;
	dflt_thread_conf.authorization_audience = NULL;
	dflt_thread_conf.chan = NULL;
	dflt_thread_conf.endpoint = NULL;
	dflt_thread_conf.ssl_grpc = 0;
	dflt_thread_conf.ca_data = NULL;
	dflt_thread_conf.language_code = NULL;
	dflt_thread_conf.max_alternatives = 1;
	dflt_thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_ALAW;
	dflt_thread_conf.vad_disable = 0;
	dflt_thread_conf.vad_min_speech_duration = 0.0;
	dflt_thread_conf.vad_max_speech_duration = 0.0;
	dflt_thread_conf.vad_silence_duration_threshold = 0.0;
	dflt_thread_conf.vad_silence_prob_threshold = 0.0;
	dflt_thread_conf.vad_aggressiveness = 0.0;
	dflt_thread_conf.interim_results_enable = 0;
	dflt_thread_conf.interim_results_interval = 0.0;
}
static int load_config(int reload)
{
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_config *cfg = ast_config_load("grpcstt.conf", config_flags);
	if (!cfg) {
		ast_mutex_lock(&dflt_thread_conf_mutex);
		clear_config();
		ast_mutex_unlock(&dflt_thread_conf_mutex);
		return 0;
	}
	if (cfg == CONFIG_STATUS_FILEUNCHANGED)
		return 0;
	if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file grpcstt.conf is in an invalid format.  Aborting.\n");
		return -1;
	}

	ast_mutex_lock(&dflt_thread_conf_mutex);

	clear_config();

	char *cat = ast_category_browse(cfg, NULL);
	while (cat) {
		if (!strcasecmp(cat, "general") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "endpoint")) {
					dflt_thread_conf.endpoint = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "use_ssl")) {
					dflt_thread_conf.ssl_grpc = ast_true(var->value);
				} else if (!strcasecmp(var->name, "ca_file")) {
					dflt_thread_conf.ca_data = load_ca_from_file(var->value);
				} else if (!strcasecmp(var->name, "language_code")) {
					dflt_thread_conf.language_code = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "max_alternatives")) {
					dflt_thread_conf.max_alternatives = atoi(var->value);
				} else if (!strcasecmp(var->name, "frame_format")) {
					if (!strcmp(var->value, "alaw")) {
						dflt_thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_ALAW;
					} else if (!strcmp(var->value, "ulaw")) {
						dflt_thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_MULAW;
					} else if (!strcmp(var->value, "slin")) {
						dflt_thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_SLINEAR16;
					} else {
						ast_log(LOG_ERROR, "Unsupported frame format '%s'\n", var->value);
						ast_mutex_unlock(&dflt_thread_conf_mutex);
						ast_config_destroy(cfg);
						return -1;
					}
				} else {
					ast_log(LOG_WARNING, "%s: Cat:%s. Unknown keyword %s at line %d of grpcstt.conf\n", app, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		} else if (!strcasecmp(cat, "vad") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "disable")) {
					dflt_thread_conf.vad_disable = ast_true(var->value);
				} else if (!strcasecmp(var->name, "min_speech_duration")) {
					dflt_thread_conf.vad_min_speech_duration = atof(var->value);
				} else if (!strcasecmp(var->name, "max_speech_duration")) {
					dflt_thread_conf.vad_max_speech_duration = atof(var->value);
				} else if (!strcasecmp(var->name, "silence_duration_threshold")) {
					dflt_thread_conf.vad_silence_duration_threshold = atof(var->value);
				} else if (!strcasecmp(var->name, "silence_prob_threshold")) {
					dflt_thread_conf.vad_silence_prob_threshold = atof(var->value);
				} else if (!strcasecmp(var->name, "aggressiveness")) {
					dflt_thread_conf.vad_aggressiveness = atof(var->value);
				} else {
					ast_log(LOG_WARNING, "%s: Cat:%s. Unknown keyword %s at line %d of grpcstt.conf\n", app, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		} else if (!strcasecmp(cat, "interim_results") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "enable")) {
					dflt_thread_conf.interim_results_enable = ast_true(var->value);
				} else if (!strcasecmp(var->name, "interval")) {
					dflt_thread_conf.interim_results_interval = atof(var->value);
				} else {
					ast_log(LOG_WARNING, "%s: Cat:%s. Unknown keyword %s at line %d of grpcstt.conf\n", app, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		} else if (!strcasecmp(cat, "authorization") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "api_key")) {
					dflt_thread_conf.authorization_api_key = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "secret_key")) {
					dflt_thread_conf.authorization_secret_key = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "issuer")) {
					dflt_thread_conf.authorization_issuer = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "subject")) {
					dflt_thread_conf.authorization_subject = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "audience")) {
					dflt_thread_conf.authorization_audience = ast_strdup(var->value);
				} else {
					ast_log(LOG_WARNING, "%s: Cat:%s. Unknown keyword %s at line %d of grpcstt.conf\n", app, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		}
		cat = ast_category_browse(cfg, cat);
	}

	ast_mutex_unlock(&dflt_thread_conf_mutex);
	ast_config_destroy(cfg);

	return 0;
}
struct grpcsttbackground_control {
	int terminate_event_fd;
};
static struct grpcsttbackground_control *make_grpcsttbackground_control(int terminate_event_fd)
{
	struct grpcsttbackground_control *s = ast_calloc(sizeof(struct grpcsttbackground_control), 1);
	if (!s)
		return NULL;
	s->terminate_event_fd = terminate_event_fd;
	return s;
}
static void destroy_grpcsttbackground_control(void *void_s)
{
	struct grpcsttbackground_control *s = void_s;
	eventfd_write(s->terminate_event_fd, 1);
	close(s->terminate_event_fd);
	ast_free(s);
}
static const struct ast_datastore_info grpcsttbackground_ds_info = {
	.type = "grpcsttbackground",
	.destroy = destroy_grpcsttbackground_control,
};
static void clear_channel_control_state_unlocked(struct ast_channel *chan)
{
	struct ast_datastore *datastore = ast_channel_datastore_find(chan, &grpcsttbackground_ds_info, NULL);
	if (datastore) {
		ast_channel_datastore_remove(chan, datastore);
		ast_datastore_free(datastore);
	}
}
static void clear_channel_control_state(struct ast_channel *chan)
{
	ast_channel_lock(chan);
	clear_channel_control_state_unlocked(chan);
	ast_channel_unlock(chan);
}
static void replace_channel_control_state_unlocked(struct ast_channel *chan, int terminate_event_fd)
{
	clear_channel_control_state_unlocked(chan);

	struct grpcsttbackground_control *control = make_grpcsttbackground_control(terminate_event_fd);
	if (!control)
		return;
	struct ast_datastore *datastore = ast_datastore_alloc(&grpcsttbackground_ds_info, NULL);
	if (!datastore) {
		destroy_grpcsttbackground_control(control);
		return;
	}
	datastore->data = control;
	ast_channel_datastore_add(chan, datastore);
}
static void replace_channel_control_state(struct ast_channel *chan, int terminate_event_fd)
{
	ast_channel_lock(chan);
	replace_channel_control_state_unlocked(chan, terminate_event_fd);
	ast_channel_unlock(chan);
}

static int make_event_fd_pair(int *parent_fd_p, int *child_fd_p)
{
	int parent_fd = eventfd(0, 0);
	if (parent_fd < 0) {
		*parent_fd_p = -1;
		*child_fd_p = -1;
		return -1;
	}
	int child_fd = dup(parent_fd);
	if (child_fd < 0) {
		int saved_errno = errno;
		close(parent_fd);
		*parent_fd_p = -1;
		*child_fd_p = -1;
		errno = saved_errno;
		return -1;
	}
	*parent_fd_p = parent_fd;
	*child_fd_p = child_fd;
	return 0;
}

static int grpcsttbackground_exec(struct ast_channel *chan, const char *data)
{
	ast_mutex_lock(&dflt_thread_conf_mutex);
	struct thread_conf thread_conf = dflt_thread_conf;
	thread_conf.chan = chan;

	char *parse = ast_strdupa(data);
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(endpoint);
		AST_APP_ARG(options);
		AST_APP_ARG(language_code);
		AST_APP_ARG(frame_format);
		AST_APP_ARG(max_alternatives);
		AST_APP_ARG(ca_file);
	);

	AST_STANDARD_APP_ARGS(args, parse);

	if (args.endpoint && *args.endpoint)
		thread_conf.endpoint = args.endpoint;

	if (!thread_conf.endpoint) {
		ast_log(LOG_ERROR, "%s: Failed to execute application: no endpoint specified\n", app);
		ast_mutex_unlock(&dflt_thread_conf_mutex);
		return -1;
	}

	if (args.options) {
		struct ast_flags flags = { 0 };
		ast_app_parse_options(grpcsttbackground_opts, &flags, NULL, args.options);

		if (ast_test_flag(&flags, GRPCSTTBACKGROUND_FLAG_NO_SSL_GRPC))
			thread_conf.ssl_grpc = 0;
		if (ast_test_flag(&flags, GRPCSTTBACKGROUND_FLAG_SSL_GRPC))
			thread_conf.ssl_grpc = 1;
	}

	if (args.language_code && *args.language_code)
		thread_conf.language_code = args.language_code;

	RAII_VAR (char *, ca_data, NULL, ast_free);
	if (args.ca_file && *args.ca_file) {
		if (!(ca_data = load_ca_from_file(args.ca_file)))
			return -1;
		ast_free(thread_conf.ca_data);
		thread_conf.ca_data = ca_data;
	}

	if (args.frame_format && *args.frame_format) {
		if (!strcmp(args.frame_format, "alaw")) {
			thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_ALAW;
		} else if (!strcmp(args.frame_format, "ulaw")) {
			thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_MULAW;
		} else if (!strcmp(args.frame_format, "slin")) {
			thread_conf.frame_format = GRPC_STT_FRAME_FORMAT_SLINEAR16;
		} else {
			ast_log(LOG_ERROR, "Unsupported frame format '%s'\n", args.frame_format);
			ast_mutex_unlock(&dflt_thread_conf_mutex);
			return -1;
		}
	}

	if (args.max_alternatives && *args.max_alternatives) {
		char *eptr;
		long int value = strtol(args.max_alternatives, &eptr, 10);
		if (!*eptr || value <= 0)
			thread_conf.max_alternatives = value;
		else
			ast_log(LOG_WARNING, "Invalid max alternatives count %s specified\n", args.max_alternatives);
	}

	ast_channel_ref(chan);
	struct thread_conf *conf = make_thread_conf(&thread_conf);
	ast_mutex_unlock(&dflt_thread_conf_mutex);
	if (!conf) {
		ast_channel_unref(chan);
		return -1;
	}
	int terminate_event_fd, child_terminate_event_fd;
	if (make_event_fd_pair(&terminate_event_fd, &child_terminate_event_fd)) {
		ast_channel_unref(chan);
		return -1;
	}
	
	conf->terminate_event_fd = child_terminate_event_fd;
	pthread_t thread;
	if (ast_pthread_create_detached_background(&thread, NULL, (void *) thread_start, conf)) {
		ast_log(AST_LOG_ERROR, "Failed to start thread\n");
		ast_channel_unref(chan);
		close(terminate_event_fd);
		close(child_terminate_event_fd);
		return -1;
	}
	replace_channel_control_state(chan, terminate_event_fd);

	return 0;
}
static int grpcsttbackgroundfinish_exec(struct ast_channel *chan, const char *data)
{
	clear_channel_control_state(chan);
	return 0;
}


static int unload_module(void)
{
	grpc_shutdown();
	ast_mutex_lock(&dflt_thread_conf_mutex);
	clear_config();
	ast_mutex_unlock(&dflt_thread_conf_mutex);
	return
		ast_unregister_application(app) |
		ast_unregister_application(app_finish);
}

static int load_module(void)
{
	grpc_init();
	if (load_config(0) ||
	    (ast_register_application_xml(app, grpcsttbackground_exec) |
	     ast_register_application_xml(app_finish, grpcsttbackgroundfinish_exec)))
		return AST_MODULE_LOAD_DECLINE;
	return AST_MODULE_LOAD_SUCCESS;
}

static int reload(void)
{
	if (load_config(1))
		return AST_MODULE_LOAD_DECLINE;
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "[" ASTERISK_MODULE_VERSION_STRING "] GRPCSTTBackground Application",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.reload = reload,
);
