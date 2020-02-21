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

extern struct ast_module *AST_MODULE_SELF_SYM(void);
#define AST_MODULE_SELF_SYM AST_MODULE_SELF_SYM

#define _GNU_SOURCE 1
#include "grpctts_conf.h"

#include <stdio.h>
#include <regex.h>
#include <sys/stat.h>
#include <asterisk.h>
#include <asterisk/paths.h>
#include <asterisk/pbx.h>


#define MAX_INMEMORY_FILE_SIZE (256*1024*1024)


static regex_t cre_fraction;
static int cre_fraction_status;
static regex_t cre_seconds;
static int cre_seconds_status;

void grpctts_conf_global_init(void)
{
	cre_fraction_status = regcomp(&cre_fraction, "\\([0-9]\\+\\(.[0-9]*\\)\\?\\)\\%", 0);
	cre_seconds_status = regcomp(&cre_seconds, "\\([0-9]\\+\\(.[0-9]*\\)\\?\\)s", 0);
}	
void grpctts_conf_global_uninit(void)
{
	if (!cre_fraction_status)
		regfree(&cre_fraction);
	if (!cre_seconds_status)
		regfree(&cre_seconds);
}


char *grpctts_load_ca_from_file(const char *relative_fname)
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


static int match_fraction(double *fraction_r, const char *str)
{
	if (cre_fraction_status)
		return 0;

	size_t len = strlen(str);

	regmatch_t pmatch[3];
	if (regexec(&cre_fraction, str, 3, pmatch, 0))
		return 0;
	if (pmatch[0].rm_so || pmatch[0].rm_eo != len)
		return 0;

	if (pmatch[1].rm_eo == -1)
		return 0;

	char buffer[4096];
	snprintf(buffer, sizeof(buffer), "%.*s", (int) (pmatch[1].rm_eo - pmatch[1].rm_so), str + pmatch[1].rm_so);

	char *eptr;
	double fraction = strtod(buffer, &eptr);
	if (eptr != (buffer + strlen(buffer)))
		return 0;

	*fraction_r = fraction;
	return 1;
}
static int match_seconds(double *fraction_r, const char *str)
{
	if (cre_seconds_status)
		return 0;

	size_t len = strlen(str);

	regmatch_t pmatch[3];
	if (regexec(&cre_seconds, str, 3, pmatch, 0))
		return 0;
	if (pmatch[0].rm_so || pmatch[0].rm_eo != len || pmatch[1].rm_eo == -1)
		return 0;

	char buffer[4096];
	snprintf(buffer, sizeof(buffer), "%.*s", (int) (pmatch[1].rm_eo - pmatch[1].rm_so), str + pmatch[1].rm_so);

	char *eptr;
	double fraction = strtod(buffer, &eptr);
	if (eptr != (buffer + strlen(buffer)))
		return 0;

	*fraction_r = fraction;
	return 1;
}

int grpctts_parse_buffer_size(struct grpctts_buffer_size *buffer_size, const char *str)
{
	const char *sep_pos = strchr(str, '+');
	if (sep_pos) {
		char buffer_fraction[4096];
		snprintf(buffer_fraction, sizeof(buffer_fraction), "%.*s", (int) (sep_pos - str), str);
		char buffer_seconds[4096];
		snprintf(buffer_seconds, sizeof(buffer_seconds), "%s", sep_pos + 1);
		return match_fraction(&buffer_size->fraction, buffer_fraction) &&
			match_seconds(&buffer_size->seconds, buffer_seconds);
	} else if (match_fraction(&buffer_size->fraction, str)) {
		buffer_size->seconds = 0.0;
	} else if (match_seconds(&buffer_size->seconds, str)) {
		buffer_size->fraction = 0.0;
	} else {
		return 0;
	}

	return 1;
}


void grpctts_job_conf_init(struct grpctts_job_conf *conf)
{
	conf->speaking_rate = 1.0;
	conf->pitch = 0.0;
	conf->volume_gain_db = 0.0;
	conf->voice_language_code = NULL;
	conf->voice_name = NULL;
	conf->voice_gender = GRPCTTS_VOICE_GENDER_UNSPECIFIED;
	conf->remote_frame_format = GRPCTTS_FRAME_FORMAT_SLINEAR16;
	conf->initial_buffer_size.fraction = 0.0;
	conf->initial_buffer_size.seconds = 0.0;
}
void grpctts_job_conf_clear(struct grpctts_job_conf *conf)
{
	ast_free(conf->voice_language_code);
	ast_free(conf->voice_name);

	conf->speaking_rate = 1.0;
	conf->pitch = 0.0;
	conf->volume_gain_db = 0.0;
	conf->voice_language_code = NULL;
	conf->voice_name = NULL;
	conf->voice_gender = GRPCTTS_VOICE_GENDER_UNSPECIFIED;
	conf->remote_frame_format = GRPCTTS_FRAME_FORMAT_SLINEAR16;
	conf->initial_buffer_size.fraction = 0.0;
	conf->initial_buffer_size.seconds = 0.0;
}
struct grpctts_job_conf *grpctts_job_conf_cpy(struct grpctts_job_conf *dest, const struct grpctts_job_conf *src)
{
	dest->speaking_rate = src->speaking_rate;
	dest->pitch = src->pitch;
	dest->volume_gain_db = src->volume_gain_db;
	ast_free(dest->voice_language_code);
	ast_free(dest->voice_name);
	dest->voice_language_code = ast_strdup(src->voice_language_code);
	dest->voice_name = ast_strdup(src->voice_name);
	dest->voice_gender = src->voice_gender;
	dest->remote_frame_format = src->remote_frame_format;
	dest->initial_buffer_size = src->initial_buffer_size;
	return dest;
}


void grpctts_conf_init(struct grpctts_conf *conf)
{
	conf->endpoint = NULL;
	conf->ssl_grpc = 0;
	conf->ca_data = NULL;
	conf->authorization_api_key = NULL;
	conf->authorization_secret_key = NULL;
	conf->authorization_issuer = NULL;
	conf->authorization_subject = NULL;
	conf->authorization_audience = NULL;

	grpctts_job_conf_init(&conf->job_conf);
}
void grpctts_conf_clear(struct grpctts_conf *conf)
{
	ast_free(conf->endpoint);
	ast_free(conf->ca_data);
	ast_free(conf->authorization_api_key);
	ast_free(conf->authorization_secret_key);
	ast_free(conf->authorization_issuer);
	ast_free(conf->authorization_subject);
	ast_free(conf->authorization_audience);

	conf->endpoint = NULL;
	conf->ssl_grpc = 0;
	conf->ca_data = NULL;
	conf->authorization_api_key = NULL;
	conf->authorization_secret_key = NULL;
	conf->authorization_issuer = NULL;
	conf->authorization_subject = NULL;
	conf->authorization_audience = NULL;

	grpctts_job_conf_clear(&conf->job_conf);
}
int grpctts_conf_load(struct grpctts_conf *conf, ast_mutex_t *mutex, const char *fname, int reload)
{
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_config *cfg = ast_config_load(fname, config_flags);
	if (!cfg) {
		if (mutex)
			ast_mutex_lock(mutex);
		grpctts_conf_clear(conf);
		if (mutex)
			ast_mutex_unlock(mutex);
		return 0;
	}
	if (cfg == CONFIG_STATUS_FILEUNCHANGED)
		return 0;
	if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file grpctts.conf is in an invalid format.  Aborting.\n");
		return -1;
	}

	if (mutex)
		ast_mutex_lock(mutex);

	grpctts_conf_clear(conf);

	char *cat = ast_category_browse(cfg, NULL);
	while (cat) {
		if (!strcasecmp(cat, "general") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "endpoint")) {
					ast_free(conf->endpoint);
					conf->endpoint = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "use_ssl")) {
					conf->ssl_grpc = ast_true(var->value);
				} else if (!strcasecmp(var->name, "ca_file")) {
					char *ca_data = grpctts_load_ca_from_file(var->value);
					if (!ca_data) {
						if (mutex)
							ast_mutex_unlock(mutex);
						ast_config_destroy(cfg);
						return -1;
					}
					conf->ca_data = ca_data;
				} else if (!strcasecmp(var->name, "pitch")) {
					char *eptr;
					double value = strtod(var->value, &eptr);
					if (*var->value && !*eptr)
						conf->job_conf.pitch = value;
					else
						ast_log(AST_LOG_ERROR, "PlayBackground: parse error at '%s': invalid 'pitch' value\n", fname);
				} else if (!strcasecmp(var->name, "volume_gain_db")) {
					char *eptr;
					double value = strtod(var->value, &eptr);
					if (*var->value && !*eptr)
						conf->job_conf.volume_gain_db = value;
					else
						ast_log(AST_LOG_ERROR, "PlayBackground: parse error at '%s': invalid 'volume_gain_db' value\n", fname);
				} else if (!strcasecmp(var->name, "speaking_rate")) {
					char *eptr;
					double value = strtod(var->value, &eptr);
					if (*var->value && !*eptr)
						conf->job_conf.speaking_rate = value;
					else
						ast_log(AST_LOG_ERROR, "PlayBackground: parse error at '%s': invalid 'speaking_rate' value\n", fname);
				} else if (!strcasecmp(var->name, "voice_language_code")) {
					ast_free(conf->job_conf.voice_language_code);
					conf->job_conf.voice_language_code = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "voice_name")) {
					ast_free(conf->job_conf.voice_name);
					conf->job_conf.voice_name = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "voice_gender")) {
					if (!strcmp(var->value, "male"))
						conf->job_conf.voice_gender = GRPCTTS_VOICE_GENDER_MALE;
					else if (!strcmp(var->value, "female"))
						conf->job_conf.voice_gender = GRPCTTS_VOICE_GENDER_FEMALE;
					else if (!strcmp(var->value, "neutral"))
						conf->job_conf.voice_gender = GRPCTTS_VOICE_GENDER_NEUTRAL;
					else if (!strcmp(var->value, "unspecified") || !strcmp(var->value, ""))
						conf->job_conf.voice_gender = GRPCTTS_VOICE_GENDER_UNSPECIFIED;
					else
						ast_log(AST_LOG_ERROR, "PlayBackground: parse error at '%s': invalid 'voice_gender' value\n", fname);
				} else if (!strcasecmp(var->name, "remote_frame_format")) {
					if (!strcmp(var->value, "slin"))
						conf->job_conf.remote_frame_format = GRPCTTS_FRAME_FORMAT_SLINEAR16;
					else if (!strcmp(var->value, "opus"))
						conf->job_conf.remote_frame_format = GRPCTTS_FRAME_FORMAT_OPUS;
					else
						ast_log(AST_LOG_ERROR, "PlayBackground: parse error at '%s': invalid 'remote_frame_format' value\n", fname);
				} else {
					ast_log(LOG_ERROR, "PlayBackground: parse error at '%s': category '%s': unknown keyword '%s' at line %d\n", fname, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		} else if (!strcasecmp(cat, "authorization") ) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "api_key")) {
					ast_free(conf->authorization_api_key);
					conf->authorization_api_key = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "secret_key")) {
					ast_free(conf->authorization_secret_key);
					conf->authorization_secret_key = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "issuer")) {
					ast_free(conf->authorization_issuer);
					conf->authorization_issuer = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "subject")) {
					ast_free(conf->authorization_subject);
					conf->authorization_subject = ast_strdup(var->value);
				} else if (!strcasecmp(var->name, "audience")) {
					ast_free(conf->authorization_audience);
					conf->authorization_audience = ast_strdup(var->value);
				} else {
					ast_log(LOG_ERROR, "PlayBackground: parse error at '%s': category '%s': unknown keyword '%s' at line %d\n", fname, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		} else if (!strcasecmp(cat, "buffering")) {
			struct ast_variable *var = ast_variable_browse(cfg, cat);
			while (var) {
				if (!strcasecmp(var->name, "initial_buffer_size")) {
					struct grpctts_buffer_size initial_buffer_size;
					if (grpctts_parse_buffer_size(&initial_buffer_size, var->value)) {
						conf->job_conf.initial_buffer_size = initial_buffer_size;
					} else {
						ast_log(LOG_ERROR, "PlayBackground: parse error at '%s': category '%s': invalid buffer size specification '%s' at line %d\n",
							fname, cat, var->value, var->lineno);
					}
				} else {
					ast_log(LOG_ERROR, "PlayBackground: parse error at '%s': category '%s': unknown keyword '%s' at line %d\n", fname, cat, var->name, var->lineno);
				}
				var = var->next;
			}
		}
		cat = ast_category_browse(cfg, cat);
	}

	if (mutex)
		ast_mutex_unlock(mutex);
	ast_config_destroy(cfg);

	return 0;
}
struct grpctts_conf *grpctts_conf_cpy(struct grpctts_conf *dest, const struct grpctts_conf *src, ast_mutex_t *src_mutex)
{
	ast_free(dest->endpoint);
	ast_free(dest->ca_data);
	ast_free(dest->authorization_api_key);
	ast_free(dest->authorization_secret_key);
	ast_free(dest->authorization_issuer);
	ast_free(dest->authorization_subject);
	ast_free(dest->authorization_audience);
	ast_free(dest->job_conf.voice_language_code);
	ast_free(dest->job_conf.voice_name);

	if (src_mutex)
		ast_mutex_lock(src_mutex);

	if (!grpctts_job_conf_cpy(&dest->job_conf, &src->job_conf)) {
		if (src_mutex)
			ast_mutex_unlock(src_mutex);
		grpctts_conf_init(dest);
		return NULL;
	}
	dest->endpoint = ast_strdup(src->endpoint);
	dest->ssl_grpc = src->ssl_grpc;
	dest->ca_data = ast_strdup(src->ca_data);
	dest->authorization_api_key = ast_strdup(src->authorization_api_key);
	dest->authorization_secret_key = ast_strdup(src->authorization_secret_key);
	dest->authorization_issuer = ast_strdup(src->authorization_issuer);
	dest->authorization_subject = ast_strdup(src->authorization_subject);
	dest->authorization_audience = ast_strdup(src->authorization_audience);

	if (src_mutex)
		ast_mutex_unlock(src_mutex);

	return dest;
}
