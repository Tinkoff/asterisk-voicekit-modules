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
 * \brief Function for getting current time
 *
 * \author Grigoriy Okopnik <g.e.okopnik@tinkoff.ru>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>extended</support_level>
 ***/

#include <asterisk.h>

#include <asterisk/pbx.h>
#include <asterisk/module.h>
#include <asterisk/channel.h>

#include <time.h>


/*** DOCUMENTATION
	<function name="GET_TIME_NSEC" language="en_US">
		<synopsis>
			Returns time in seconds with nanosecond precision as real value.
		</synopsis>
		<syntax>
			<parameter name="CLOCK" required="false">
				<para>Specifies source CLOCK.</para>
				<para>Allowed values are UTC and MONOTONIC.</para>
			</parameter>
		</syntax>
		<description>
			<example title="Get current time since epoch in UTC (using CLOCK_REALTIME clock)">
			 Log(Notice,UTC = ${GET_TIME_NSEC(UTC)});
			 // e. g., "UTC = 1547817040.192614270"
			</example>
			<example title="Get current time since unspecified point without synchronization jumps (using CLOCK_MONOTONIC_RAW clock)">
			 Log(Notice,Monotonic = ${GET_TIME_NSEC(MONOTONIC)});
			 // e. g., "Monotonic = 13480206.384741348"
			</example>
		</description>
	</function>
 ***/

static int afc_gettimensec_exec(struct ast_channel *chan, const char *cmd, char *parse, char *buffer, size_t buflen)
{
	struct timespec current_time = {0, 0};
	if (!strcasecmp(parse, "UTC")) {
		if (clock_gettime(CLOCK_REALTIME, &current_time)) {
			ast_log(AST_LOG_ERROR, "Failed to get current time (0.0 returned): %s\n", strerror(errno));
			current_time.tv_sec = 0;
			current_time.tv_nsec = 0;
		}
	} else if (!strcasecmp(parse, "MONOTONIC")) {
		if (clock_gettime(CLOCK_MONOTONIC_RAW, &current_time)) {
			ast_log(AST_LOG_ERROR, "Failed to get monotonic time (0.0 returned): %s\n", strerror(errno));
			current_time.tv_sec = 0;
			current_time.tv_nsec = 0;
		}
	} else {
		ast_log(AST_LOG_ERROR, "Unknown clock '%s' (0.0 returned)\n", parse);
	}

	sprintf(buffer, "%llu.%09u", (long long int) current_time.tv_sec, (unsigned int) current_time.tv_nsec);

	return 0;
}

static struct ast_custom_function acf_gettimensec = {
	.name = "GET_TIME_NSEC",
	.read = afc_gettimensec_exec,
	.read_max = 32,
};

static int unload_module(void)
{
	ast_custom_function_unregister(&acf_gettimensec);

	return 0;
}

static int load_module(void)
{
	return ast_custom_function_register(&acf_gettimensec);
}

AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY, "Current time function");
