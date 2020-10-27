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
 * \brief App wait for event from event queue
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

#include <asterisk.h>

#include <asterisk/pbx.h>
#include <asterisk/module.h>
#include <asterisk/image.h>
#include <asterisk/dlinkedlists.h>
#include <asterisk/stasis_endpoints.h>
#include <asterisk/channel.h>
#include <asterisk/stasis_channels.h>

#include <math.h>
#include <sys/eventfd.h>


static const char *waiteventinit_app = "WaitEventInit";
static const char *waitevent_app = "WaitEvent";

/*** DOCUMENTATION
	<application name="WaitEventInit" language="en_US">
		<synopsis>
			Initializes WaitEvent event queue and starts reading channel frames in background.
		</synopsis>
		<syntax>
		</syntax>
		<description>
			<para>Initializes WaitEvent event queue. This is required for proper WaitEvent() application usage.</para>
			<para>WARNING: If WaitEventInit() isn't called WaitEvent() call still initializes event queue but events sent before WaitEvent() will be silently dropped.</para>
			<para>Starts reading channel frames in background. To actually get consistent queue of frames in background framehook API must be utilized.</para>
			<para>Should be started at the beginning of a channel where non-blocking style is to be used.</para>
		</description>
		<see-also>
			<ref type="application">WaitEvent</ref>
			<ref type="application">GRPCSTTBackground</ref>
			<ref type="application">PlayBackground</ref>
		</see-also>
	</application>
	<application name="WaitEvent" language="en_US">
		<synopsis>
			Waits for first event from queue
		</synopsis>
		<syntax>
			<parameter name="timeout" required="true">
				<para>Time to wait for next event. Interpreted as double precision floating point number.</para>
			</parameter>
		</syntax>
		<description>
			<para>Waits for first event from queue no longer than specified timeout.</para>
			<para>For proper behaviour WaitEventInit() have to be called at the beginning of the channel.</para>
			<para>At execution end 4 varibles may are set: WAITEVENTSTATUS and WAITEVENTBODY</para>
			<variablelist>
				<variable name="WAITEVENTSTATUS">
					<para>Indicates execution status.</para>
					<value name="SUCCESS">
						Have event.
					</value>
					<value name="FAIL">
						Timeout reached, no events retrieved.
					</value>
				</variable>
				<variable name="WAITEVENTFAILREASON">
					<para>Contains fail reason on failure or empty string otherwise.</para>
					<value name="TIMEOUT">
						Timeout reached.
					</value>
					<value name="HANGUP">
						Channel hanged up.
					</value>
					<value name="BAD_EVENT">
						Internal error: bad event generated.
					</value>
				</variable>
				<variable name="WAITEVENTNAME">
					<para>Contains event name if event is recieved or empty string otherwise.</para>
				</variable>
				<variable name="WAITEVENTBODY">
					<para>Contains event body if event is recieved or empty string otherwise.</para>
				</variable>
			</variablelist>
			<para><emphasis>Event generation using AMI is described at examples.</emphasis></para>
			<example title="Wait 2400ms for next event">
			 WaitEvent(2.4);
			</example>
		</description>
		<see-also>
			<ref type="application">WaitEventInit</ref>
			<ref type="application">GRPCSTTBackground</ref>
			<ref type="application">PlayBackground</ref>
		</see-also>
	</application>
 ***/

struct user_message {
	struct ast_json *json_value;
	AST_DLLIST_ENTRY(user_message) list_meta;
};

struct ht_user_message_queue {
	int efd;
	ast_mutex_t mutex;
	AST_DLLIST_HEAD(entries, user_message) entries;
	struct stasis_subscription *stasis_subscription;
};


/* struct user_message methods */
static struct user_message *make_user_message(struct ast_json *json_value)
{
	struct user_message *s = ast_calloc(sizeof(struct user_message), 1);
	s->json_value = json_value;
	return s;
}


/* struct ht_user_message_queue methods */
static void destroy_ht_user_message_queue(void *void_s)
{
	struct ht_user_message_queue *s = void_s;
	close (s->efd);
	if (s->stasis_subscription)
		stasis_unsubscribe_and_join(s->stasis_subscription);
	ast_mutex_destroy(&s->mutex);
	struct user_message *entry;
	while ((entry = AST_DLLIST_FIRST(&s->entries))) {
		struct ast_json *root = entry->json_value;
		AST_DLLIST_REMOVE(&s->entries, entry, list_meta);
		ast_json_unref(root);
		ast_free (entry);
	}
	AST_DLLIST_HEAD_DESTROY(&s->entries);
	ast_free(s);
}
static const struct ast_datastore_info waitevent_ds_info = {
	.type = "waitevent",
	.destroy = destroy_ht_user_message_queue,
};

static struct ht_user_message_queue *make_ht_user_message_queue(void)
{
	struct ht_user_message_queue *s = ast_calloc(sizeof(struct ht_user_message_queue), 1);
	s->efd = eventfd (0, 0);
	ast_mutex_init(&s->mutex);
	return s;
}
static struct user_message *ht_user_message_queue_take_first (struct ht_user_message_queue *s)
{
	ast_mutex_lock(&s->mutex);
	struct user_message *entry = AST_DLLIST_FIRST(&s->entries);
	if (entry) {
		AST_DLLIST_REMOVE(&s->entries, entry, list_meta);
		ast_mutex_unlock(&s->mutex);
		return entry;
	}
	ast_mutex_unlock(&s->mutex);

	return NULL;
}


/* WaitEventInit methods */
static void waitevent_subscription_cb(struct ht_user_message_queue *queue, struct stasis_subscription *sub, struct stasis_message *message)
{
	if (stasis_message_type(message) == ast_multi_user_event_type()) {
		struct user_message *entry = make_user_message(stasis_message_to_json(message, NULL));
		ast_mutex_lock(&queue->mutex);
		AST_DLLIST_INSERT_TAIL(&queue->entries, entry, list_meta);
		ast_mutex_unlock(&queue->mutex);
		eventfd_write(queue->efd, 1);
	}
}

static inline void set_success_status(struct ast_channel *chan, const char *name, const char *body)
{
	pbx_builtin_setvar_helper(chan, "WAITEVENTSTATUS", "SUCCESS");
	pbx_builtin_setvar_helper(chan, "WAITEVENTFAILREASON", "");
	pbx_builtin_setvar_helper(chan, "WAITEVENTNAME", name);
	pbx_builtin_setvar_helper(chan, "WAITEVENTBODY", body);
}
static inline void set_fail_status(struct ast_channel *chan, const char *reason)
{
	pbx_builtin_setvar_helper(chan, "WAITEVENTSTATUS", "FAIL");
	pbx_builtin_setvar_helper(chan, "WAITEVENTFAILREASON", reason);
	pbx_builtin_setvar_helper(chan, "WAITEVENTNAME", "");
	pbx_builtin_setvar_helper(chan, "WAITEVENTBODY", "");
}
static struct ht_user_message_queue *get_channel_queue(struct ast_channel *chan)
{
	ast_channel_lock(chan);
	struct ast_datastore *datastore = ast_channel_datastore_find(chan, &waitevent_ds_info, NULL);
	if (!datastore) {
		ast_channel_unlock(chan);
		return NULL;
	}
	ast_channel_unlock(chan);
	return datastore->data;
}
static int string_starts_with(const char *haystack, const char *needle)
{
	char c;
	while ((c = *needle) && tolower(c) == tolower(*haystack)) {
		++haystack;
		++needle;
	}
	return !*needle;
}
static void check_unref_channel(struct ast_channel *chan)
{
	if (chan)
		ast_channel_unref(chan);
}
static int user_event_hook_cb(int category, const char *event, char *body)
{
	if (!(category & EVENT_FLAG_USER) || strcasecmp(event, "UserEvent"))
		return 0;
	struct ht_user_message_queue *queue = NULL;
	RAII_VAR (struct ast_channel *, chan, NULL, check_unref_channel);
	char *eventname = NULL;
	char *eventbody = NULL;
	char *eventname_e = NULL;
	char *eventbody_e = NULL;
	while (1) {
		if (string_starts_with(body, "Channel:")) {
			char *value = ast_skip_blanks(body + (sizeof("Channel:") - sizeof("")));
			char *value_e = strstr(value, "\r\n");
			if (!value_e)
				return 0;
			char t = *value_e;
			*value_e = '\0';
			check_unref_channel(chan);
			chan = ast_channel_get_by_name(value);
			*value_e = t;
			if (!chan || !(queue = get_channel_queue(chan)))
				return 0;
			body = value_e + (sizeof("\r\n") - sizeof(""));
		} else if (string_starts_with(body, "ChannelState:")) {
			/* Hacky way to filter dialplan events (we only want events from AMI clients) */
			return 0;
		} else if (string_starts_with(body, "UserEvent:")) {
			eventname = ast_skip_blanks(body + (sizeof("UserEvent:") - sizeof("")));
			if (!(eventname_e = strstr(eventname, "\r\n")))
				return 0;
			body = eventname_e + (sizeof("\r\n") - sizeof(""));
		} else if (string_starts_with(body, "EventBody:")) {
			eventbody = ast_skip_blanks(body + (sizeof("EventBody:") - sizeof("")));
			if (!(eventbody_e = strstr(eventbody, "\r\n")))
				return 0;
			body = eventbody_e + (sizeof("\r\n") - sizeof(""));
		} else {
			if (!(body = strstr(body, "\r\n")))
				break;
			body += sizeof("\r\n") - sizeof("");
		}
	}
	if (!eventname || !chan || !queue)
		return 0;

	*eventname_e = '\0';
	if (eventbody_e)
		*eventbody_e = '\0';
	struct ast_json *blob =
		eventbody ?
		ast_json_pack("{s: {s: s, s: s}}", "userevent", "eventname", eventname, "eventbody", eventbody) :
		ast_json_pack("{s: {s: s}}", "userevent", "eventname", eventname);
	*eventname_e = '\r';
	if (eventbody_e)
		*eventbody_e = '\r';

	struct user_message *entry = make_user_message(blob);
	ast_mutex_lock(&queue->mutex);
	AST_DLLIST_INSERT_TAIL(&queue->entries, entry, list_meta);
	ast_mutex_unlock(&queue->mutex);
	eventfd_write(queue->efd, 1);

	return 0;
}
static struct manager_custom_hook user_event_hook = {
	.file = __FILE__,
	.helper = user_event_hook_cb,
};

static struct ht_user_message_queue *init_event_queue(struct ast_channel *chan)
{
	struct stasis_topic *topic = ast_channel_topic(chan);

	struct ht_user_message_queue *queue = make_ht_user_message_queue();
	if (!queue) {
		return NULL;
	}

	struct ast_datastore *datastore = ast_datastore_alloc(&waitevent_ds_info, NULL);
	if (!datastore) {
		destroy_ht_user_message_queue(queue);
		return NULL;
	}

	datastore->data = queue;

	ast_channel_lock(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);

	queue->stasis_subscription = stasis_subscribe(topic, (void *) waitevent_subscription_cb, queue);

	return queue;
}
static int waiteventinit_exec(struct ast_channel *chan, const char *data)
{
	(void) data;

	return init_event_queue(chan) ? 0 : -1;
}


/* WaitEvent methods */
static void store_event(struct ast_channel *chan, struct ast_json *root)
{
	if (!root)
		goto fail;
	struct ast_json *userevent = ast_json_object_get(root, "userevent");
	if (!userevent)
		goto fail;

	struct ast_json *eventname = ast_json_object_get(userevent, "eventname");
	const char *name = eventname ? ast_json_string_get(eventname) : NULL;
	if (!name)
		goto fail;

	struct ast_json *eventbody = ast_json_object_get(userevent, "eventbody");
	set_success_status(chan, name, (eventbody ? ast_json_string_get(eventbody) : ""));
	return;

fail:
	set_fail_status(chan, "BAD_EVENT");
}
static inline void add_time(struct timespec *ts, double timeout)
{
	ts->tv_sec += lrint(ceil(timeout));
	ts->tv_nsec += lrint(remainder(timeout, 1.0)*1000000000.0);
	if (ts->tv_nsec >= 1000000000) {
		++ts->tv_sec;
		ts->tv_nsec -= 1000000000;
	}
}
static inline void time_set_sub(struct timespec *sub, const struct timespec *a, const struct timespec *b)
{
	sub->tv_sec = a->tv_sec - b->tv_sec;
	sub->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (sub->tv_nsec < 0) {
		--sub->tv_sec;
		sub->tv_nsec += 1000000000;
	}
}
static inline int time_gt(const struct timespec *a, const struct timespec *b)
{
	return
		a->tv_sec > b->tv_sec ||
		(a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec);
}
static inline int time_ge(const struct timespec *a, const struct timespec *b)
{
	return
		a->tv_sec > b->tv_sec ||
		(a->tv_sec == b->tv_sec && a->tv_nsec >= b->tv_nsec);
}
static inline void read_out_fd(int fd)
{
	char buffer[4096];
	while (read(fd, buffer, sizeof(buffer)) == sizeof(buffer))
		/* NOOP */;
}
static inline void read_out_frames(struct ast_channel *chan)
{
	int ms;
	while (ms = 0, ast_waitfor_n(&chan, 1, &ms))
		ast_frame_dtor(ast_read(chan));
}
/*
  Waits for channel event or event on event_fd
  Returns:
  -1 on poll error
   0 on timeout
   1 on channel events except hangup
   2 on channel hangup
 */
static int wait_for_channel_and_event_fd(struct ast_channel *chan, int event_fd, const struct timespec *rel_timeout)
{
	struct pollfd pollfds[AST_MAX_FDS + 1];
	size_t i;
	for (i = 0; i < AST_MAX_FDS; ++i) {
		pollfds[i].fd = ast_channel_fd(chan, i);
		pollfds[i].events = ast_channel_fd_isset(chan, i) ? POLLIN : 0;
		pollfds[i].revents = 0;
			
	}
	{
		pollfds[AST_MAX_FDS].fd = event_fd;
		pollfds[AST_MAX_FDS].events = POLLIN;
		pollfds[AST_MAX_FDS].revents = 0;
	}

	int ret = ppoll(pollfds, AST_MAX_FDS + 1, rel_timeout, NULL);
	if (ret <= 0)
		return ret;

	if (pollfds[AST_MAX_FDS].revents & POLLIN) {
		eventfd_t value;
		eventfd_read(event_fd, &value);
	}
	if (pollfds[AST_ALERT_FD].revents & POLLIN) {
		if (ast_check_hangup_locked(chan))
			return 2;
		return 1;
	}
	for (i = 0; i < AST_MAX_FDS; ++i)
		if (pollfds[i].revents & POLLIN)
			return 1;
	return 0;
}

static int waitevent_exec(struct ast_channel *chan, const char *data)
{
	struct ht_user_message_queue *queue = get_channel_queue(chan);
	if (!queue) {
		ast_log(AST_LOG_WARNING, "No queue initialized for 'WaitEvent' command: use 'WaitEventInit()' to initialize queue!!");
		if (!(queue = init_event_queue(chan)))
			return -1;
	}

	double timeout = strtod(data, NULL);
	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC_RAW, &deadline);
	if (timeout > 0.0)
		add_time(&deadline, timeout);

	read_out_frames(chan);

	struct user_message *entry;
	while (!(entry = ht_user_message_queue_take_first(queue))) {
		struct timespec current_time;
		clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
		if (time_ge (&current_time, &deadline))
			break;
		struct timespec rel_timeout;
		time_set_sub(&rel_timeout, &deadline, &current_time);
		int ret = wait_for_channel_and_event_fd(chan, queue->efd, &rel_timeout);
		if (ret < 0) {
			set_fail_status(chan, "POLL_ERROR");
			ast_log(AST_LOG_WARNING, "Failed to poll for channel FDs: %s\n", strerror(errno));
			return 0;
		}
		if (ret == 2) {
			set_fail_status(chan, "HANGUP");
			return 0;
		}
		if (ret == 1) {
			read_out_frames(chan);
		}
	}

	if (entry) {
		struct ast_json *root = entry->json_value;
		store_event(chan, root);
		ast_json_unref(root);
		ast_free (entry);
		return 0;
	}

	set_fail_status(chan, "TIMEOUT");

	return 0;
}

static int unload_module(void)
{
	ast_manager_unregister_hook(&user_event_hook);
	return
		ast_unregister_application(waiteventinit_app) |
		ast_unregister_application(waitevent_app);
}

static int load_module(void)
{
	ast_manager_register_hook(&user_event_hook);
	return
		ast_register_application_xml(waiteventinit_app, waiteventinit_exec) |
		ast_register_application_xml(waitevent_app, waitevent_exec);
}

AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY, "[" ASTERISK_MODULE_VERSION_STRING "] Event Control Application");
