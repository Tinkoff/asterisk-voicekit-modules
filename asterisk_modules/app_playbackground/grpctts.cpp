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

#define typeof __typeof__
#include "grpctts.h"

#include "channel.h"
#include "grpctts_conf.h"
#include "channelbackend.h"
#include "job.h"
#include "tts.grpc.pb.h"

#include <grpc/grpc.h>
#include <sys/stat.h>


extern "C" void grpctts_set_stream_error_callback(grpctts_stream_error_callback_t callback)
{
	GRPCTTS::ChannelBackend::SetErrorCallback(callback);
	GRPCTTS::Job::SetErrorCallback(callback);
}
extern "C" void grpctts_init()
{
	grpc_init();
}
extern "C" void grpctts_shutdown()
{
	grpc_shutdown();
}


extern "C" struct grpctts_channel *grpctts_channel_create(const char *endpoint, const char *ca_data,
							  const char *authorization_api_key, const char *authorization_secret_key,
							  const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience)
{
	GRPCTTS::Channel *channel = new GRPCTTS::Channel(endpoint, ca_data, authorization_api_key, authorization_secret_key,
							 authorization_issuer, authorization_subject, authorization_audience);
	return (struct grpctts_channel *) channel;
}
extern "C" void grpctts_channel_destroy(struct grpctts_channel *channel)
{
	delete (GRPCTTS::Channel *) channel;
}
extern "C" struct grpctts_job *grpctts_channel_start_job(struct grpctts_channel *channel, const struct grpctts_job_conf *job_conf, const struct grpctts_job_input *job_input)
{
	enum tinkoff::cloud::tts::v1::SsmlVoiceGender ssml_gender = tinkoff::cloud::tts::v1::SSML_VOICE_GENDER_UNSPECIFIED;
	switch (job_conf->voice_gender) {
	case GRPCTTS_VOICE_GENDER_UNSPECIFIED:
		ssml_gender = tinkoff::cloud::tts::v1::SSML_VOICE_GENDER_UNSPECIFIED;
		break;
	case GRPCTTS_VOICE_GENDER_MALE:
		ssml_gender = tinkoff::cloud::tts::v1::MALE;
		break;
	case GRPCTTS_VOICE_GENDER_FEMALE:
		ssml_gender = tinkoff::cloud::tts::v1::FEMALE;
		break;
	case GRPCTTS_VOICE_GENDER_NEUTRAL:
		ssml_gender = tinkoff::cloud::tts::v1::NEUTRAL;
	}
	return (struct grpctts_job *) ((GRPCTTS::Channel *) channel)->StartJob(
		job_conf->speaking_rate, job_conf->pitch, job_conf->volume_gain_db,
		"", (job_conf->voice_name ? job_conf->voice_name : ""), ssml_gender,
		job_conf->remote_frame_format,
		*job_input);
}


extern "C" void grpctts_job_destroy(struct grpctts_job *job)
{
	delete (GRPCTTS::Job *) job;
}
extern "C" int grpctts_job_event_fd(struct grpctts_job *job)
{
	return ((GRPCTTS::Job *) job)->EventFD();
}
extern "C" int grpctts_job_collect(struct grpctts_job *job)
{
	return ((GRPCTTS::Job *) job)->Collect();
}
extern "C" size_t grpctts_job_buffer_size(struct grpctts_job *job)
{
	return ((GRPCTTS::Job *) job)->BufferSize();
}
extern "C" int grpctts_job_take_block(struct grpctts_job *job, size_t byte_count, void *data)
{
	return ((GRPCTTS::Job *) job)->TakeBlock(byte_count, data);
}
extern "C" size_t grpctts_job_take_tail(struct grpctts_job *job, size_t byte_count, void *data)
{
	return ((GRPCTTS::Job *) job)->TakeTail(byte_count, data);
}
extern "C" int grpctts_job_termination_called(struct grpctts_job *job)
{
	return ((GRPCTTS::Job *) job)->TerminationCalled();
}
extern "C" int grpctts_job_completion_success(struct grpctts_job *job)
{
	return ((GRPCTTS::Job *) job)->CompletionSuccess();
}
