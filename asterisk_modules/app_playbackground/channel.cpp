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

#include "channel.h"

#include "job.h"
#include "channelbackend.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/create_channel_posix.h>
#include <grpcpp/security/credentials.h>


namespace GRPCTTS {

Channel::Channel(const char *endpoint, const char *ca_data, const char *authorization_api_key, const char *authorization_secret_key,
		 const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience)
	: channel_backend (std::make_shared<ChannelBackend> (endpoint, ca_data, authorization_api_key, authorization_secret_key,
							     authorization_issuer, authorization_subject, authorization_audience))
{
}
Channel::~Channel()
{
}
Job *Channel::StartJob(double speaking_rate, double pitch, double volume_gain_db,
		       const std::string &voice_language_code, const std::string &voice_name, enum tinkoff::cloud::tts::v1::SsmlVoiceGender ssml_gender,
		       enum grpctts_frame_format remote_frame_format,
		       const struct grpctts_job_input &job_input)
{
	return new Job(channel_backend,
		       speaking_rate, pitch, volume_gain_db,
		       voice_language_code, voice_name, ssml_gender, remote_frame_format,
		       job_input);
}

};
