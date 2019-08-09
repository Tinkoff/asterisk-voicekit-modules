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

#ifndef GRPCTTS_CHANNEL_H
#define GRPCTTS_CHANNEL_H

#include "tts.grpc.pb.h"
#include "grpctts.h"

#include <string>
#include <memory>


struct grpctts_job_input;

namespace grpc {
class Channel;
};


namespace GRPCTTS {

class Job;
class ChannelBackend;


class Channel
{
public:
	Channel(const char *endpoint, const char *ca_data, const char *authorization_api_key, const char *authorization_secret_key,
		const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience);
	~Channel();
	Job *StartJob(double speaking_rate, double pitch, double volume_gain_db,
		      const std::string &voice_language_code, const std::string &voice_name, enum tinkoff::cloud::tts::v1::SsmlVoiceGender ssml_gender,
		      enum grpctts_frame_format remote_frame_format,
		      const struct grpctts_job_input &job_input);

private:
	std::shared_ptr<ChannelBackend> channel_backend;
};

};

#endif
