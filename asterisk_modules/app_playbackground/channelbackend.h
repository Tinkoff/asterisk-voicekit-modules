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

#ifndef GRPCTTS_CHANNEL_BACKEND_H
#define GRPCTTS_CHANNEL_BACKEND_H

#include <memory>
#include <thread>


typedef void (*grpctts_stream_error_callback_t)(const char *message);


struct grpctts_job_input;

namespace grpc {
class Channel;
};


namespace GRPCTTS {

class ChannelBackend
{
public:
	static void SetErrorCallback(grpctts_stream_error_callback_t callback);

public:
	ChannelBackend(const char *endpoint, const char *ca_data, const char *authorization_api_key, const char *authorization_secret_key,
		       const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience);
	~ChannelBackend();
	void SetChannel(std::shared_ptr<grpc::Channel> grpc_channel);
	std::shared_ptr<grpc::Channel> GetChannel(); // To be called after polling on channel_completion_fd shows some data
	int ChannelCompletionFD() const;
	std::string BuildAuthToken() const;

private:
	int socket_fd_pass_socket_fd;
	std::shared_ptr<grpc::Channel> grpc_channel;
	int channel_completion_fd;
	const std::string authorization_api_key;
	const std::string authorization_secret_key;
	const std::string authorization_issuer;
	const std::string authorization_subject;
	const std::string authorization_audience;
	std::thread thread;
};

};

#endif
