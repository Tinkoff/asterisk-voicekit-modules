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

#include "mutex"
#include "map"

#include "channel_manager.h"
#include "roots.pem.h"

static const std::string grpc_roots_pem_string ((const char *) grpc_roots_pem, sizeof(grpc_roots_pem));

std::map <std::string, std::map<std::string, std::shared_ptr < grpc::Channel>>> ChannelManager::channels = {};
std::mutex map_mutex;


std::shared_ptr <grpc::Channel> ChannelManager::get_channel(const char *endpoint, const char *ssl, int ssl_grpc) {
	std::string endpoint_str = endpoint == NULL ? "" : endpoint;
	std::string ssl_str = ssl == NULL ? "" : ssl;

	std::lock_guard<std::mutex> guard(map_mutex);
	if (!channels.count(endpoint_str)) {
		std::shared_ptr<grpc::Channel> channel = create_channel(endpoint, ssl, ssl_grpc);
		channels[endpoint_str][ssl_str] = channel;
		return channel;
	}
	std::map<std::string, std::shared_ptr<grpc::Channel>> ssl_map = channels[endpoint];
	if (!ssl_map.count(ssl_str)) {
		std::shared_ptr <grpc::Channel> channel = create_channel(endpoint, ssl, ssl_grpc);
		ssl_map[ssl_str] = channel;
		return channel;
	}
	return ssl_map[ssl_str];
}

std::shared_ptr<grpc::Channel> ChannelManager::create_channel(const char *endpoint, const char *ssl, int ssl_grpc) {
	grpc::SslCredentialsOptions ssl_credentials_options = {
			.pem_root_certs = ssl ? ssl : grpc_roots_pem_string,
	};
	return grpc::CreateChannel(
			endpoint,
			(ssl_grpc ? grpc::SslCredentials(ssl_credentials_options) : grpc::InsecureChannelCredentials()
			));
}