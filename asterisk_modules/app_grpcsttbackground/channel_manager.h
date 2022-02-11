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

#include <memory>
#include <map>
#include <string>
#include <mutex>

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#ifndef ASTERISK_VOICEKIT_MODULES_CHANNEL_MANAGER_H
#define ASTERISK_VOICEKIT_MODULES_CHANNEL_MANAGER_H

typedef std::map <std::string, std::map<std::string, std::shared_ptr<grpc::Channel>>> chann_storage;

class ChannelManager {
	static std::mutex map_mutex;
    static std::unique_ptr<chann_storage> channels;
    static std::shared_ptr <grpc::Channel> create_channel(const char *endpoint, const char *ssl, int ssl_grpc);

public:
    static std::shared_ptr <grpc::Channel> get_channel(const char *endpoint, const char *ssl, int ssl_grpc);
	static void clear();
};

#endif //ASTERISK_VOICEKIT_MODULES_CHANNEL_MANAGER_H
