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

#ifndef JWT_H
#define JWT_H

#include <stdint.h>
#include <string>

std::string GenerateJWT(
	const std::string &api_key,
	const std::string &secret_key,
	const std::string &issuer,
	const std::string &subject,
	const std::string &audience,
	int64_t expiration_time_sec);

#endif
