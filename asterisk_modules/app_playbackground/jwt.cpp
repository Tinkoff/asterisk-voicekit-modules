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

#define _GNU_SOURCE 1
#include "jwt.h"

#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>

extern "C" {
#include <asterisk.h>
#include <asterisk/json.h>
};


/* Base64 implementation is adapted from https://www.boost.org/doc/libs/1_70_0/boost/beast/core/detail/base64.ipp */
static const char base64_rev_alpha[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0-15
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16-31
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32-47
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48-63
	-1,  0,	 1,  2,	 3,  4,	 5,  6,	 7,  8,	 9, 10, 11, 12, 13, 14, //  64-79
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80-95
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96-111
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128-143
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 144-159
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 160-175
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 176-191
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 192-207
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 208-223
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 224-239
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1	// 240-255
};
static const char base64_alpha_url_safe[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
};

static std::string base64_decode(const std::string &src, bool *ok = NULL)
{
	std::string dest;

	unsigned char const *in = reinterpret_cast<unsigned char const*>(src.data());
	std::size_t len = src.size();
	unsigned char c3[3], c4[4];

	int i = 0;
	while (len-- && *in != '=') {
		char v = base64_rev_alpha[*in];
		if (v == -1) {
			if (ok)
				*ok = false;
			return "";
		}
		++in;
		c4[i] = v;
		if (++i == 4) {
			c3[0] =	 (c4[0]	       << 2) + ((c4[1] & 0x30) >> 4);
			c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
			c3[2] = ((c4[2] & 0x3) << 6) +	 c4[3];

			dest.append(reinterpret_cast<const char*>(c3), 3);

			i = 0;
		}
	}

	if (i) {
		c3[0] = ( c4[0]	       << 2) + ((c4[1] & 0x30) >> 4);
		c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
		c3[2] = ((c4[2] & 0x3) << 6) +	 c4[3];

		dest.append(reinterpret_cast<const char*>(c3), i - 1);
	}

	if (ok)
		*ok = true;
	return dest;
}
static std::string base64_encode_url_safe(const std::string &src)
{
	std::string dest;

	const char *in = src.data();
	const char *tab = base64_alpha_url_safe;

	size_t len = src.size();

	for (size_t n = len/3; n--;) {
		char chunk[] = {
			tab[ (in[0] & 0xfc) >> 2],
			tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)],
			tab[((in[2] & 0xc0) >> 6) + ((in[1] & 0x0f) << 2)],
			tab[  in[2] & 0x3f],
		};
		dest.append(chunk, 4);
		in += 3;
	}

	switch (len % 3) {
	case 2: {
		char chunk[] = {
			tab[ (in[0] & 0xfc) >> 2],
			tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)],
			tab[			     (in[1] & 0x0f) << 2],
			'=',
		};
		dest.append(chunk, 4);
	} break;
	case 1: {
		char chunk[] = {
			tab[ (in[0] & 0xfc) >> 2],
			tab[((in[0] & 0x03) << 4)],
			'=',
			'=',
		};
		dest.append(chunk, 4);
	}
	}

	return dest;
}

static std::string build_header(const std::string &api_key)
{
	struct ast_json *json = ast_json_pack(
		"{s: s, s: s, s: s}",
		"alg", "HS256",
		"typ", "JWT",
		"kid", api_key.c_str());
	if (!json)
		return "";

	char *serialized = ast_json_dump_string(json);
	std::string ret(serialized ? serialized : "");
	ast_json_free(serialized);

	ast_json_unref(json);

	return ret;
}
static std::string build_payload(const std::string &issuer, const std::string &subject, const std::string &audience, int64_t expires_at)
{
	double expires_at_value = expires_at;
	struct ast_json *json = ast_json_pack(
		"{s: s, s: s, s: s, s: f}",
		"iss", issuer.c_str(),
		"sub", subject.c_str(),
		"aud", audience.c_str(),
		"exp", expires_at_value);
	if (!json)
		return "";

	char *serialized = ast_json_dump_string(json);
	std::string ret(serialized ? serialized : "");
	ast_json_free(serialized);

	ast_json_unref(json);

	return ret;
}


std::string GenerateJWT(const std::string &api_key, const std::string &secret_key,
			const std::string &issuer, const std::string &subject, const std::string &audience,
			int64_t expiration_time_sec)
{
	std::string jwt;

	std::string header_bytes = build_header(api_key);
	std::string payload_bytes = build_payload(issuer, subject, audience, expiration_time_sec);

	std::string data = base64_encode_url_safe(header_bytes) + "." + base64_encode_url_safe(payload_bytes);

	std::string secret_decoded = base64_decode(secret_key);
	
	unsigned char sig[SHA256_DIGEST_LENGTH];
	unsigned int sig_len;
	unsigned char *ret = HMAC(EVP_sha256(), secret_decoded.data(), secret_decoded.size(), (const unsigned char *) data.data(), data.size(), sig, &sig_len);
	if (!ret)
		return jwt;
	std::string signature = std::string(reinterpret_cast<const char *>(sig), sig_len);
	std::string signature_b64 = base64_encode_url_safe(signature);
	jwt = data + "." + signature_b64;

	return jwt;
}
