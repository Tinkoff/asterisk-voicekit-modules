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

#include "channelbackend.h"

#include "roots.pem.h"
#include "job.h"
#include "jwt.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <grpcpp/create_channel_posix.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <atomic>


// 7 days
#define EXPIRATION_PERIOD (7*86400)


static grpctts_stream_error_callback_t grpctts_stream_error_callback = NULL;

static const std::string grpc_roots_pem_string ((const char *) grpc_roots_pem, sizeof(grpc_roots_pem));


static int *fd_rc_copy(int *p)
{
	__atomic_add_fetch(&p[1], 1, __ATOMIC_SEQ_CST);
	return p;
}
static void fd_rc_destroy(int *p)
{
	if (!p) return;

	int count = __atomic_add_fetch(&p[1], -1, __ATOMIC_SEQ_CST);
	if (count <= 0) {
		close(p[0]);
		free(p);
	}
}
static int fd_rc_cmp(int *p, int *q)
{
	if (*p < *q)
		return -1;
	if (*p > *q)
		return 1;
	return 0;
}

static const grpc_arg_pointer_vtable fd_rc_vtable = {
	.copy = (void *(*)(void *)) fd_rc_copy,
	.destroy = (void (*)(void *)) fd_rc_destroy,
	.cmp = (int (*)(void *, void *)) fd_rc_cmp,
};

static int *fd_rc_new(int fd)
{
	int *fd_rc = (int *) malloc(sizeof(int[2]));
	if (!fd_rc)
		return nullptr;
	fd_rc[0] = fd;
	fd_rc[1] = 1;
	return fd_rc;
}

static void thread_routine(int channel_completion_fd, const std::string &endpoint, const std::string &ca_data, int socket_fd_pipe_fd, GRPCTTS::ChannelBackend *channel_backend)
{
	grpc::SslCredentialsOptions ssl_credentials_options = {
		.pem_root_certs = ca_data.length() ? ca_data : grpc_roots_pem_string,
	};

	std::shared_ptr<grpc::ChannelCredentials> channel_credentials = grpc::SslCredentials(ssl_credentials_options);
	grpc::ChannelArguments arguments;
	if (socket_fd_pipe_fd != -1) {
		int *fd_rc = fd_rc_new(socket_fd_pipe_fd);
		if (fd_rc) {
			arguments.SetPointerWithVtable("socket_fd_pass_socket_fd", fd_rc, &fd_rc_vtable);
			fd_rc_destroy(fd_rc);
		}
	}

	std::shared_ptr<grpc::Channel> grpc_channel = grpc::CreateCustomChannel(endpoint, channel_credentials, arguments);
	channel_backend->SetChannel(grpc_channel);
	eventfd_write(channel_completion_fd, 1);
}


namespace GRPCTTS {

void ChannelBackend::SetErrorCallback(grpctts_stream_error_callback_t callback)
{
	grpctts_stream_error_callback = callback;
}

#define NON_NULL_STRING(str) ((str) ? (str) : "")
ChannelBackend::ChannelBackend(const char *endpoint, const char *ca_data, const char *authorization_api_key, const char *authorization_secret_key,
			       const char *authorization_issuer, const char *authorization_subject, const char *authorization_audience)
	: socket_fd_pass_socket_fd(-1), channel_completion_fd(eventfd(0, EFD_NONBLOCK)),
	  authorization_api_key(NON_NULL_STRING(authorization_api_key)), authorization_secret_key(NON_NULL_STRING(authorization_secret_key)),
	  authorization_issuer(NON_NULL_STRING(authorization_issuer)), authorization_subject(NON_NULL_STRING(authorization_subject)), authorization_audience(NON_NULL_STRING(authorization_audience))
{
	int socket_fd_pass_write_socket_fd = -1;
	{
		int socket_pair[2];
		if (!socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair)) {
			socket_fd_pass_socket_fd = socket_pair[0];
			socket_fd_pass_write_socket_fd = socket_pair[1];
		}
	}

	thread = std::thread(thread_routine, channel_completion_fd, std::string(endpoint), std::string(ca_data ? ca_data : ""), socket_fd_pass_write_socket_fd, this);
}
#undef NON_NULL_STRING
ChannelBackend::~ChannelBackend()
{
	if (socket_fd_pass_socket_fd != -1) {
		int socket_fd;
		if (recv(socket_fd_pass_socket_fd, &socket_fd, sizeof(int), MSG_DONTWAIT) == sizeof(int)) {
			shutdown(socket_fd, SHUT_RDWR);
			close(socket_fd);
		}
		close(socket_fd_pass_socket_fd);
	}
	thread.join();
	close(channel_completion_fd);
}
void ChannelBackend::SetChannel(std::shared_ptr<grpc::Channel> grpc_channel)
{
	this->grpc_channel = grpc_channel;
}
std::shared_ptr<grpc::Channel> ChannelBackend::GetChannel()
{
	return grpc_channel;
}
int ChannelBackend::ChannelCompletionFD() const
{
	return channel_completion_fd;
}
std::string ChannelBackend::BuildAuthToken() const
{
	if (authorization_api_key.size() && authorization_secret_key.size() &&
	    authorization_issuer.size() && authorization_subject.size() && authorization_audience.size()) {
		int64_t expiration_time_sec = time(NULL) + EXPIRATION_PERIOD;

		std::string jwt = "Bearer " + GenerateJWT(
			authorization_api_key, authorization_secret_key,
			authorization_issuer, authorization_subject, authorization_audience,
			expiration_time_sec);
		return jwt;
	}
	return "";
}

};
