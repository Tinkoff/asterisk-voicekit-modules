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

#include "job.h"

#include "bytequeue.h"
#include "channelbackend.h"
#include "grpctts.h"
#include "RAII.h"

#include <memory>
#include <thread>
#include <unordered_map>

#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <opus.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>


#define CHANNEL_FRAME_SAMPLE_RATE 8000
#define CHANNEL_MAX_OPUS_FRAME_SAMPLES 960
#define CHANNEL_AWAIT_TIMEOUT 60000 /* 60 sec */

#define CXX_STRING(str) (std::string((str) ? (str) : ""))

static grpctts_stream_error_callback_t grpctts_stream_error_callback = NULL;


namespace GRPCTTS {

static void thread_routine(std::shared_ptr<ChannelBackend> channel_backend,
			   double speaking_rate, double pitch, double volume_gain_db,
			   const std::string &voice_language_code, const std::string &voice_name, enum tinkoff::cloud::tts::v1::SsmlVoiceGender ssml_gender,
			   enum grpctts_frame_format remote_frame_format,
			   const std::string &text, const std::string &ssml, std::shared_ptr<ByteQueue> byte_queue)
{
	auto gprc_shutdown_caller = BuildSafeRAII(grpc_shutdown /* To survie module unloading */);
	auto byte_queue_finalizer = BuildSafeRAII([byte_queue]()
						  {
							  byte_queue->Terminate(false);
						  });
	OpusDecoder *opus_decoder = NULL;
	auto opus_finalizer = BuildSafeRAII([&opus_decoder]()
					    {
						    if (opus_decoder)
							    opus_decoder_destroy(opus_decoder);
					    });

	int channel_completion_fd = channel_backend->ChannelCompletionFD();
	struct pollfd pfd = {
		.fd = channel_completion_fd,
		.events = POLLIN,
		.revents = 0,
	};
	poll(&pfd, 1, CHANNEL_AWAIT_TIMEOUT);
	if (!(pfd.revents & POLLIN)) {
		if (grpctts_stream_error_callback)
			grpctts_stream_error_callback("GRPC TTS stream finished with error: failed to initialize channel");
		return;
	}

	std::shared_ptr<grpc::Channel> grpc_channel = channel_backend->GetChannel();
	if (!grpc_channel) {
		if (grpctts_stream_error_callback)
			grpctts_stream_error_callback("GRPC TTS stream finished with error: failed to initialize channel");
		return;
	}

	grpc::ClientContext context;
	std::string auth_token(channel_backend->BuildAuthToken());
	if (auth_token.length())
		context.AddMetadata("authorization", auth_token);
	std::unique_ptr<tinkoff::cloud::tts::v1::TextToSpeech::Stub> tts_stub = tinkoff::cloud::tts::v1::TextToSpeech::NewStub(grpc_channel);
	tinkoff::cloud::tts::v1::SynthesizeSpeechRequest request;

	{
		tinkoff::cloud::tts::v1::SynthesisInput *input = request.mutable_input();
		if (text.size()) {
			input->set_text(text);
		}
		if (ssml.size()) {
			input->set_ssml(ssml);
		}
	}
	{
		tinkoff::cloud::tts::v1::VoiceSelectionParams *voice = request.mutable_voice();
		voice->set_language_code(voice_language_code);
		voice->set_name(voice_name);
		voice->set_ssml_gender(ssml_gender);
	}
	{
		tinkoff::cloud::tts::v1::AudioConfig *audio_config = request.mutable_audio_config();
		switch (remote_frame_format) {
		case GRPCTTS_FRAME_FORMAT_OPUS:
			audio_config->set_audio_encoding(tinkoff::cloud::tts::v1::RAW_OPUS);
			break;
		default:
			audio_config->set_audio_encoding(tinkoff::cloud::tts::v1::LINEAR16);
		}
		if (remote_frame_format == GRPCTTS_FRAME_FORMAT_OPUS) {
			int error;
			opus_decoder = opus_decoder_create(CHANNEL_FRAME_SAMPLE_RATE, 1, &error);
			if (error != OPUS_OK || !opus_decoder) {
				if (grpctts_stream_error_callback)
					grpctts_stream_error_callback("GRPC TTS stream finished with error: failed to initialize Opus decoder");
				return;
			}
		}
		audio_config->set_speaking_rate(speaking_rate);
		// audio_config->set_pitch(pitch); - ingore for now
		// audio_config->set_volume_gain_db(volume_gain_db); - ingore for now
		audio_config->set_sample_rate_hertz(CHANNEL_FRAME_SAMPLE_RATE);
	}
	std::unique_ptr<grpc::ClientReader<tinkoff::cloud::tts::v1::StreamingSynthesizeSpeechResponse>> stream = tts_stub->StreamingSynthesize(&context, request);
	stream->WaitForInitialMetadata();
	std::string x_request_id;
	int64_t num_samples = -1;
	const std::multimap<grpc::string_ref, grpc::string_ref> &metadata = context.GetServerInitialMetadata();
	{
		std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator x_request_id_it = metadata.find("x-request-id");
		if (x_request_id_it != metadata.end()) {
			const grpc::string_ref &x_request_id_ref = x_request_id_it->second;
			x_request_id = std::string(x_request_id_ref.data(), x_request_id_ref.size());
			if (x_request_id.size() > 255)
				x_request_id.resize(255);
		}
	}
	{
		std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator x_audio_num_samples_it = metadata.find("x-audio-num-samples");
		if (x_audio_num_samples_it != metadata.end()) {
			const grpc::string_ref &x_audio_num_samples_ref = x_audio_num_samples_it->second;
			std::string x_audio_num_samples(x_audio_num_samples_ref.data(), x_audio_num_samples_ref.size());
			std::size_t conv_count;
			num_samples = std::stoll(x_audio_num_samples, &conv_count);
			if (conv_count != x_audio_num_samples.size())
				num_samples = -1;
		}
	}
	{
		std::string initial_data((const char *) &num_samples, sizeof(int64_t));
		initial_data.append(1, uint8_t(x_request_id.size()));
		initial_data.append(x_request_id);
		byte_queue->Push(initial_data);
	}

	tinkoff::cloud::tts::v1::StreamingSynthesizeSpeechResponse response;
	while (stream->Read(&response)) {
		switch (remote_frame_format) {
		case GRPCTTS_FRAME_FORMAT_OPUS: {
			const std::string &audio_chunk = response.audio_chunk();
			int16_t frame_samples[CHANNEL_MAX_OPUS_FRAME_SAMPLES];
			int num_samples_per_channel = opus_decode(opus_decoder, (const unsigned char *) audio_chunk.data(), audio_chunk.size(),
								  frame_samples, sizeof(frame_samples)/sizeof(frame_samples[0]), 0);
			if (!num_samples_per_channel) {
				if (grpctts_stream_error_callback)
					grpctts_stream_error_callback("GRPC TTS stream finished with error: no audio decoded from Opus");
				return;
			} else if (num_samples_per_channel < 0) {
				if (grpctts_stream_error_callback) {
					char message[4096];
					snprintf(message, sizeof(message), "GRPC TTS stream finished with error: failed to decoded audio from Opus: %s", opus_strerror(num_samples_per_channel));
					grpctts_stream_error_callback(message);
				}
				return;
			}
			byte_queue->Push(std::string((const char *) frame_samples, num_samples_per_channel*sizeof(int16_t)));
		} break;
		default: {
			byte_queue->Push(response.audio_chunk());
		}
		}
	}
	grpc::Status status = stream->Finish();
	byte_queue->Terminate(status.ok());
	if (!status.ok() && grpctts_stream_error_callback) {
		char message[4096];
		snprintf(message, sizeof(message), "GRPC TTS stream finished with error (code = %d): %s", (int) status.error_code(), status.error_message().c_str());
		grpctts_stream_error_callback(message);
	}
}


void Job::SetErrorCallback(grpctts_stream_error_callback_t callback)
{
	grpctts_stream_error_callback = callback;
}


static std::atomic<int> Job_alloc_balance;

Job::Job(std::shared_ptr<ChannelBackend> channel_backend,
	 double speaking_rate, double pitch, double volume_gain_db,
	 const std::string &voice_language_code, const std::string &voice_name, enum tinkoff::cloud::tts::v1::SsmlVoiceGender ssml_gender,
	 enum grpctts_frame_format remote_frame_format, const struct grpctts_job_input &job_input)
	: byte_queue(std::make_shared<ByteQueue>())
{
	grpc_init(); // To survie module unloading
	std::thread thread = std::thread(thread_routine,
					 channel_backend,
					 speaking_rate, pitch, volume_gain_db,
					 voice_language_code, voice_name, ssml_gender, remote_frame_format,
					 CXX_STRING(job_input.text), CXX_STRING(job_input.ssml), byte_queue);
	thread.detach();
}
Job::~Job()
{
}
int Job::EventFD()
{
	return byte_queue->EventFD();
}
bool Job::Collect()
{
	return byte_queue->Collect();
}
size_t Job::BufferSize()
{
	return byte_queue->BufferSize();
}
bool Job::TakeBlock(size_t byte_count, void *data)
{
	return byte_queue->TakeBlock(byte_count, data);
}
size_t Job::TakeTail(size_t byte_count, void *data)
{
	return byte_queue->TakeTail(byte_count, data);
}
bool Job::TerminationCalled()
{
	return byte_queue->TerminationCalled();
}
bool Job::CompletionSuccess()
{
	return byte_queue->CompletionSuccess();
}

};
