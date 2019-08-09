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

#include "bytequeue.h"

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <atomic>


namespace GRPCTTS {

struct Record
{
	Record(bool completion_success)
		: completion_success(completion_success), next(NULL)
		{
		}
	Record(const std::string &data)
		: data(data), completion_success(false), next(NULL)
		{
		}
	bool IsEmpty()
		{
			return data.empty();
		}

	std::string data;
	bool completion_success;
	Record* next;
};


ByteQueue::ByteQueue()
	: event_fd(eventfd(0, EFD_NONBLOCK)), exchange_head(NULL),
	  recieved_head(NULL), recieved_tail_p(&recieved_head), head_offset(0), recieved_byte_count(0),
	  termination_pushed(false), termination_called(false), completion_success(false)
{
}
ByteQueue::~ByteQueue()
{
	Collect();
	while (recieved_head) {
		Record *record = recieved_head;
		recieved_head = recieved_head->next;
		delete record;
	}
	close(event_fd);
}
void ByteQueue::Push(const std::string &data)
{
	if (termination_pushed)
		return;
	PushRecord(new Record(data));
}
void ByteQueue::Terminate(bool completion_success)
{
	if (termination_pushed)
		return;
	PushRecord(new Record(completion_success));
	termination_pushed = true;
}
int ByteQueue::EventFD()
{
	return event_fd;
}
bool ByteQueue::TerminationCalled()
{
	return termination_called;
}
bool ByteQueue::CompletionSuccess()
{
	return completion_success;
}
bool ByteQueue::Collect()
{
	eventfd_t value = 0;
	eventfd_read(event_fd, &value);
	Record *new_exchange_head = NULL;
	Record *reversed_recieved_head;
	__atomic_exchange(&exchange_head, &new_exchange_head, &reversed_recieved_head, __ATOMIC_SEQ_CST);
	if (!reversed_recieved_head)
		return false;
	StoreReverseList(reversed_recieved_head);
	return true;
}
size_t ByteQueue::BufferSize()
{
	return recieved_byte_count;
}
bool ByteQueue::TakeBlock(size_t byte_count, void *data)
{
	if (byte_count > recieved_byte_count)
		return false;
	ExtractBytes(byte_count, data);
	return true;
}
size_t ByteQueue::TakeTail(size_t byte_count, void *data)
{
	size_t write_left = std::min(byte_count, recieved_byte_count);
	ExtractBytes(write_left, data);
	return write_left;
}
void ByteQueue::PushRecord(Record *object)
{
	__atomic_exchange(&exchange_head, &object, &object->next, __ATOMIC_SEQ_CST);
	eventfd_write(event_fd, 1);
}
void ByteQueue::ExtractBytes(size_t byte_count, void *data)
{
	size_t write_left = byte_count;
	char *dptr = (char *) data;
	while (write_left > 0) {
		Record *head = recieved_head;
		size_t left_at_record = head->data.size() - head_offset;
		if (write_left >= left_at_record) {
			memcpy(dptr, head->data.data() + head_offset, left_at_record);
			dptr += left_at_record;
			recieved_byte_count -= left_at_record;
			write_left -= left_at_record;
			recieved_head = head->next;
			delete head;
			head_offset = 0;
			if (!recieved_head)
				recieved_tail_p = &recieved_head;
		} else {
			memcpy(dptr, head->data.data() + head_offset, write_left);
			head_offset += write_left;
			recieved_byte_count -= write_left;
			break;
		}
	}
}
void ByteQueue::StoreReverseList(Record *queue)
{
	// 1. Reverse
	Record **new_tail = &queue->next;
	Record *prev = queue;
	queue = queue->next;
	prev->next = NULL;
	while (queue) {
		Record *next = queue->next;
		queue->next = prev;
		prev = queue;
		queue = next;
	}
	Record *list_head = prev;

	// 2. Append to current list
	*recieved_tail_p = list_head;
	recieved_tail_p = new_tail;

	// 3. Count bytes and set termination flag and status
	while (list_head) {
		if (list_head->IsEmpty()) {
			termination_called = true;
			completion_success = list_head->completion_success;
		}
		recieved_byte_count += list_head->data.size();
		list_head = list_head->next;
	}
}

};
