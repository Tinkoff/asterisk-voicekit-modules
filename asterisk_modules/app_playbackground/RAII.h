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

#ifndef RAII_H
#define RAII_H

#include <utility>
#include <exception>


template<typename Op>
class RAII
{
public:
	RAII(const RAII &) = delete;
	RAII &operator=(const RAII &) = delete;

	RAII(RAII &&) noexcept = default;

	explicit RAII(Op &&op)
		: op(std::forward<Op>(op))
	{
	}
	~RAII()
	{
		op();
	}

private:
	Op op;
};

template<typename Op>
RAII<Op> BuildSafeRAII(Op &&op)
{
	try {
		return RAII<Op>(std::forward<Op>(op));
	} catch(...) {
		op();
		throw std::current_exception;
	}
}

#endif
