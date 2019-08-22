#!/bin/bash

command -v nc &> /dev/null || (echo "Error: no 'nc' tool present; please install NetCat"; exit 1)

if [ "$#" -ne 5 ]; then
    if [ "$#" -ne 0 ]; then
	echo "Invalid number of arguments"
    fi

    echo "Usage: $0 HOST PORT USERNAME SECRET CHANNEL"

    exit 1
fi

HOST="$1"
PORT="$2"
USERNAME="$3"
SECRET="$4"
CHANNEL="$5"

X=""

X="${X}Action: Login\r\n"
X="${X}Username: ${USERNAME}\r\n"
X="${X}Secret: ${SECRET}\r\n"
X="${X}\r\n"

X="${X}Action: Events\r\n"
X="${X}Eventmask: off\r\n"
X="${X}\r\n"

X="${X}Action: Events\r\n"
X="${X}Eventmask: call,user\r\n"
X="${X}\r\n"

X="${X}Action: UserEvent\r\n"
X="${X}ActionID: 321\r\n"
X="${X}Channel: ${CHANNEL}\r\n"
X="${X}UserEvent: CMD_PLAY\r\n"
X="${X}EventBody: greeting\r\n"
X="${X}\r\n"

X="${X}Action: UserEvent\r\n"
X="${X}ActionID: 321\r\n"
X="${X}Channel: ${CHANNEL}\r\n"
X="${X}UserEvent: CMD_PLAY_NEXT\r\n"
X="${X}EventBody: main_speech\r\n"
X="${X}\r\n"

echo -ne "$X" | nc "$HOST" "$PORT"
