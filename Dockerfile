FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y git g++ libtool autoconf automake m4 make
RUN apt-get install -y asterisk-dev libopus-dev
RUN apt-get install -y curl xxd jq libssl-dev pkg-config

RUN mkdir -p /usr/src/asterisk-voicekit-modules
COPY .git /usr/src/asterisk-voicekit-modules/.git/
COPY asterisk_modules /usr/src/asterisk-voicekit-modules/asterisk_modules/
RUN cd /usr/src/asterisk-voicekit-modules/asterisk_modules && ./bootstrap
RUN cd /usr/src/asterisk-voicekit-modules/asterisk_modules/app_grpcsttbackground && \
    ./configure --prefix=/usr --localstatedir=/var --with-asterisk-xmldoc-dir=/usr/share/asterisk/documentation && \
    make && \
    make install
RUN cd /usr/src/asterisk-voicekit-modules/asterisk_modules/app_playbackground && \
    ./configure --prefix=/usr --localstatedir=/var --with-asterisk-xmldoc-dir=/usr/share/asterisk/documentation && \
    make && \
    make install
RUN cd /usr/src/asterisk-voicekit-modules/asterisk_modules/app_waitevent && \
    ./configure --prefix=/usr --localstatedir=/var --with-asterisk-xmldoc-dir=/usr/share/asterisk/documentation && \
    make && \
    make install
RUN cd /usr/src/asterisk-voicekit-modules/asterisk_modules/func_gettimensec && \
    ./configure --prefix=/usr --localstatedir=/var --with-asterisk-xmldoc-dir=/usr/share/asterisk/documentation && \
    make && \
    make install

COPY container-data/extensions.ael /etc/asterisk
COPY container-data/grpcstt.conf /etc/asterisk
COPY container-data/grpctts.conf /etc/asterisk
COPY container-data/sip.conf /etc/asterisk
COPY container-data/extract_text /usr/share/asterisk/agi-bin/extract_text
RUN chmod 755 /usr/share/asterisk/agi-bin/extract_text

CMD asterisk -c
