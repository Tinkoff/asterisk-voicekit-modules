FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y git g++ libtool autoconf automake m4 make
RUN apt-get install -y asterisk-dev libopus-dev
RUN apt-get install -y curl xxd jq libssl-dev pkg-config

RUN mkdir -p /usr/src/asterisk-voicekit-modules

COPY .git /usr/src/asterisk-voicekit-modules/.git/

RUN cd /usr/src/asterisk-voicekit-modules && git checkout .
# NOTE: Alternatively use following (instead of previous line) to apply local modifications:
# COPY asterisk_modules /usr/src/asterisk-voicekit-modules/asterisk_modules/

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

COPY container-data/extract_text /usr/share/asterisk/agi-bin/extract_text
RUN chmod 755 /usr/share/asterisk/agi-bin/extract_text

RUN rm -f /etc/asterisk/extensions.ael /etc/asterisk/sip.conf
RUN ln -s /mnt/extensions.ael /etc/asterisk/extensions.ael
RUN ln -s /mnt/grpcstt.conf /etc/asterisk/grpcstt.conf
RUN ln -s /mnt/grpctts.conf /etc/asterisk/grpctts.conf
RUN ln -s /mnt/sip.conf /etc/asterisk/sip.conf

CMD asterisk -c
