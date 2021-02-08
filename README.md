INTRODUCTION
------------

This document provides a brief description of the VoiceKit modules for Asterisk.
Each module may be used individually although there are shared thitd party repositories.

Following presentation may be helpful for Russian speakers as an introduction:
https://www.youtube.com/watch?v=4LRcaSM46t8


INSTALLATION
------------

See INSTALL files for corresponding modules.


QUICKSTART
----------

See 'examples' directory for dial-plan and configuration examples.

You may also build Docker image or use pre-built one with STT and TTS demo using your API credentials.

Building demo Docker image
==========================

1. Put your API credentials into `api_key` and `secret_key` variables at `container-mnt/grpcstt.conf` and `container-mnt/grpcstt.conf`

2. Build image:

```
docker build -t asterisk-voicekit-demo .
```

3. Run container in foreground mode:

```
docker run -it --network=host --mount type=bind,src="$PWD/container-mnt",dst=/mnt asterisk-voicekit-demo
```

**NOTE**: System-wide Asterisk must be stopped if running!

Using pre-built Docker image
============================

1. Put your API credentials into `api_key` and `secret_key` variables at `container-mnt/grpcstt.conf` and `container-mnt/grpcstt.conf`

2. Run container in foreground mode:

```
docker run -it --network=host --mount type=bind,src="$PWD/container-mnt",dst=/mnt tinkoffcreditsystems/asterisk-voicekit-modules:`git describe --tags`
```

**NOTE**: System-wide Asterisk must be stopped if running!

**NOTE**: The modules repository must be at recent release tag for `git describe --tags` to work properly!

For full list of pre-built images see: https://hub.docker.com/r/tinkoffcreditsystems/asterisk-voicekit-modules/tags

Configuring SIP client
======================

1. Install Ekiga:

```
sudo apt-get install ekiga
```

2. Configure Ekiga:

- Set "Edit -> Preferences -> Protocols -> SIP settings -> Outbound proxy" to "localhost"
- Add account at "Edit -> Accounts" with following settings:
  - Name: `demo-user`
  - Registrar: `sip`
  - User: `demo-user`
  - Authentication user: `demo-user`
  - Password: `lBwzDjXAwMs94Sn`
- Add contact at "Chat -> Add contact" with following settings:
  - Name: `Voicekit parrot`
  - Address: `sip:parrot`

3. Call contact `Voicekit parrot`

LICENSING
---------

Since Asterisk is distributed under the GPLv2 license, and the VoiceKit modules are loaded by and
directly interface with Asterisk, the GPLv2 license applies to the VoiceKit modules too.

See COPYING files for corresponding modules for details.
