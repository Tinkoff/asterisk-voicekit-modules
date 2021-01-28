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
Also you may build docker container with STT and TTS demo using your API credentials.

Building demo container
=======================

1. Put your API credentials into `api_key` and `secret_key` variables at `container-data/grpcstt.conf` and `container-data/grpcstt.conf`

2. Build container:

```
docker build -t asterisk-voicekit-demo .
```

3. Run container in foreground mode:

```
docker run -it --network=host asterisk-voicekit-demo
```

**NOTE**: System-wide Asterisk must be stopped if running!

4. Install Ekiga:

```
sudo apt-get install ekiga
```

4. Configure Ekiga:

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

4. Call contact `Voicekit parrot`

LICENSING
---------

Since Asterisk is distributed under the GPLv2 license, and the VoiceKit modules are loaded by and
directly interface with Asterisk, the GPLv2 license applies to the VoiceKit modules too.

See COPYING files for corresponding modules for details.
