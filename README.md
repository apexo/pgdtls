PGDTLS: Python GNUTLS/DTLS stack
================================

Requirements
------------

- python 2.7, python 3.3, or pypy 2.0
- python-cffi
- gnutls 3.2


dtlstap
-------

dtlstap is a very simple DTLS/TAP tunnel. It can run in client mode, e.g.:

    dtlstap.py -c host:port -u username -p hex_password --up up-client.sh


In client mode, dtlstap tries to automatically connect to a server given with -c. PSK crendentials (username and password) must be passed with -u and -p, password must be hex-encoded. The --up script is invoked as soon as the tap interface is opened. The name of the device node (e.g. /dev/tap0) is passed in the environment variable DEVICE\_NAME. For each host/port that is passed with -c/--connect two parameters will be passed to the up script: IP and port of the host to be connected host. Example:

    #!/bin/sh -e
    while [ -n "$1" ]; do
        route=`ip route get $1 | head -n1`
        ip route add $route || true
        shift
        shift
    done
    /sbin/ifconfig $DEVICE_NAME up 10.10.1.2/24
    ip route del default || true
    ip route add default via 10.10.1.1 dev $DEVICE_NAME src 10.10.1.2


This will set explicit routes for all --connect hosts, so that they be routed via the current default gateway. Then the default route is replaced.

Server mode example invocation:

    dtlstap.py -l port --up up-server.sh -f psk_keys_file


Example for up-server.sh:

    /sbin/ifconfig $DEVICE_NAME up 10.10.1.1/24


Example for psk\_keys\_file (one user:hex\_password per line):

    user:70617373776f7264


Note that every client also listens for incoming request on a random port (if no explicit port is given via -l). However, if no server credentials are provided (via -f/--psk-file) incoming handshakes will fail. Clients/servers supports multiple connections, but currently traffic is only sent to the first.

dtlsclient/dtlsserver
---------------------

Very simple flooding client and echo server for benchmarking purposes.
