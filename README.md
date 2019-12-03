# sslpsk

[![PyPI version](https://badge.fury.io/py/sslpsk.svg)](https://badge.fury.io/py/sslpsk)
[![Build Status](https://travis-ci.org/drbild/sslpsk.svg?branch=master)](https://travis-ci.org/drbild/sslpsk)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/drbild/sslpsk?branch=master)](https://ci.appveyor.com/project/drbild/sslpsk)

This module adds TLS-PSK support to the Python 2.7 and 3.x `ssl`
package. Simply use

    sslpsk.wrap_socket(sock, psk=b'...', ...)

instead of

    ssl.wrap_socket(sock, ...)

## Installation

```pip install sslpsk```

`pip` builds from source for Linux and Mac OSX, so a C compiler, the Python
development headers, and the openSSL development headers are required.  For
Microsoft Windows, pre-built binaries are available so there are no such
prerequisites.

## Usage

`sslpsk.wrap_socket(...)` is a drop-in replacement for `ssl.wrap_socket(...)` that
supports two additional arguments, `psk` and `hint`.

`psk` sets the preshared key and, optionally, the identity for a client
connection. `hint` sets the identity hint for a server connection and is
optional.

For client connections, `psk` can be one of four things:

1. Just the preshared key.

```python
sslpsk.wrap_socket(sock, psk=b'mypsk')
```

2. A tuple of the preshared key and client identity.

```python
sslpsk.wrap_socket(sock, psk=(b'mypsk', b'myidentity'))
```

3. A function mapping the server identity hint to the preshared key.

```python
PSK_FOR = {b'server1' : b'abcdef',
           b'server2' : b'123456'}

sslpsk.wrap_socket(sock, psk=lambda hint: PSK_FOR[hint])
```

4. A function mapping the server identity hint to a tuple of the preshared key
and client identity.

```python
PSK_FOR = {b'server1' : b'abcdef',
           b'server2' : b'123456'}

ID_FOR  = {b'server1' : b'clientA',
           b'server2' : b'clientB'}

sslpsk.wrap_socket(sock, psk=lambda hint: (PSK_FOR[hint], ID_FOR[hint]))
```

For server connections, `psk` can be one of two things:

1. Just the preshared key.

```python
sslpsk.wrap_socket(sock, server_side=True, psk=b'mypsk')
```

2. A function mapping the client identity to the preshared key.

```python
PSK_FOR = {b'clientA' : b'abcdef',
           b'clientB' : b'123456'}

sslpsk.wrap_socket(sock, server_side=True, psk=lambda identity: PSK_FOR[identity])
```

Additionally for server connections, the optional server identity hint is
specified using the  `hint` argument.

```python
sslpsk.wrap_socket(sock, server_side=True, hint=b'myidentity', psk=b'mypsk')
```

If `hint` is not specified, `None`, or the empty string, the identity hint
will not be sent to the client.

### Example Server

```python
from __future__ import print_function
import socket
import ssl
import sslpsk

PSKS = {'client1' : 'abcdef',
        'client2' : '123456'}

def server(host, port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((host, port))
    tcp_sock.listen(1)

    sock, _ = tcp_sock.accept()
    ssl_sock = sslpsk.wrap_socket(sock,
                                  server_side = True,
                                  ssl_version=ssl.PROTOCOL_TLSv1,
                                  ciphers='ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH',
                                  psk=lambda identity: PSKS[identity],
                                  hint=b'server1')

    msg = ssl_sock.recv(4).decode()
    print('Server received: %s'%(msg))
    msg = "pong"
    ssl_sock.sendall(msg.encode())

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def main():
    host = '127.0.0.1'
    port = 6000
    server(host, port)

if __name__ == '__main__':
    main()
```

### Example Client

```python
from __future__ import print_function
import socket
import ssl
import sslpsk

PSKS = {b'server1' : b'abcdef',
        b'server2' : b'uvwxyz'}

def client(host, port, psk):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))

    ssl_sock = sslpsk.wrap_socket(tcp_socket,
                                  ssl_version=ssl.PROTOCOL_TLSv1,
                                  ciphers='ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH',
                                  psk=lambda hint: (PSKS[hint], b'client1'))

    msg = "ping"
    ssl_sock.sendall(msg.encode())
    msg = ssl_sock.recv(4).decode()
    print('Client received: %s'%(msg))

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def main():
    host = '127.0.0.1'
    port = 6000
    client(host, port, PSKS)

if __name__ == '__main__':
    main()
```

## Changelog

+ 0.1.0 (July 31, 2017)
  + initial release
+ 1.0.0 (August 2, 2017)
  + include tests in pip distribution
  + add support for Windows

## Acknowledgments

The main approach was borrowed from
[webgravel/common-ssl](https://github.com/webgravel/common-ssl).

## Contributing

Please submit bugs, questions, suggestions, or (ideally) contributions as
issues and pull requests on GitHub.

### Maintainers
**David R. Bild**

+ [https://www.davidbild.org](https://www.davidbild.org)
+ [https://github.com/drbild](https://github.com/drbild)

## License
Copyright 2017 David R. Bild

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
