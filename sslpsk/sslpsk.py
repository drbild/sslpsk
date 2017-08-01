# Copyright 2017 David R. Bild
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import

import ssl
import sys
import weakref

from sslpsk import _sslpsk

_callbacks = {}

class FinalizerRef(weakref.ref):
    """subclass weakref.ref so that attributes can be added"""
    pass

def _register_callback(sock, ssl_id, callback):
    _callbacks[ssl_id] = callback
    callback.unregister = FinalizerRef(sock, _unregister_callback)
    callback.unregister.ssl_id = ssl_id

def _unregister_callback(ref):
    del _callbacks[ref.ssl_id]

def _python_psk_client_callback(ssl_id, hint):
    """Called by _sslpsk.c to return the (psk, identity) tuple for the socket with
    the specified ssl socket.

    """
    if ssl_id not in _callbacks:
        return ("", "")
    else:
        res = _callbacks[ssl_id](hint)
        return res if isinstance(res, tuple) else (res, "")

def _sslobj(sock):
    """Returns the underlying PySLLSocket object with which the C extension
    functions interface.

    """
    pass
    if sys.version_info >= (3, 5):
        return sock._sslobj._sslobj
    else:
        return sock._sslobj

def _python_psk_server_callback(ssl_id, identity):
    """Called by _sslpsk.c to return the psk for the socket with the specified
    ssl socket.

    """
    if ssl_id not in _callbacks:
        return ""
    else:
        return _callbacks[ssl_id](identity)

_sslpsk.sslpsk_set_python_psk_client_callback(_python_psk_client_callback)
_sslpsk.sslpsk_set_python_psk_server_callback(_python_psk_server_callback)
    
def _ssl_set_psk_client_callback(sock, psk_cb):
    ssl_id = _sslpsk.sslpsk_set_psk_client_callback(_sslobj(sock))
    _register_callback(sock, ssl_id, psk_cb)

def _ssl_set_psk_server_callback(sock, psk_cb, hint):
    ssl_id = _sslpsk.sslpsk_set_accept_state(_sslobj(sock))
    _      = _sslpsk.sslpsk_set_psk_server_callback(_sslobj(sock))
    _      = _sslpsk.sslpsk_use_psk_identity_hint(_sslobj(sock), hint if hint else "")
    _register_callback(sock, ssl_id, psk_cb)

def wrap_socket(*args, **kwargs):
    """
    """
    do_handshake_on_connect = kwargs.get('do_handshake_on_connect', True)
    kwargs['do_handshake_on_connect'] = False
    
    psk = kwargs.setdefault('psk', None)
    del kwargs['psk']

    hint = kwargs.setdefault('hint', None)
    del kwargs['hint']

    server_side = kwargs.setdefault('server_side', False)
    if psk:
        del kwargs['server_side'] # bypass need for cert
    
    sock = ssl.wrap_socket(*args, **kwargs)

    if psk:
        if server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sock, cb, hint)
        else:
            cb = psk if callable(psk) else lambda _hint: psk if isinstance(psk, tuple) else (psk, "")
            _ssl_set_psk_client_callback(sock, cb)

    if do_handshake_on_connect:
        sock.do_handshake()

    return sock
