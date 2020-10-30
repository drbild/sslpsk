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

import binascii
import os
import socket
import ssl
import sslpsk
import subprocess
import sys
import threading
from time import sleep
import traceback
import unittest
import warnings

HOST = "localhost"
PORT = 6000
CIPHERS = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
TEST_DATA = b"abcdefghi"
TIMEOUT = 3

TLS_PROTOCOL = None
if hasattr(ssl, "PROTOCOL_TLS"):
    TLS_PROTOCOL = ssl.PROTOCOL_TLS
else:
    TLS_PROTOCOL = ssl.PROTOCOL_SSLv23
if os.environ.get("TRAVIS_OS_NAME") == "osx":
    # the travis Mac osx environment is known to fail
    # with protocol ssl.PROTOCOL_TLS.
    # Therefore we choose ssl.PROTOCOL_TLSv1_2
    TLS_PROTOCOL = ssl.PROTOCOL_TLSv1_2

def cmd_exists(cmd):
    return any(
        os.access(os.path.join(path, cmd), os.X_OK)
        for path in os.environ["PATH"].split(os.pathsep)
    )


class SslPskBase(unittest.TestCase):
    # ---------- setup/tear down functions
    def setUp(self):
        warnings.filterwarnings("ignore")
        self.key = b"c033f52671c61c8128f7f8a40be88038bcf2b07a6eb3095c36e3759f0cf40837"
        self.client_psk = self.key
        self.server_psk = self.key
        self.addr = (HOST, PORT)
        self.client_socket = socket.socket()
        self.server_socket = None
        self.accept_socket = socket.socket()
        self.client_psk_sock = None
        self.server_psk_sock = None
        self.server_cipher = None
        self.server_ssl_version = None
        self.server_thread = None
        self.server_thread_exception = None
        self.server_thread_traceback = None
        self.proc = None

    def tearDown(self):
        if self.server_thread_exception is not None:
            print("Traceback from server thread ({}):\n".format(self.id()))
            print(self.server_thread_traceback)
            print(self.server_thread_exception)
        for sock in [
            self.client_psk_sock or self.client_socket,
            self.server_psk_sock or self.server_socket,
            self.accept_socket,
        ]:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                except AttributeError:
                    if sock is None:
                        pass
                    else:
                        raise
                finally:
                    sock.close()

        self.client_socket = None
        self.server_socket = None
        self.accept_socket = None
        self.client_psk_sock = None
        self.server_psk_sock = None
        if self.server_thread is not None:
            self.server_thread.join()
            self.server_thread = None
        if self.proc is not None:
            self.proc.stdin.close()
            self.proc.stdout.close()
            self.proc.stderr.close()
            self.proc.terminate()
            self.proc = None

    def startServer(self, ssl_version=TLS_PROTOCOL, ciphers=CIPHERS, myid=None):
        self.accept_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.accept_socket.bind(self.addr)
        self.accept_socket.listen(1)
        self.server_ciphers = ciphers
        self.server_ssl_version = ssl_version
        self.server_id = myid

        def accept():
            try:
                self.server_socket, _ = self.accept_socket.accept()
            except Exception as exc:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.server_thread_exception = exc
                self.server_thread_traceback = "".join(
                    traceback.format_tb(exc_traceback)
                )
                return

            try:
                # wrap socket with TLS-PSK
                self.server_psk_sock = sslpsk.wrap_socket(
                    self.server_socket,
                    psk=self.server_psk,
                    ciphers=self.server_ciphers,
                    ssl_version=self.server_ssl_version,
                    server_side=True,
                    hint=self.server_id,
                )
            except Exception as exc:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.server_thread_exception = exc
                self.server_thread_traceback = "".join(
                    traceback.format_tb(exc_traceback)
                )
                return

            # accept data from client
            data = self.server_psk_sock.recv(10)
            self.server_psk_sock.sendall(data.upper())

            # close
            try:
                self.server_psk_sock.shutdown(socket.SHUT_RDWR)
                self.server_psk_sock.close()
            except AttributeError:
                pass
            finally:
                self.server_psk_sock = None

        self.server_thread = threading.Thread(target=accept)
        self.server_thread.start()

    def connectAndReceiveData(
        self, ssl_version=TLS_PROTOCOL, ciphers=CIPHERS, myid=None
    ):
        # initialize
        self.client_socket.connect(self.addr)

        # wrap socket with TLS-PSK
        self.client_psk_sock = sslpsk.wrap_socket(
            self.client_socket,
            psk=self.client_psk,
            ciphers=ciphers,
            ssl_version=ssl_version,
            server_side=False,
            hint=myid,
        )

        self.client_psk_sock.sendall(TEST_DATA)
        data = self.client_psk_sock.recv(10)
        self.assertTrue(data == TEST_DATA.upper(), "Test Failed")


class SslPskTest(SslPskBase):
    def testClient(self):
        self.startServer()
        self.connectAndReceiveData()

    def testCiphersPskAes256(self):
        ciphers = "PSK-AES256-CBC-SHA"
        self.startServer(ciphers=ciphers)
        self.connectAndReceiveData(ciphers=ciphers)

    def testCiphersAll(self):
        ciphers = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
        self.startServer(ciphers=ciphers)
        self.connectAndReceiveData(ciphers=ciphers)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_SSLv23"), "ssl module does not provide required protocol"
    )
    @unittest.skipIf(
        os.environ.get("TRAVIS_OS_NAME") == "osx", "Mac OS is known to fail"
    )
    def testProtocolSslV23(self):
        ssl_version = ssl.PROTOCOL_SSLv23
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)


    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLS"), "ssl module does not provide required protocol"
    )
    @unittest.skipIf(
        os.environ.get("TRAVIS_OS_NAME") == "osx", "Mac OS is known to fail"
    )
    def testProtocolTls(self):
        ssl_version = ssl.PROTOCOL_TLS
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1(self):
        ssl_version = ssl.PROTOCOL_TLSv1
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_1(self):
        ssl_version = ssl.PROTOCOL_TLSv1_1
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_2"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_2(self):
        ssl_version = ssl.PROTOCOL_TLSv1_2
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLS"), "ssl module does not provide required protocol"
    )
    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_2"), "ssl module does not provide required protocol"
    )
    def testProtocolClientTlsV1_2ServerTls(self):
        self.startServer(ssl_version=ssl.PROTOCOL_TLS)
        self.connectAndReceiveData(ssl_version=ssl.PROTOCOL_TLSv1_2)

    def testIdentity(self):
        identity = b"id1"
        psks = {b"id1": b"abcdef", b"id2": b"123456"}
        self.server_psk = lambda identity: psks.get(identity)
        self.client_psk = (b"abcdef", b"id1")

        self.startServer(myid=identity)
        self.connectAndReceiveData(myid=identity)

    def testClientIdentity(self):
        psks = {b"client1": b"abcdef", b"client2": b"123456"}
        self.server_psk = lambda identity: psks.get(identity)
        self.client_psk = (b"abcdef", b"client1")

        self.startServer(myid=b"server1")
        self.connectAndReceiveData(myid=b"client1")

    def testClientAndServerIdentities(self):
        psks_on_server = {b"client1": b"abcdef", b"client2": b"123456"}
        self.server_psk = lambda identity: psks_on_server.get(identity)

        id_on_server = {b"server1": b"client1", b"server2": b"client2"}

        psks_on_client = {b"server1": b"abcdef", b"server2": b"123456"}

        self.client_psk = lambda hint: (
            psks_on_client.get(hint),
            id_on_server.get(hint),
        )

        self.startServer(myid=b"server1")
        self.connectAndReceiveData()

    def testBareosIdentity(self):
        def getBareosIdentity(name):
            identity_prefix = b"R_CONSOLE"
            record_separator = bytearray.fromhex("1E")

            result = identity_prefix + record_separator + name

            return bytes(result)

        clientid = getBareosIdentity(b"client1")

        psks = {b"client1": b"abcdef", b"client2": b"123456", clientid: b"secret"}
        self.server_psk = lambda identity: psks.get(identity)
        self.client_psk = (b"secret", clientid)

        self.startServer()
        self.connectAndReceiveData()


@unittest.skipUnless(cmd_exists("openssl"), "openssl program not available")
@unittest.skipIf(sys.version_info < (3, 3), "Python >= 3.3 required")
@unittest.skipIf(os.environ.get("TRAVIS_OS_NAME") == "osx", "Mac OS is not supported")
class SslPskServerTest(SslPskBase):
    def connectOpenSslClientWithSslPskServer(
        self, ssl_version=ssl.PROTOCOL_TLSv1, ciphers=CIPHERS, myid=None
    ):
        clientid = b"opensslclient"
        psk = b"secret"
        psks = {b"client1": b"abcdef", b"client2": b"123456", clientid: psk}
        self.server_psk = lambda identity: psks.get(identity)
        self.startServer(ssl_version, ciphers, myid)

        command = [
            "openssl",
            "s_client",
            "-quiet",
            "-connect",
            "{}:{}".format(HOST, PORT),
            "-psk_identity",
            clientid,
            "-psk",
            binascii.hexlify(psk),
        ]
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # send data from openssl server to python client
        out, err = self.proc.communicate(input=TEST_DATA, timeout=TIMEOUT)

        self.assertEqual(
            self.proc.returncode,
            0,
            "Server command {} exited with error {}.".format(
                str(command), self.proc.returncode
            ),
        )
        self.assertEqual(out, TEST_DATA.upper())

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLS"), "ssl module does not provide required protocol"
    )
    def testProtocolTls(self):
        self.connectOpenSslClientWithSslPskServer(ssl_version=ssl.PROTOCOL_TLS)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1(self):
        self.connectOpenSslClientWithSslPskServer(ssl_version=ssl.PROTOCOL_TLSv1)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_1(self):
        self.connectOpenSslClientWithSslPskServer(ssl_version=ssl.PROTOCOL_TLSv1_1)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_2"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_2(self):
        self.connectOpenSslClientWithSslPskServer(ssl_version=ssl.PROTOCOL_TLSv1_2)


# timeout parameter since Python 3.3
@unittest.skipUnless(cmd_exists("openssl"), "openssl program not available")
@unittest.skipUnless(sys.version_info >= (3, 3), "Python >= 3.3 required")
class SslPskClientTest(SslPskBase):
    def connectSshPskClientWithOpenSslServer(
        self, ssl_version=ssl.PROTOCOL_TLSv1, ciphers=CIPHERS, myid=None
    ):
        # start the openssl server,
        # connect sslpsk client to server,
        # client: sents data to the server,
        # server: sents data to the client and reads incoming data.
        clientid = b"pythonclient"
        psk = b"secret"

        self.proc = subprocess.Popen(
            [
                "openssl",
                "s_server",
                "-port",
                str(PORT),
                "-nocert",
                "-cipher",
                CIPHERS,
                "-psk_hint",
                b"opensslserver",
                "-psk_identity",
                clientid,
                "-psk",
                binascii.hexlify(psk),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        out = ""
        err = ""
        # send data from openssl server to python client
        try:
            out, err = self.proc.communicate(input=TEST_DATA.upper(), timeout=1)
        except subprocess.TimeoutExpired:
            pass

        if self.proc.poll() is not None:
            raise unittest.SkipTest(
                "openssl is not working: {} {}".format(
                    out.decode("utf-8")[:100], err.decode("utf-8")[:100]
                )
            )

        # print("out: {}".format(out))
        # print("err: {}".format(err))

        self.client_socket.connect(self.addr)
        # wrap socket with TLS-PSK
        self.client_psk_sock = sslpsk.wrap_socket(
            self.client_socket,
            psk=(psk, clientid),
            ssl_version=ssl_version,
            ciphers=ciphers,
            server_side=False,
            hint=myid,
        )

        # Send data from client to server.
        self.client_psk_sock.sendall(TEST_DATA)

        # retreive data on the python client
        data = self.client_psk_sock.recv(10)
        self.assertEqual(data, TEST_DATA.upper())

        # self.proc.wait(timeout=TIMEOUT)
        # send data from openssl server to python client
        out, err = self.proc.communicate(timeout=TIMEOUT)

        self.assertEqual(self.proc.returncode, 0)
        # Data from client to server is not always retrieved,
        # as the server exits very shortly after sending his data.
        # Therefore we done check for this.
        # self.assertIn(TEST_DATA, out)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLS"), "ssl module does not provide required protocol"
    )
    def testProtocolTls(self):
        self.connectSshPskClientWithOpenSslServer(ssl_version=ssl.PROTOCOL_TLS)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1(self):
        self.connectSshPskClientWithOpenSslServer(ssl_version=ssl.PROTOCOL_TLSv1)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_1"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_1(self):
        self.connectSshPskClientWithOpenSslServer(ssl_version=ssl.PROTOCOL_TLSv1_1)

    @unittest.skipUnless(
        hasattr(ssl, "PROTOCOL_TLSv1_2"), "ssl module does not provide required protocol"
    )
    def testProtocolTlsV1_2(self):
        self.connectSshPskClientWithOpenSslServer(ssl_version=ssl.PROTOCOL_TLSv1_2)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
