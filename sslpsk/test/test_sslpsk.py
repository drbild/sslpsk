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

import os
import socket
import ssl
import sslpsk
import sys
import threading
import traceback
import unittest

HOST = "localhost"
PORT = 6000
TEST_DATA = b"abcdefghi"
CIPHERS = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"


class SSLPSKTest(unittest.TestCase):
    # ---------- setup/tear down functions
    def setUp(self):
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

    def startServer(self, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=CIPHERS, myid=None):
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
                self.server_thread_exception = exc
                self.server_thread_traceback = "".join(
                    traceback.format_tb(exc.__traceback__)
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
                self.server_thread_exception = exc
                self.server_thread_traceback = "".join(
                    traceback.format_tb(exc.__traceback__)
                )
                return

            # accept data from client
            data = self.server_psk_sock.recv(10)
            self.server_psk_sock.sendall(data.upper())

        self.server_thread = threading.Thread(target=accept)
        self.server_thread.start()

    def connectAndReceiveData(
        self, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=CIPHERS, myid=None
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

    def testClientCiphersPskAes256(self):
        ciphers = "PSK-AES256-CBC-SHA"
        ssl_version = ssl.PROTOCOL_TLSv1_2
        self.startServer(ssl_version, ciphers)
        self.connectAndReceiveData(ssl_version, ciphers)

    def testCiphersAll(self):
        ciphers = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
        ssl_version = ssl.PROTOCOL_TLSv1_2
        self.startServer(ssl_version, ciphers)
        self.connectAndReceiveData(ssl_version, ciphers)

    @unittest.expectedFailure
    def testProtocolTls(self):
        ssl_version = ssl.PROTOCOL_TLS
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    def testProtocolTlsV1(self):
        ssl_version = ssl.PROTOCOL_TLSv1
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    def testProtocolTlsV1_1(self):
        ssl_version = ssl.PROTOCOL_TLSv1_1
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

    def testProtocolTlsV1_2(self):
        ssl_version = ssl.PROTOCOL_TLSv1_2
        self.startServer(ssl_version=ssl_version)
        self.connectAndReceiveData(ssl_version=ssl_version)

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



def main():
    unittest.main(warnings="ignore")


if __name__ == "__main__":
    main()
