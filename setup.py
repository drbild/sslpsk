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

from setuptools import setup, Extension

import sys

if sys.platform == 'win32':
    LIB_NAMES = ['ssleay32MD', 'libeay32MD']
    LIB_FILES = ['openssl/bin/%s.dll'%lib for lib in LIB_NAMES]
else:
    LIB_NAMES = ['ssl']
    LIB_FILES = []

_sslpsk = Extension('sslpsk._sslpsk',
                    sources = ['sslpsk/_sslpsk.c'],
                    libraries = LIB_NAMES
)
            
setup(
    name = 'sslpsk',
    version = '1.0.0',
    description = 'Adds TLS-PSK support to the Python ssl package',
    author = 'David R. Bild',
    author_email = 'david@davidbild.org',
    license="Apache 2.0",
    url = 'https://github.com/drbild/sslpsk',
    download_url = 'https://github.com/drbild/sslpsk/archive/1.0.0.tar.gz',
    keywords = ['ssl', 'tls', 'psk', 'tls-psk', 'preshared key'],
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Operating System :: MacOS',
        'Operating System :: Microsoft'
    ],
    packages = ['sslpsk', 'sslpsk.test'],
    ext_modules = [_sslpsk],
    data_files = [('sslpsk', LIB_FILES)],
    test_suite = 'sslpsk.test',
    zip_safe = False
)
