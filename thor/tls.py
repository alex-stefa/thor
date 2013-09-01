#!/usr/bin/env python


"""
push-based asynchronous SSL/TLS-over-TCP

This is a generic library for building event-based / asynchronous
SSL/TLS servers and clients.
"""

__author__ = "Mark Nottingham <mnot@mnot.net>"
__copyright__ = """\
Copyright (c) 2005-2013 Mark Nottingham, Alex Stefanescu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import errno
import os
import socket
import ssl as sys_ssl

from thor.events import on
from thor.loop import EventSource
from thor.tcp import TcpServer, TcpClient, TcpConnection, server_listen


TcpConnection._block_errs.add((sys_ssl.SSLError, sys_ssl.SSL_ERROR_WANT_READ))
TcpConnection._block_errs.add(
                        (sys_ssl.SSLError, sys_ssl.SSL_ERROR_WANT_WRITE)
)
TcpConnection._close_errs.add((sys_ssl.SSLError, sys_ssl.SSL_ERROR_EOF))
TcpConnection._close_errs.add((sys_ssl.SSLError, sys_ssl.SSL_ERROR_SSL))

NPN_HTTP = ['http/1.1', 'http/1.0']
NPN_SPDY = ['spdy/3']


class TlsConfig():
    """
    Holds configuration for a SSLContext instance.
    
    The keyfile and certfile parameters specify optional files which contain a 
    certificate to be used to identify the local side of the connection. 
    The certfile string must be the path to a single file in PEM format 
    containing the certificate as well as any number of CA certificates needed 
    to establish the certificate's authenticity. The keyfile string, if present,
    must point to a file containing the private key in. Otherwise the private 
    key will be taken from certfile as well. 
    
    The password argument may be a function to call to get the password for 
    decrypting the private key. It will only be called if the private key is 
    encrypted and a password is necessary. It will be called with no arguments, 
    and it should return a string, bytes, or bytearray. If the return value is 
    a string it will be encoded as UTF-8 before using it to decrypt the key. 
    Alternatively a string, bytes, or bytearray value may be supplied directly 
    as the password argument. It will be ignored if the private key is not 
    encrypted and no password is needed.

    If the password argument is not specified and a password is required, 
    OpenSSL's built-in password prompting mechanism will be used to 
    interactively prompt the user for a password.
    
    Loads a set of "certification authority" (CA) certificates used to validate 
    other peers' certificates when verify_mode is other than CERT_NONE. 
    At least one of cafile or capath must be specified.

    The cafile string, if present, is the path to a file of concatenated CA 
    certificates in PEM format. The capath string, if present, is the path to 
    a directory containing several CA certificates in PEM format, following an 
    OpenSSL specific layout.
    
    see: http://docs.python.org/3.3/library/ssl.html#ssl-contexts
    """
    def __init__(self, 
        keyfile=None,
        certfile=None,
        password=None,
        cafile=None,
        capath=None,
        npn_prot=None):
        self._keyfile=keyfile,
        self._certfile=certfile,
        self._password=password,
        self._cafile=cafile,
        self._capath=capath,
        self._npn_prot=npn_prot,
        context = sys_ssl.SSLContext(sys_ssl.PROTOCOL_SSLv23)
        if certfile:
            context.load_cert_chain(certfile, keyfile, password)
        if cafile or capath:
            context.set_default_verify_paths()
            context.load_verify_locations(cafile, capath)
        if npn_prot:
            context.set_npn_protocols(npn_prot)
        context.verify_mode = sys_ssl.CERT_NONE
        self._context = context
        
    @property
    def context(self):
        return self._context
        
    @property
    def npn_prot(self):
        return self._npn_prot

        
# TODO: Validate CAs, expose cipher info, peer info
    
class TlsClient(TcpClient):
    """
    An asynchronous SSL/TLS client.

    Emits:
      - connect (tcp_conn): upon connection
      - connect_error (err_type, err): if there's a problem before getting
        a connection. err_type is socket.error or socket.gaierror; err
        is the specific error encountered.

    To connect to a server:

    > c = TlsClient(tls_config)
    > c.on('connect', conn_handler)
    > c.on('connect_error', error_handler)
    > c.connect(host, port)

    conn_handler will be called with the tcp_conn as the argument
    when the connection is made.
    """
    def __init__(self, tls_config, loop=None):
        TcpClient.__init__(self, loop)
        self.tls_config = tls_config
        self.sock = tls_config.context.wrap_socket(
            self.sock,
            server_side=False,
            do_handshake_on_connect=False)
        
    def create_conn(self):
        handshaker = TlsHandshake(self.sock, self.tls_config, self._loop)        
        
        @on(handshaker, 'success')
        def on_success():
            TcpClient.create_conn(self)
        
        @on(handshaker, 'handshake_error')
        def on_handshake_error(err_type, err_id, err_str):
            self.emit('connect_error', err_type, err_id, err_str)
        
        handshaker.handshake()       
            
            
class TlsServer(TcpServer):
    """
    An asynchronous SSL/TLS server.

    Emits:
      - connect (tcp_conn): upon connection
      - connect_error (err_type, err_id, err_str): if there is a problem with
        the accepted socket
        
    To start listening:

    > s = TlsServer(host, port, tls_config)
    > s.on('connect', conn_handler)

    conn_handler is called every time a new client connects.
    """
    def __init__(self, host, port, tls_config, sock=None, loop=None):
        TcpServer.__init__(self, host, port, sock, loop)
        self.tls_config = tls_config
        
    def create_conn(self, sock, host, port):
        sock = self.tls_config.context.wrap_socket(
            sock, 
            server_side=True,
            do_handshake_on_connect=False)
        handshaker = TlsHandshake(sock, self.tls_config, self._loop)
        
        @on(handshaker, 'success')
        def on_success():
            TcpServer.create_conn(self, sock, host, port)
        
        @on(handshaker, 'handshake_error')
        def on_handshake_error(err_type, err_id, err_str):
            self.emit('connect_error', err_type, err_id, err_str)
        
        handshaker.handshake()
             

class TlsHandshake(EventSource):
    """
    Performs the TLS handshake on a TCP connection.
    
    Emits:
      - success: upon handshake completion
      - handshake_error (err_type, err_id, err_str): if there's a problem
        while performing the handshake
    """
    def __init__(self, sock, tls_config, loop=None):
        EventSource.__init__(self, loop)
        self.sock = sock
        self.tls_config = tls_config
        self.on('error', self.handle_error)
        self.register_fd(self.sock.fileno(), 'writable')
        self.event_add('error')       
        self.once('writable', self.handshake)
        
    def handshake(self):
        try:
            self.sock.do_handshake()
            self.once('writable', self.handle_complete)
        except sys_ssl.SSLError as why:
            if why.args[0] == sys_ssl.SSL_ERROR_WANT_READ:
#                self.once('readable', self.handshake)
                self.once('writable', self.handshake) # Oh, Linux...
            elif why.args[0] == sys_ssl.SSL_ERROR_WANT_WRITE:
                self.once('writable', self.handshake)
            else:
                self.handle_error(sys_ssl.SSLError, why)
        except socket.error as why:
            self.handle_error(socket.error, why)

    def handle_complete(self):
        self.unregister_fd()
        if self.tls_config.npn_prot and not self.sock.selected_npn_protocol():
            self.sock.close()
            self.emit('handshake_error', sys_ssl.SSLError, None,
                'NPN not supported by remote side or unknown protocol')
        else:
            print(self.sock.selected_npn_protocol())
            self.emit('success')
            
    def handle_error(self, err_type, why):
        self.unregister_fd()
        if err_type is None:
            err_type = socket.error
            err_id = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            err_str = os.strerror(err_id)
        else:
            err_id = why.args[0]
            err_str = why.args[1]
        self.sock.close()
        self.emit('handshake_error', err_type, err_id, err_str)
                     

def monkey_patch_ssl():
    """
    Oh, god, I feel dirty.
    
    See Python bug 11326.
    """
    if not hasattr(sys_ssl.SSLSocket, '_real_connect'):
        import _ssl
        def _real_connect(self, addr, return_errno):
            if self._sslobj:
                raise ValueError(
                    "attempt to connect already-connected SSLSocket!"
                )
            self._sslobj = _ssl.sslwrap(self._sock, False, self.keyfile,
                self.certfile, self.cert_reqs, self.ssl_version,
                self.ca_certs, self.ciphers)
            try:
                socket.socket.connect(self, addr)
                if self.do_handshake_on_connect:
                    self.do_handshake()
            except socket.error as e:
                if return_errno:
                    return e.errno
                else:
                    self._sslobj = None
                    raise e
            return 0
        def connect(self, addr):
            self._real_connect(addr, False)
        def connect_ex(self, addr):
            return self._real_connect(addr, True)
        sys_ssl.SSLSocket._real_connect = _real_connect
        sys_ssl.SSLSocket.connect = connect
        sys_ssl.SSLSocket.connect_ex = connect_ex
monkey_patch_ssl()


if __name__ == "__main__":
    import sys
    from thor import run
    test_host = sys.argv[1]

    def go(conn):
        conn.on('data', sys.stdout.write)
        conn.write("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % test_host)
        conn.pause(False)
        print('conn cipher: %s' % conn.socket.cipher())

    c = TlsClient()
    c.on('connect', go)
    c.connect(test_host, 443)
    run()