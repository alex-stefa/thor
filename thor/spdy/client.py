#!/usr/bin/env python

"""
Thor SPDY Client
"""

__author__ = "Mark Nottingham <mnot@mnot.net>"
__copyright__ = """\
Copyright (c) 2008-2011 Mark Nottingham

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

from collections import defaultdict
from urlparse import urlsplit, urlunsplit
from time import time, strftime, gmtime

from thor.events import EventEmitter, on
from thor.tcp import TcpClient
from thor.spdy import error
from thor.spdy.common import \
    SpdyMessageHandler, SpdyStream, \
    invalid_hdrs, header_dict, get_header, \
    InputStates, StreamStates, ExchangeStates, Flags, FrameTypes
    
req_remove_hdrs = (invalid_hdrs + 
    [':method', ':path', ':version', ':host', ':scheme'])

# TODO: proxy support
# TODO: implement connect retry? 
# TODO: spdy over tls (needs npn support)

#-------------------------------------------------------------------------------

class SpdyClient(EventEmitter):
    "An asynchronous SPDY client."
    
    def __init__(self, loop=None):
        EventEmitter.__init__(self)
        self.connect_timeout = None
        self.read_timeout = None
        self._sessions = dict()
        self._loop = loop or thor.loop._loop
        self._loop.on('stop', self.close)
        self.spdy_session_class = SpdyClientSession
        self.tcp_client_class = TcpClient

        # TODO:
        self.proxy = None
        self.use_tls = False
        self.idle_timeout = None # in sec, 0 closes immediately, None to disable

    def session(self, origin):
        "Find an idle connection for (host, port), or create a new one."
        host, port = origin # FIXME: add scheme?
        try:
            session = self._sessions[origin]
        except KeyError:
            session = self.spdy_session_class(self, origin)
            tcp_client = self.tcp_client_class(self._loop)
            tcp_client.on('connect', session._handle_connect)
            tcp_client.on('connect_error', session._handle_connect_error)
            tcp_client.connect(host, port, self.connect_timeout)
            self.sessions[origin] = session
        return session
        
    def remove_session(self, session):
        "Closes and removes session from dictionary."
        try:
            if self._sessions[session.origin] == session:
                session._close()
                del self._sessions[session.origin]
        except:
            pass
            
    def close(self):
        "Close all SPDY sessions."
        for session in self._sessions.values():
            try:
                session._close()
            except:
                pass
        self._sessions.clear()
        # TODO: probably need to close in-progress conns too.
    
    def exchange(self):
        return SpdyClientExchange(self)
 
        
#-------------------------------------------------------------------------------

"""
A SPDY request-response exchange with support for server push streams

Event handlers:
    error(err)
    response_start(
    response_body(
    response_done(

"""
class SpdyClientExchange(EventEmitter):

    def __init__(self, client):
        EventEmitter.__init__(self)
        self.client = client
        self.session = None
        self.stream = None
        self.pushed_streams = list()
        self.state = ExchangeStates.REQ_WAITING
        self._read_timeout_ev = None
        
    ### Header helpers
    
    @property
    def req_method(self):
        return self.stream.send_hdrs[':method'][-1]
    @property
    def req_path(self):
        return self.stream.send_hdrs[':path'][-1]
    @property
    def req_host(self):
        return self.stream.send_hdrs[':host'][-1]
    @property
    def req_version(self):
        return self.stream.send_hdrs[':version'][-1]
    @property
    def req_scheme(self):
        return self.stream.send_hdrs[':scheme'][-1]
    @property
    def req_uri(self):
        return urlunsplit((
            self.req_scheme, self.req_host, self.req_path, '', ''))
    @property
    def res_version(self):
        return self.stream.recv_hdrs[':version'][-1]
    @property
    def res_status(self):
        status = self.stream.recv_hdrs[':status'][-1]
        try:
            res_code, res_phrase = status.split(None, 1)
        except ValueError:
            res_code = status.rstrip()
            res_phrase = ''
        return (res_code, res_phrase)
    # TODO: ensure there is at most one header value for the following:

    ### Public methods
    
    def request_start(self, method, uri, req_hdrs, done=False):
        """
        Start a request to uri using method, where
        req_hdrs is a list of (field_name, field_value) for
        the request headers.
        
        If @done is True, the request is sent immediately with an empty body
        """
        # TODO: find out where to connect to the hard way
        (scheme, authority, path, query, fragment) = urlsplit(uri)
        if scheme.lower() != 'http':
            self.emit('error', error.UrlError('Only HTTP URLs are supported.'))
            return
        if '@' in authority:
            userinfo, authority = authority.split('@', 1)
        if ':' in authority:
            host, port = authority.rsplit(':', 1)
            try:
                port = int(port)
            except ValueError:
                self.emit('error', error.UrlError('Non-integer port in URL.'))
                return
        else:
            host, port = authority, 80
        self.session = self.client._get_session((host, port))
        path = '/' + urlunsplit(('', '', path, query, fragment))
        self.session._req_start(self, method, path, authority, scheme, 
            req_hdrs, done)
        
    def request_body(self, chunk):
        """
        Send part of the request body. May be called zero to many times.
        """
        self.session._req_body(self, chunk)
        
    def request_done(self):
        """
        Signal the end of the request, whether or not there was a body. MUST be
        called exactly once for each request. 
        """
        self.session._req_done(self)

#-------------------------------------------------------------------------------

"""
A SPDY connection to a server

Event handlers:
    error(err)
    ping(
    syn(
    ..etc for each frame type
"""        
class SpdyClientSession(SpdyMessageHandler, EventEmitter):

    def __init__(self, client, origin):
        SpdyMessageHandler.__init__(self)
        EventEmitter.__init__(self)
        self.client = client
        self.tcp_conn = None
        self.origin = origin # (host, port)
        self.streams = dict()
        self.exchanges = dict()
        self.highest_stream_id = -1
        self.highest_ping_id = -1
        self._output_buffer = list()
        self._read_timeout_ev = None

    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.tcp_conn:
            status.append(
              self.tcp_conn.tcp_connected and 'connected' or 'disconnected')
        return "<%s at %#x>" % (", ".join(status), id(self))
    
    def _close(self):
        if self.tcp_conn:
            self.tcp_conn.close()
            self.tcp_conn = None
        
    def pause_input(self, paused):
        "Temporarily stop / restart sending the response body."
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.pause(paused)

    def _next_odd(stream_id):
        return stream_id + 1 + stream_id % 2

    def _next_even(stream_id):
        return stream_id + 2 - stream_id % 2

    def _req_start(self, exchange, method, path, host, scheme, req_hdrs, done):
        if exchange.state != ExchangeStates.REQ_WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
            return
        req_hdrs = [(entry[0].lower, entry[1])
            for entry in req_hdrs if not entry[0].lower() in req_remove_hdrs]
        req_hdrs.append((':method', method))
        req_hdrs.append((':path', path))
        req_hdrs.append((':version', 'HTTP/1.1'))
        req_hdrs.append((':host', host))
        req_hdrs.append((':scheme', scheme))
        self.highest_stream_id = self._next_odd(self.highest_stream_id)
        # TODO: check to make sure it's not too high.. what then?
        req_stream = SpdyStream(
            self.highest_stream_id, header_dict(req_hdrs), None)
        exchange.request = req_stream
        self.streams[req_stream.stream_id] = req_stream
        self.exchanges[req_stream.stream_id] = exchange
        if done:
            req_stream.state = StreamStates.LOCAL_CLOSED
            exchange.state = ExchangeStates.REQ_DONE
            self._output(self._ser_syn_frame(
                CTL_SYN_STREAM, FLAG_FIN, stream_id, req_hdrs))
            self._set_read_timeout(exchange, 'start')
        else:
            exchange.state = ExchangeStates.REQ_STARTED
            self._output(self._ser_syn_frame(
                CTL_SYN_STREAM, FLAG_NONE, stream_id, req_hdrs))
    
    def _req_body(self, exchange, chunk):
        if exchange.state == ExchangeStates.REQ_WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request headers not sent.'))
        elif exchange.state != ExchangeStates.REQ_STARTED:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
        else:
            self._output(self._ser_data_frame(
                exchange.request.stream_id, FLAG_NONE, chunk))
    
    def _req_done(self, exchange):
        if exchange.state == ExchangeStates.REQ_WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request headers not sent.'))
        elif exchange.state != ExchangeStates.REQ_STARTED:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
        else:
            exchange.state = ExchangeStates.REQ_DONE
            exchange.request.state = StreamStates.LOCAL_CLOSED
            self._set_read_timeout(exchange, 'start')
            self._output(self._ser_data_frame(
                exchange.request.stream_id, FLAG_FIN, ''))
    
    ### Methods called by common.SpdyMessageHandler
        
    def _handle_frame(self, frame):
    #_clear_read_timeout(self)
    
    def handle_syn(self):
        # validate stream_id, associated_stream_id
        # validate hdrs
        # update highest_stream_id
        # send SYN_REPLY
        # call _input_start
        # raise errors to exchange instance
        
    #handle_reply(session, stream_id, hdrs):
        # validate stream_id, response hdrs
        # call _input_start
        # raise errors to exchange instance
        
    #handle_data(session, stream_id, flags, chunk)
        # validate stream_id
        # close stream if FLAG_FIN
        # call _input_body
        # raise errors to exchange instance

    #handle_ping(session):
        # validate ping ID
        # send ping reply
        # update last_ping_id
        
    #_set_read_timeout(sel)
        pass
     
    def _handle_error(self, err):
        # on InvalidStreamIDError send GOAWAY + close session
        pass
   

    def _validate_stream_id(stream_id, existing=True):
        if existing:
            if stream_id not in self.streams:
                return error.StreamIdError('#%d is unknown' % stream_id))
        else:
            if stream_id < self.highest_stream_id:
                return error.StreamIdError('#%d already seen' % stream_id))
            if stream_id % 2 == 1:
                return error.StreamIdError('#%d expected even' % stream_id))
        return None

    def _validate_headers(hdr_tuples):
        status = get_header(hdr_tuples, ':status')
        if len(status) == 0:
            return error.HeaderError('missing :status header'))
        if len(status) > 1:
            return error.HeaderError('multiple :status headers received'))
        version = get_header(hdr_tuples, ':version')
        if len(version) == 0:
            return error.HeaderError('missing :version header'))
        if len(version) > 1:
            return error.HeaderError('multiple :version headers received'))
        
    def _input_error(self, err):
        "Indicate a parsing problem with the server response."
        self._clear_read_timeout(self)
        if not err.client_recoverable:
            self.client.remove_session(self)
        self._set_read_timeout(self)
        self.emit('error', err)

    def _input_start(self, stream_id, stream_assoc_id, hdr_tuples, priority):
        """
        Take the top set of headers from the input stream, parse them
        and queue the request to be processed by the application.
        """
        # TODO: validate host for same-origin policy
        if stream_assoc_id:
            # create new server push stream
            exchange = self.exchanges[stream_assoc_id]
            self.exchanges[stream_id] = exchange
            self._clear_read_timeout(exchange)
            reply_stream = SpdyStream(stream_id, None, header_dict(hdr_tuples), 
                stream_assoc_id, priority, True)
            self.streams[stream_id] = reply_stream
            exchange.pushed_streams.append(reply_stream)
            self._set_read_timeout(exchange, 'body')
            exchange.emit('response_start', reply_stream) 
        else:
            # response for stream request
            exchange = self.exchanges[stream_id]
            self._clear_read_timeout(exchange)
            exchange.state = ExchangeStates.RES_STARTED
            exchange.stream.recv_hdrs = header_dict(hdr_tuples)
            self._set_read_timeout(exchange, 'body')
            exchange.emit('response_start', exchange.stream) 
        
    def _input_body(self, stream_id, chunk):
        "Process a response body chunk from the wire."
        exchange = self.exchanges[stream_id]
        self._clear_read_timeout(exchange)
        self._set_read_timeout(exchange, 'body')
        stream = self.streams[stream_id]
        exchange.emit('response_body', stream, chunk)
        
    def _input_end(self, stream_id):
        "Indicate that the response body is complete."
        exchange = self.exchanges[stream_id]
        self._clear_read_timeout(exchange)
        stream = self._streams[stream_id]
        stream.state = StreamStates.REMOTE_CLOSED
        if exchange.stream == stream:
            exchange.state = ExchangeStates.RES_DONE
        if exchange.state != ExchangeStates.REQ_DONE
            self._set_read_timeout(exchange, 'body')
        exchange.emit('response_done', stream)
        # TODO: delete stream if output side is half-closed.

    def _output(self, chunk):
        self._output_buffer.append(chunk)
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write("".join(self._output_buffer))
            self._output_buffer = []

    ### Methods called by tcp
    
    def _handle_connect(self, tcp_conn):
        "The connection has succeeded."
        self.tcp_conn = tcp_conn
        self._set_read_timeout(self, 'connect')
        tcp_conn.on('data', self._handle_input)
        tcp_conn.on('close', self._handle_closed)
        tcp_conn.on('pause', self._handle_pause)
        # FIXME: should this be done AFTER _req_start?
        self.output('') # kick the output buffer
        self.tcp_conn.pause(False)

    def _handle_connect_error(self, err_type, err_id, err_str):
        "The connection has failed."
        self._input_error(error.ConnectError(err_str))
        
    def _handle_closed(self):
        "The server closed the connection."
        self._clear_read_timeout(self)
        if self._input_buffer:
            self.handle_input('')
        if self._input_state == InputStates.READING_FRAME_DATA: # FIXME: make it tighter
            self._input_error(error.ConnectError(
                'Server dropped connection before the response was complete.'))
        else:
            self.emit('close')
        # TODO: notify exchange instances
        
    def _handle_pause(self, paused):
        "The client needs the application to pause/unpause the request body."
        self.emit('pause', paused)
        # TODO: notify exchange instances
        
    ### Timeouts

    def _handle_read_timeout(self, entity, err):
        if entity == self:
            self._input_error(err)
        else: # a SpdyClientExchange
            self._clear_read_timeout(entity)
            entity.emit('error', err)
        
    def _set_read_timeout(self, entity, kind):
        "Set the read timeout."
        # FIXME: check overwrite existing _read_timeout_ev
        if self.client.read_timeout:
            entity._read_timeout_ev = self.client._loop.schedule(
                self.client.read_timeout, self._handle_read_timeout, 
                entity, error.ReadTimeoutError(kind))

    def _clear_read_timeout(self, entity):
        "Clear the read timeout."
        if entity._read_timeout_ev:
            entity._read_timeout_ev.delete()    
        
#-------------------------------------------------------------------------------
        
def test_client(request_uri):
    "A simple demonstration of a client."
    def printer(version, status, phrase, headers, res_pause):
        "Print the response headers."
        print "HTTP/%s" % version, status, phrase
        print "\n".join(["%s:%s" % header for header in headers])
        print
        def body(chunk):
            print chunk
        def done(err):
            if err:
                print "*** ERROR: %s (%s)" % (err['desc'], err['detail'])
            push_tcp.stop()
        return body, done
    c = SpdyClient()
    req_body_write, req_done = c.req_start("GET", request_uri, [], printer, dummy)
    req_done(None)
    push_tcp.run()
            
if __name__ == "__main__":
    import sys
    test_client(sys.argv[1])
