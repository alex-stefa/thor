#!/usr/bin/env python

"""
Thor SPDY Client
"""

__author__ = "Mark Nottingham <mnot@mnot.net>"
__copyright__ = """\
Copyright (c) 2008-2013 Mark Nottingham, Alex Stefanescu

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

import thor
from thor.events import EventEmitter, on
from thor.tcp import TcpClient
from thor.spdy import error
from thor.spdy.common import \
    SpdyMessageHandler, \
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

class SpdyClientExchange(EventEmitter):
    """
    A SPDY request-response exchange with support for server push streams

    Event handlers that can be added:
        error(err)
        response_start(stream_id, hdr_dict)
        response_body(stream_id, chunk)
        response_headers(stream_id, hdr_dict)
        response_done(stream_id)
    """
    def __init__(self, client):
        EventEmitter.__init__(self)
        self.client = client
        self.session = None
        self.timestamp = time()
        self.stream_id = None
        self.priority = 7 # 0 highest to 7 lowest
        self._stream_assoc_id = None
        self._exchg_state = ExchangeStates.REQ_WAITING
        self._stream_state = StreamStates.OPEN
        self._read_timeout_ev = None
        self._pushed = False # is server pushed?
                
    def __str__(self):
        return ('[#%d A%s P%d%s %s %s %s%s]' % (
            str(self.stream_id) if self.stream_id else '?',
            str(self._stream_assoc_id) if self._stream_assoc_id else '?',
            self.priority,
            '!' if self._pushed else '',
            StreamStates.str[self._stream_state],
            ExchangeStates.str[self._exchg_state],
            strftime('%H:%M:%S', gmtime(self.timestamp))
        ))

    ### "Public" methods
    
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
        
    def request_headers(self, req_hdrs):
        """
        Send additional request headers
        """
        self.session._req_headers(self, req_hdrs)
        
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

class SpdyClientSession(SpdyMessageHandler, EventEmitter):
    """
    A SPDY connection to a server

    Event handlers that can be added:
        error(err)
        pause(paused)
        ping(
        syn_stream(
        ..etc for each frame type
    """
    def __init__(self, client, origin):
        SpdyMessageHandler.__init__(self)
        EventEmitter.__init__(self)
        self.client = client
        self.tcp_conn = None
        self.origin = origin # (host, port)
        self.exchanges = dict()
        self._highest_stream_id = -1
        self._highest_ping_id = -1
        self._output_buffer = list()
        self._read_timeout_ev = None

    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.tcp_conn:
            status.append(
              self.tcp_conn.tcp_connected and 'connected' or 'disconnected')
        return "<%s at %#x>" % (", ".join(status), id(self))
    
    ### "Public" methods
    
    def pause_input(self, paused):
        "Temporarily stop / restart sending the response body."
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.pause(paused)
            
    def _close(self):
        if self.tcp_conn:
            self.tcp_conn.close()
            self.tcp_conn = None
        # TODO: figure out how to properly close a session
            
    ### Helper methods
    
    def _next_odd(stream_id):
        return stream_id + 1 + stream_id % 2

    def _next_even(stream_id):
        return stream_id + 2 - stream_id % 2
        
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

    ### Exchange request methods 
    
    def _req_start(self, exchange, method, path, host, scheme, req_hdrs, done):
        if exchange._exchg_state != ExchangeStates.REQ_WAITING:
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
        self._highest_stream_id = self._next_odd(self._highest_stream_id)
        # TODO: check to make sure it's not too high.. what then?
        exchange.stream_id = self._highest_stream_id
        exchange.session = self
        self.exchanges[exchange.stream_id] = exchange
        if done:
            exchange._stream_state = StreamStates.LOCAL_CLOSED
            exchange._exchg_state = ExchangeStates.REQ_DONE
            self._output(self._ser_syn_stream(
                Flags.FLAG_FIN, exchange.stream_id, 
                req_hdrs, exchange.priority))
            self._set_read_timeout(exchange, 'start')
        else:
            exchange.state = ExchangeStates.REQ_STARTED
            self._output(self._ser_syn_stream(
                Flags.FLAG_NONE, exchange.stream_id, 
                req_hdrs, exchange.priority))
    
    def _ensure_can_send(exchange):
        if exchange._exchg_state == ExchangeStates.REQ_WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request headers not sent.'))
            return False
        elif exchange._exchg_state != ExchangeStates.REQ_STARTED:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
            return False
        return True
    
    def _req_headers(self, exchange, req_hdrs):
        if _ensure_can_send(exchange):
            req_hdrs = [(entry[0].lower, entry[1]) for entry in req_hdrs 
                if not entry[0].lower() in req_remove_hdrs]
            self._output(self._ser_headers(
                Flags.FLAG_NONE, exchange.stream_id, req_hdrs))
    
    def _req_body(self, exchange, chunk):
        if _ensure_can_send(exchange):
            self._output(self._ser_data_frame(
                Flags.FLAG_NONE, exchange.stream_id, chunk))
    
    def _req_done(self, exchange):
        if _ensure_can_send(exchange):
            exchange._exchg_state = ExchangeStates.REQ_DONE
            exchange._stream_state = StreamStates.LOCAL_CLOSED
            self._set_read_timeout(exchange, 'start')
            self._output(self._ser_data_frame(
                Flags.FLAG_FIN, exchange.stream_id, ''))
    
    ### Frame handling methods called by common.SpdyMessageHandler
    
    #def _handle_frame(self, frame):
        #_clear_read_timeout(self)
    
    #def handle_syn(self):
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
        
        #_set_read_timeout(self)
        
    def _handle_data(self, flags, stream_id, chunk):
        pass
    
    def _handle_syn_stream(self, flags, stream_id, stream_assoc_id, 
        priority, slot, hdr_tuples):
        pass
        
    def _handle_syn_reply(self, flags, stream_id, hdr_tuples):
        raise NotImplementedError

    def _handle_rst_stream(self, stream_id, status):
        raise NotImplementedError
    
    def _handle_settings(self, flags, settings_tuples):
        raise NotImplementedError
    
    def _handle_ping(self, ping_id):
        raise NotImplementedError
        
    def _handle_goaway(self, last_stream_id, reason):
        raise NotImplementedError
        
    def _handle_headers(self, flags, stream_id, hdr_tuples):
        raise NotImplementedError
     
    def _handle_window_update(self, stream_id, size):
        raise NotImplementedError
    
    ### Error handlers
         
    def _handle_error(self, err):
        # on InvalidStreamIDError send GOAWAY + close session
        pass
   
    def _input_error(self, err):
        "Indicate a parsing problem with the server response."
        self._clear_read_timeout(self)
        if not err.client_recoverable:
            self.client.remove_session(self)
        self._set_read_timeout(self)
        self.emit('error', err)
        
    ### Input-related methods called by common.SpdyMessageHandler

    def _input_start(self, stream_id, stream_assoc_id, hdr_tuples, priority):
        "Indicate the beginning of a response or a new pushed stream."
        # TODO: validate host for same-origin policy
        if stream_assoc_id:
            # create new server push stream
            pushed_exchg = SpdyClientExchange(self.client)
            pushed_exchg.session = self
            pushed_exchg.stream_id = stream_id
            pushed_exchg.priority = priority
            pushed_exchg._pushed = True
            pushed_exchg._stream_assoc_id = stream_assoc_id
            pushed_exchg._exchg_state = ExchangeStates.REQ_DONE
            pushed_exchg._stream_state = StreamStates.LOCAL_CLOSED
            self.exchanges[stream_id] = pushed_exchg
            exchange = self.exchanges[stream_assoc_id]
        else:
            # response for stream request
            exchange = self.exchanges[stream_id]
            exchange._exchg_state = ExchangeStates.RES_STARTED
        self._clear_read_timeout(exchange)
        self._set_read_timeout(exchange, 'body')
        exchange.emit('response_start', stream_id, header_dict(hdr_tuples)) 
    
    def _input_body(self, stream_id, chunk):
        "Process a response body chunk from the wire."
        exchange = self.exchanges[stream_id]
        if exchange._pushed:
            exchange = self.exchanges[exchange._stream_assoc_id]
        self._clear_read_timeout(exchange)
        self._set_read_timeout(exchange, 'body')
        exchange.emit('response_body', stream_id, chunk)
    
    def _input_headers(self, stream_id, hdr_tuples):
        "Process additional response headers."
        exchange = self.exchanges[stream_id]
        if exchange._pushed:
            exchange = self.exchanges[exchange._stream_assoc_id]
        self._clear_read_timeout(exchange)
        self._set_read_timeout(exchange, 'body')
        exchange.emit('response_headers', stream_id, header_dict(hrd_tuples))
        
    def _input_end(self, stream_id):
        "Indicate that the response body is complete."
        exchange = self.exchanges[stream_id]
        exchange._exchg_state = ExchangeStates.RES_DONE
        exchange._stream_state = StreamStates.CLOSED
        if exchange._pushed:
            exchange = self.exchanges[exchange._stream_assoc_id]
        self._clear_read_timeout(exchange)
        if exchange._exchg_state != ExchangeStates.RES_DONE
            self._set_read_timeout(exchange, 'body')
        exchange.emit('response_done', stream_id)
        # TODO: delete stream if output side is half-closed.

    ### Output-related methods called by common.SpdyMessageHandler
    
    def _output(self, chunk):
        self._output_buffer.append(chunk)
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write(''.join(self._output_buffer))
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
            self._handle_input('')
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
