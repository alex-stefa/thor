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

import os
import sys
import logging
from urlparse import urlsplit, urlunsplit

import thor
from thor.events import EventEmitter, on
from thor.tcp import TcpClient
from thor.spdy import error
from thor.spdy.common import *
    
req_remove_hdrs = (invalid_hdrs + 
    [':method', ':path', ':version', ':host', ':scheme'])

#-------------------------------------------------------------------------------

# TODO: figure out appropriate logging
# TODO: proxy support
# TODO: implement connect retry? 
# TODO: spdy over tls (needs npn support)

class SpdyClient(EventEmitter):
    """
    An asynchronous SPDY client.
    """
    def __init__(self, 
            connect_timeout=None, 
            read_timeout=None, 
            loop=None, 
            spdy_session_class=SpdyClientSession, 
            tcp_client_class=TcpClient):
        EventEmitter.__init__(self)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._sessions = dict()
        self._loop = loop or thor.loop._loop
        self._loop.on('stop', self.close)
        self._spdy_session_class = spdy_session_class
        self._tcp_client_class = tcp_client_class

        # TODO:
        self.proxy = None
        self.use_tls = False

    def session(self, origin):
        """
        Find an idle connection for (host, port), or create a new one.
        """
        host, port = origin # FIXME: add scheme?
        try:
            session = self._sessions[origin]
        except KeyError:
            session = self._spdy_session_class(self, origin)
            tcp_client = self._tcp_client_class(self._loop)
            tcp_client.on('connect', session._handle_connect)
            tcp_client.on('connect_error', session._handle_connect_error)
            tcp_client.connect(host, port, self._connect_timeout)
            self.sessions[origin] = session
        return session
        
    def _remove_session(self, session):
        """
        Closes and removes session from dictionary.
        """
        try:
            if self._sessions[session.origin] == session:
                del self._sessions[session.origin]
        except:
            pass
            
    def shutdown(self):
        """
        Close all SPDY sessions.
        """
        for session in self._sessions.values():
            try:
                session._close()
            except:
                pass
        self._sessions.clear()
    
    def exchange(self):
        """
        Return an unbounded client exchange. When a request is made on the 
        exchange, it will be bound to a session corresponding to the 
        host refered to in the request URL.
        """
        return SpdyClientExchange(self)
        
#-------------------------------------------------------------------------------

class SpdyClientExchange(EventEmitter, SpdyExchange):
    """
    A SPDY request-response exchange with support for server push streams

    Event handlers that can be added:
        response_start(hdr_dict)
        response_headers(hdr_dict)
        response_body(chunk)
        response_done()
        pushed_response(exchage) -- new server pushed response associated with  
            this exchange's request wrapped in a SpdyClientExchange instance
        error(err)
    """
    def __init__(self, client):
        EventEmitter.__init__(self)
        SpdyExchange.__init__(self)
        self.client = client
        self._read_timeout_ev = None
        
    ### "Public" methods
    
    def request_start(self, method, uri, req_hdrs, done=False):
        """
        Start a request to uri using method, where
        req_hdrs is a list of (field_name, field_value) for
        the request headers.
        
        If @done is True, the request is sent immediately with an empty body.
        """
        # TODO: find out where to connect to the hard way
        (scheme, authority, path, query, fragment) = urlsplit(uri)
        scheme = scheme.lower()
        if scheme != 'http':
            self.emit('error', error.UrlError('Only HTTP URLs are supported.'))
            return
        if '@' in authority:
            userinfo, authority = authority.split('@', 1)
        authority = authority.lower()
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
        self.session._req_start(self, method, scheme, authority, path, 
            req_hdrs, done)
        
    def request_headers(self, req_hdrs):
        """
        Send additional request headers.
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
        
    def cancel(self):
        """
        Sends a RST_STREAM frame with CANCEL status code to indicate that
        the SPDY stream associated to this exchange should be cancelled.
        """
        self.session._close_exchg(self, StatusCodes.CANCEL)

#-------------------------------------------------------------------------------

class SpdyClientSession(SpdyMessageHandler, EventEmitter):
    """
    A SPDY connection to a server.

    Event handlers that can be added:
        frame(frame)
        pause(paused)
        error(err)
        close()
    """
    def __init__(self, client, origin):
        SpdyMessageHandler.__init__(self)
        EventEmitter.__init__(self)
        self.client = client
        self.tcp_conn = None
        self.origin = origin # (host, port)
        self.exchanges = dict()
        self._highest_stream_id = 0
        self._highest_ping_id = 0
        self._output_buffer = list()
        self._read_timeout_ev = None

    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.tcp_conn:
            status.append(
              self.tcp_conn.tcp_connected and 'connected' or 'disconnected')
        return "<%s at %#x>" % (", ".join(status), id(self))
    
    ### "Public" methods
    
    @property
    def is_active(self):
        return self.tcp_conn is not None
                
    def close(self, reason=GoawayReasons.OK):
        """
        Tear down the SPDY session for given reason.
        """
        if not self.is_active:
            return
        if reason is not None:
            self._queue_frame(
                Priority.MAX,
                GoawayFrame(self._highest_stream_id, reason))
        self._clear_read_timeout(self)
        self._close_active_exchanges(error.ConnectionClosedError(
                'Local endpoint has closed the connection.'))
        if self.tcp_conn:
            self.tcp_conn.close()
            self.tcp_conn = None
        self.client._remove_session(self)
        self.emit('close')

    def pause_input(self, paused):
        """
        Temporarily stop / restart sending the response body.
        """
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.pause(paused)
        
    ### Helper methods
    
    def _validate_stream_id(self, stream_id, existing=True):
        if existing:
            if stream_id not in self.streams:
                return error.StreamIdError('#%d is unknown' % stream_id))
        else:
            if stream_id < self.highest_stream_id:
                return error.StreamIdError('#%d already seen' % stream_id))
            if stream_id % 2 == 1:
                return error.StreamIdError('#%d expected even' % stream_id))
        return None

    def _validate_headers(self, hdr_tuples):
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
            
    def _next_stream_id(self):
        self._highest_stream_id = self._next_odd(self._highest_stream_id)
        if self._highest_stream_id > MAX_STREAM_ID:
            raise ValueError('Next stream ID is larger than 31 bits.')
        return self._highest_stream_id
                
    def _ensure_can_init(self, exchange):
        if exchage._pushed:
            exchange.emit('error', error.ExchangeStateError(
                'Cannont make a request on a pushed stream.'))
            return False
        if exchange._req_state != ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
            return False
        return True

    def _ensure_can_send(self, exchange):
        if exchage._pushed:
            exchange.emit('error', error.ExchangeStateError(
                'Cannont make a request on a pushed stream.'))
            return False
        if exchange._req_state == ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request headers not sent.'))
            return False
        elif exchange._req_state == ExchangeStates.DONE:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
            return False
        return True

    ### Exchange request methods 
    
    def _req_start(self, exchange, method, scheme, host, path, req_hdrs, done):
        if not self._ensure_can_init(exchange):
            return
        req_hdrs = clean_headers(req_hdrs, req_remove_hdrs)
        req_hdrs.append((':method', method if method else ''))
        req_hdrs.append((':version', 'HTTP/1.1'))
        req_hdrs.append((':scheme', scheme if scheme else ''))
        req_hdrs.append((':host', host if host else ''))
        req_hdrs.append((':path', path if path else ''))
        exchange.stream_id = self._next_stream_id()
        exchange.session = self
        self.exchanges[exchange.stream_id] = exchange
        if done:
            self._queue_frame(
                exchage.priority,
                SynStreamFrame(
                    Flags.FLAG_FIN, 
                    exchage.stream_id,
                    req_hdrs,
                    exchage.priority,
                    0, # stream_assoc_id
                    0))
            exchange._req_state = ExchangeStates.DONE
            self._set_read_timeout(exchange, 'start')
        else:
            self._queue_frame(
                exchage.priority,
                SynStreamFrame(
                    Flags.FLAG_NONE, 
                    exchage.stream_id,
                    req_hdrs,
                    exchage.priority,
                    0, # stream_assoc_id
                    0))
            exchange._req_state = ExchangeStates.STARTED
    
    def _req_headers(self, exchange, req_hdrs):
        if self._ensure_can_send(exchange):
            req_hdrs = clean_headers(req_hdrs, req_remove_hdrs)
            self._queue_frame(
                exchage.priority,
                HeadersFrame(
                    Flags.FLAG_NONE,
                    exchage.stream_id,
                    req_hdrs))
    
    def _req_body(self, exchange, chunk):
        if self._ensure_can_send(exchange) and chunk is not none:
            self._queue_frame(
                exchange.priority,
                DataFrame(
                    Flags.FLAG_NONE,
                    exchange.stream_id, 
                    chunk))
    
    def _req_done(self, exchange):
        if self._ensure_can_send(exchange):
            self._queue_frame(
                exchange.priority,
                DataFrame(
                    Flags.FLAG_FIN,
                    exchange.stream_id, 
                    ''))
            exchange._req_state = ExchangeStates.DONE
            self._set_read_timeout(exchange, 'start')
    
    ### Error handler method called by common.SpdyMessageHandler
         
    def _handle_error(self, err, status=None, stream_id=None):
        """
        Properly handle a SPDY stream-level error with given @status code
        for @stream_id, or a session-level error if @stream_id is None.
        """
        if stream_id is None: # session error
            if err is not None:
                self.emit('error', err)
            self._close_active_exchanges(err)
            self._close(status)
        else: # stream error
            try:
                exchange = self.exchanges[stream_id]
            except:
                exchange = None
            if exchange:
                if err is not None:
                    exchange.emit('error', err)
                self._close_exchange(exchange, status)
    
    def _close_exchange(self, exchange, status=None):
        """
        Closes the SPDY stream with given status code.
        """
        exchange._req_state = DONE
        exchange._res_state = DONE
        self._clear_read_timeout(exchage)
        if status is not None:
            self._queue_frame(
                Priority.MAX,
                RstStreamFrame(exchange.stream_id, status))
        # TODO: when to remove closed exchange from self.exchanges?
    
    def _close_active_exchanges(self, err=None):
        """
        Closes all active exchanges, issuing given error.
        """
        for (stream_id, exchange) in self.exchanges.items():
            if exchange.is_active:
                self._close_exchg(exchange, None)
                if err is not None:
                    exchange.emit('error', err)
                    
    ### Output-related method called by common.SpdyMessageHandler

    def _queue_frame(self, priority, frame):
        self._output(frame.serialize(self))

    def _output(self, chunk):
        self._output_buffer.append(chunk)
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write(''.join(self._output_buffer))
            self._output_buffer = []

    ### Methods called by tcp
    
    def _handle_connect(self, tcp_conn):
        """
        The connection to the server has succeeded.
        """
        self.tcp_conn = tcp_conn
        self._set_read_timeout(self, 'connect')
        tcp_conn.on('data', self._handle_input)
        tcp_conn.on('close', self._handle_closed)
        tcp_conn.on('pause', self._handle_pause)
        # FIXME: should this be done AFTER _req_start?
        self._output('') # kick the output buffer
        self.tcp_conn.pause(False)

    def _handle_connect_error(self, err_type, err_id, err_str):
        """
        The connection to the server has failed.
        """
        self._handle_error(error.ConnectError(err_str))
        
    def _handle_closed(self):
        """
        The server closed the connection.
        """
        self._clear_read_timeout(self)
        if self._input_buffer:
            self._handle_input('')
        self._handle_error(error.ConnectionClosedError(
            'Remote endpoint has closed the connection.'))
        # TODO: what if conn closed while in the middle of reading frame data?
        
    def _handle_pause(self, paused):
        """
        The client needs the application to pause/unpause the request body.
        """
        self.emit('pause', paused)
        for (stream_id, exchange) in self.exchanges.items():
            if exchange.is_active:
                exchange.emit('pause', paused)
        # TODO: actually pause sending data from _output_buffer
    
    ### Timeouts

    def _handle_read_timeout(self, entity, err):
        """
        Handle a read timeout on the exchange entity, of session if it's None.
        """
        if entity == self: # session level read timeout
            self._handle_error(
                error.ReadTimeoutError('No frame received for %d seconds.' 
                    % self.client._read_timeout),
                GoawayReasons.OK)
        else: # a SpdyClientExchange read timeout
            self._handle_error(err, StatusCodes.CANCEL, entity.stream_id)
        
    def _set_read_timeout(self, entity, kind):
        """
        Set the read timeout associated to entity.
        """
        if self.client._read_timeout and entity._read_timeout_ev is None:
            entity._read_timeout_ev = self.client._loop.schedule(
                self.client.read_timeout, 
                self._handle_read_timeout, 
                entity, 
                error.ReadTimeoutError(kind))

    def _clear_read_timeout(self, entity):
        """
        Clear the read timeout associated to entity.
        """
        if entity._read_timeout_ev:
            entity._read_timeout_ev.delete()
            entity._read_timeout_ev = None
    
    ### Frame handling methods called by common.SpdyMessageHandler
    
    def _handle_frame(self, frame):
        self._clear_read_timeout(self)
    
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
        
        self._set_read_timeout(self)
        
    
    




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
