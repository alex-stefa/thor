#!/usr/bin/env python

"""
Thor SPDY Server
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
from thor.tcp import TcpServer
from thor.spdy import error
from thor.spdy.common import *

res_remove_hdrs = (invalid_hdrs + 
    [':status', ':path', ':version', ':host', ':scheme'])

#-------------------------------------------------------------------------------

# TODO: figure out appropriate logging
# TODO: spdy over tls (needs npn support)
# TODO: read timeout for receiving a complete request on a stream?

class SpdyServer(EventEmitter):
    """
    An asynchronous SPDY server.
    
    Event handlers that can be added:
        start()
        stop()
        exchange(exchange) -- a new request has been received
    """
    def __init__(self,
            host='localhost',
            port=8080,
            idle_timeout=None, # seconds a conn is kept open until a frame is received
            loop=None,
            spdy_session_class=SpdyServerSession,
            tcp_server_class=TcpServer):
        EventEmitter.__init__(self)
        self._idle_timeout = idle_timeout
        self._spdy_session_class = spdy_session_class
        self._tcp_server = tcp_server_class(host, port, loop=loop)
        self._tcp_server.on('connect', self._handle_conn)
        thor.schedule(0, self.emit, 'start') # FIXME: does this work?
        
        # TODO:
        self.use_tls = False # TODO: SPDY over TLS
        self.certfile = None
        self.keyfile = None
 
    def _handle_conn(self, tcp_conn):
        """
        Process a new client connection, tcp_conn.
        """
        session = self._spdy_session_class(self, tcp_conn)
        session._set_idle_timeout()
        tcp_conn.on('data', session._handle_input)
        tcp_conn.on('close', session._handle_closed)
        tcp_conn.on('pause', session._handle_pause)
        tcp_conn.pause(False)
        
    def shutdown(self):
        """
        Stop the server.
        """
        self._tcp_server.shutdown()
        self.emit('stop')
        # TODO: close existing sessions? (we have no reference to them here..)

#-------------------------------------------------------------------------------

class SpdyServerExchange(EventEmitter, SpdyExchange):
    """
    A SPDY request-response exchange with support for server push streams.

    Event handlers that can be added:
        request_start(hdr_dict)
        request_headers(hdr_dict)
        request_body(chunk)
        request_done()
        pause(paused)
        error(err)
    """
    def __init__(self, server):
        EventEmitter.__init__(self)
        SpdyExchange.__init__(self)
        self.server = server
        
    ### "Public" methods
   
    def response_start(self, res_hdrs, status="200 OK", uri=None, done=False):
        """
        Start a response to the request received by the exchange with specified 
        response status and headers as a list of (field_name, field_value). 
        
        The @uri of the response resource is necessary if it is a pushed stream.
        
        If @done is True, the response is sent immediately with an empty body.
        """
        # TODO: more elegant status specification?
        # TODO: find out where to connect to the hard way
        if self._pushed:
            if not uri:
                self.emit('error', 
                    error.UrlError('Missing URI for pushed resource.'))
                return
            (scheme, authority, path, query, fragment) = urlsplit(uri)
            scheme = scheme.lower()
            if scheme != 'http':
                self.emit('error', 
                    error.UrlError('Only HTTP URLs are supported.'))
                return
            if '@' in authority:
                userinfo, authority = authority.split('@', 1)
            authority = authority.lower()
            path = '/' + urlunsplit(('', '', path, query, fragment))
            self.session._res_start(self, status, scheme, authority, path,
                res_hdrs, done)
        else:
            self.session._res_start(self, status, None, None, None,
                res_hdrs, done)
        
    def response_headers(self, res_hdrs):
        """
        Send additional response headers.
        """
        self.session._res_headers(self, res_hdrs)
        
    def response_body(self, chunk):
        """
        Send part of the response body. May be called zero to many times.
        """
        self.session._res_body(self, chunk)
        
    def response_done(self):
        """
        Signal the end of the response, whether or not there was a body. MUST be
        called exactly once for each response. 
        """
        self.session._res_done(self)
        
    def push_response(self):
        """
        Create a pushed exchange associated to the current exchange. 
        This exchange will not be receiving request_XXX events, and should
        be used by calling the response_XXX methods.
        """
        return self.session._init_pushed_exchg(self)
        
    def cancel(self):
        """
        Sends a RST_STREAM frame with CANCEL status code to indicate that
        the SPDY stream associated to this exchange should be cancelled.
        """
        self.session._close_exchg(self, StatusCodes.CANCEL)
        
#-------------------------------------------------------------------------------

class SpdyServerConnection(SpdyMessageHandler, EventEmitter):
    """
    A SPDY connection to a client.

    Event handlers that can be added:
        frame(frame)
        pause(paused)
        error(err)
        close()
    """
    def __init__(self, server, tcp_conn)
        SpdyMessageHandler.__init__(self)
        EventEmitter.__init__(self)
        self.server = server
        self.tcp_conn = tcp_conn
        self.exchanges = dict()
        self._highest_created_stream_id = -1
        self._highest_accepted_stream_id = 0
        self._highest_ping_id = 0
        self._write_queue = [[] for x in Priority.range]
        self._write_pending = False
        self._output_paused = False
        self._idle_timeout_ev = None
        
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
                GoawayFrame(self._highest_accepted_stream_id, reason))
        self._clear_idle_timeout()
        self._close_active_exchanges(error.ConnectionClosedError(
                'Local endpoint has closed the connection.'))
        if self.tcp_conn:
            self.tcp_conn.close()
            self.tcp_conn = None
        self.emit('close')
        
    def pause_input(self, paused):
        """
        Temporarily stop / restart sending the request body.
        """
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.pause(paused)
            
    ### Helper methods

    def _next_created_stream_id(self):
        self._highest_created_stream_id = max(
            self._highest_created_stream_id + 2,
            self._highest_accepted_stream_id + 1)
        if self._highest_created_stream_id > MAX_STREAM_ID:
            raise ValueError('Next stream ID is larger than 31 bits.')
        return self._highest_created_stream_id
    
    def _init_pushed_exchg(self, assoc_exchg):
        pushed_exchg = SpdyServerExchange(self.server)
        pushed_exchg.session = self
        pushed_exchg.stream_id = self._next_created_stream_id()
        pushed_exchg.priority = assoc_exchg.priority
        pushed_exchg._stream_assoc_id = assoc_exchg.stream_id
        pushed_exchg._pushed = True
        pushed_exchg._req_state = ExchangeStates.DONE
        pushed_exchg._res_state = ExchangeStates.WAITING
        self.exchanges[pushed_exchg.stream_id] = pushed_exchg
        return pushed_exchg

    def _ensure_can_init(self, exchange):
        if exchange._res_state != ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Response already sent.'))
            return False
        if exchange._pushed:
            try:
                assoc_exchg = self.exchanges[exchange._stream_assoc_id]
                if assoc_exchg._res_state == ExchangeStates.DONE:
                    exchange.emit('error',
                        err.ExchangeStateError('Cannot push new stream for '
                        'closed associated stream.'))
                    return False
            except:
                exchange.emit('error',
                    err.ExchangeStateError('Cannot push new stream for '
                    'unknown associated stream.'))
                return False
        return True
        
    def _ensure_can_send(self, exchange):
        if exchange._res_state == ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Response headers not sent.'))
            return False
        elif exchange._res_state == ExchangeStates.DONE:
            exchange.emit('error', 
                error.ExchangeStateError('Response already sent.'))
            return False
        return True
        
    ### Exchange response methods 
    
    def _res_start(self, exchange, status, scheme, host, path, res_hdrs, done):
        if not self._ensure_can_init(exchange):
            return
        res_hdrs = clean_headers(res_hdrs, res_remove_hdrs)
        # FIXME: is status necessary on pushed streams?
        req_hdrs.append((':status', str(status) if status else ''))
        req_hdrs.append((':version', 'HTTP/1.1'))
        fin_flag = Flags.FLAG_FIN if done else Flags.FLAG_NONE
        if exchange._pushed:
            req_hdrs.append((':scheme', scheme if scheme else ''))
            req_hdrs.append((':host', host if host else ''))
            req_hdrs.append((':path', path if path else ''))
            self._queue_frame(
                exchange.priority,
                SynStreamFrame(
                    Flags.FLAG_FIN if done else Flags.FLAG_UNIDIRECTIONAL,
                    exchange.stream_id, 
                    res_hdrs,
                    exchange.priority,
                    exchange._stream_assoc_id,
                    0))
        else:
            self._queue_frame(
                exchange.priority,
                SynReplyFrame(
                    Flags.FLAG_FIN if done else Flags.FLAG_NONE,
                    exchange.stream_id, 
                    res_hdrs))
        exchange._res_state = ExchangeStates.DONE if done else ExchangeStates.STARTED
            
    def _res_headers(self, exchange, res_hdrs):
        if self._ensure_can_send(exchange):
            res_hdrs = clean_headers(res_hdrs, res_remove_hdrs)
            self._queue_frame(
                exchange.priority,
                HeadersFrame(
                    Flags.FLAG_NONE,
                    exchange.stream_id, 
                    res_hdrs))
    
    def _res_body(self, exchange, chunk):
        if self._ensure_can_send(exchange) and chunk is not None:
            self._queue_frame(
                exchange.priority,
                DataFrame(
                    Flags.FLAG_NONE,
                    exchange.stream_id, 
                    chunk))
    
    def _res_done(seld, exchange):
        if self._ensure_can_send(exchange):
            self._queue_frame(
                exchange.priority,
                DataFrame(
                    Flags.FLAG_FIN,
                    exchange.stream_id, 
                    ''))
            exchange._res_state = DONE

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
    
    def _has_write_data(self):
        if self._output_paused:
            return False
        for p in Priority.range:
            if len(self._write_queue[p]) > 0:
                return True
        return False

    def _write_frame_callback(self):
        """
        Find the highest priority data chunk and send it.
        """
        self._write_pending = False
        for p in Priority.range:
            if len(self._write_queue[p]) > 0:
                frame = self._write_queue[p][0]
                self._write_queue[p] = self._write_queue[p][1:]
                self._output(frame.serialize(self))
                break
        if self._has_write_data():
            self._schedule_write()
        
    def _schedule_write(self):
        if not self._write_pending:
            thor.schedule(0, self._write_frame_callback)
            self._write_pending = True

    def _queue_frame(self, priority, frame):
        self._output_paused = False
        self._clear_idle_timeout()
        self._set_idle_timeout()
        self._write_queue[priority].append(frame)
        self._schedule_write()

    def _output(self, chunk):
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write(chunk)

    ### Methods called by tcp
    
    def _handle_closed(self):
        """
        The remote client closed the connection.
        """
        if self._input_buffer:
            self._handle_input('')
        self._handle_error(error.ConnectionClosedError(
            'Remote endpoint has closed the connection.'))
        # TODO: what if conn closed while in the middle of reading frame data?
        
    def _handle_pause(self, paused):
        """
        The server needs the application to pause/unpause the response body.
        """
        self.emit('pause', paused)
        for (stream_id, exchange) in self.exchanges.items():
            if exchange.is_active:
                exchange.emit('pause', paused)
        self._output_paused = paused
        if not paused:
            self._schedule_write()
        
    ### Timeouts
    
    def _set_idle_timeout(self):
        """
        Set the session idle timeout.
        """
        if self.server._idle_timeout and self._idle_timeout_ev is None:
            self._idle_timeout_ev = thor.schedule(
                self.server._idle_timeout,
                self._handle_error,
                error.IdleTimeoutError('No frame received for %d seconds.' 
                    % self.server._idle_timeout),
                GoawayReasons.OK)
    
    def _clear_idle_timeout(self):
        """
        Clear the session idle timeout.
        """
        if self._idle_timeout_ev:
            self._idle_timeout_ev.delete()
            self._idle_timeout_ev = None

    ### Frame input handler method called by common.SpdyMessageHandler
    
    def _valid_new_stream_id(self, stream_id):
        """
        0 is not a valid Stream-ID.
        If a client receives a server push stream with stream-id 0, it 
        MUST issue a session error (Section 2.4.1) with the status code 
        PROTOCOL_ERROR.
        """
        if stream_id == 0:
            self._handle_error(error.StreamIdError(
                'Invalid stream ID 0.'), GoawayReasons.PROTOCOL_ERROR)
            return False
        """
        The stream-id MUST increase with each new stream. If an endpoint 
        receives a SYN_STREAM with a stream id which is less than any 
        previously received SYN_STREAM, it MUST issue a session error 
        (Section 2.4.1) with the status PROTOCOL_ERROR.
        """
        if stream_id < self._highest_accepted_stream_id:
            self._handle_error(error.StreamIdError(
                'New stream ID %d is less than previously received IDs.' %
                stream_id), GoawayReasons.PROTOCOL_ERROR)
            return False
        """
        It is a protocol error to send two SYN_STREAMs with the same stream-id. 
        If a recipient receives a second SYN_STREAM for the same stream, it 
        MUST issue a stream error (Section 2.4.2) with the status code 
        PROTOCOL_ERROR.
        """
        if stream_id == self._highest_accepted_stream_id:
            self._handle_error(error.StreamIdError(
                'Duplicate SYN_STREAM received for the last accepted stream ID %d.' %
                stream_id), StatusCodes.PROTOCOL_ERROR, stream_id)
            return False
        """
        If the server is initiating the stream, the Stream-ID must be even.
        """
        if stream_id % 2 == 1:
            self._handle_error(error.StreamIdError(
                'New stream ID %d expected to be even.' %
                stream_id), GoawayReasons.PROTOCOL_ERROR)
            return False
        return True
        
    def _valid_created_stream_id(self, stream_id):
        try:
            exchange = self.exchanges[stream_id]
        except:
            
            
    def _valid_accepted_stream_id(self, stream_id):
        
    
    def _handle_frame(self, frame):
        self._clear_idle_timeout()
        self._set_idle_timeout()
        
        if frame.type == FrameTypes.SYN_STREAM:
        
            if frame.
            
            
        #elif frame.type
            
    

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig()
    log = logging.getLogger('server')
    log.setLevel(logging.INFO)
    log.info("PID: %s\n" % os.getpid())
    h, p = '127.0.0.1', int(sys.argv[1])
    server = SpdyServer(h, p, test_handler, log)
    push_tcp.run()
