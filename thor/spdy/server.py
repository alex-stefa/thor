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

from thor.loop import _loop as global_loop
from thor.events import EventEmitter
from thor.tcp import TcpServer
from thor.spdy import error
from thor.spdy.common import *
from thor.spdy.frames import *

res_remove_hdrs = invalid_hdrs + response_hdrs + response_pushed_hdrs

#-------------------------------------------------------------------------------

class SpdyServerExchange(SpdyExchange):
    """
    A SPDY request-response exchange with support for server push streams.

    Event handlers that can be added:
        request_start(header_dict)
        request_headers(header_dict)
        request_body(chunk)
        request_done()
        pause(paused)
        error(err)
    """
    def __init__(self, server, session):
        SpdyExchange.__init__(self)
        self.server = server
        self.session = session
        
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
            path = urlunsplit(('', '', path, query, fragment))
            self.session._res_start(self, status, scheme, authority, path,
                res_hdrs, done)
        else:
            self.session._res_start(self, status, None, None, None,
                res_hdrs, done)
        
    def response_headers(self, res_hdrs):
        """
        Send additional response headers.
        """
        # TODO: "Note: If the server does not have all of the Name/Value Response headers available at the time it issues the HEADERS frame for the pushed resource, it may later use an additional HEADERS frame to augment the name/value pairs to be associated with the pushed stream. The subsequent HEADERS frame(s) must not contain a header for ':host', ':scheme', or ':path' (e.g. the server can't change the identity of the resource to be pushed). The HEADERS frame must not contain duplicate headers with a previously sent HEADERS frame. The server must send a HEADERS frame including the scheme/host/port headers before sending any data frames on the stream."
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
        # TODO: "The server MUST only push resources which would have been returned from a GET request."
        return self.session._init_pushed_exchg(self)
        
    def cancel(self):
        """
        Sends a RST_STREAM frame with CANCEL status code to indicate that
        the SPDY stream associated to this exchange should be cancelled.
        
        If the response has not been started yet, the REFUSED_STREAM status 
        code will be used.
        """
        if self._res_state == ExchangeStates.WAITING:
            self.session._close_exchange(self, StatusCodes.REFUSED_STREAM)
        else:
            self.session._close_exchange(self, StatusCodes.CANCEL)
        
#-------------------------------------------------------------------------------

class SpdyServerSession(SpdySession):
    """
    A SPDY connection to a client.
    
    Event handlers that can be added:
        exchange(exchange) -- a new SpdyServerExchange request has been received
        bound(tcp_conn)
        frame(frame)
        goaway(reason, last_stream_id)
        pause(paused)
        error(err)
        close()
    """
    def __init__(self, server, tcp_conn):
        SpdySession.__init__(self, False, server._idle_timeout, server._loop)
        self.server = server
        self._write_queue = [[] for x in Priority.range]
        self._write_pending = False
        self._output_paused = False
        self.frame_handlers[FrameTypes.DATA].append(self._frame_data)
        self.frame_handlers[FrameTypes.SYN_STREAM].append(self._frame_syn_stream)
        self.frame_handlers[FrameTypes.SYN_REPLY].append(self._frame_syn_reply)
        self.frame_handlers[FrameTypes.HEADERS].append(self._frame_headers)
        self.frame_handlers[FrameTypes.RST_STREAM].append(self._frame_rst_stream)
        self._bind(tcp_conn)
            
    ### Exchange response methods 
    
    def _init_pushed_exchg(self, assoc_exchg):
        exchg = SpdyServerExchange(self.server, self)
        exchg.stream_id = self._next_created_stream_id()
        exchg.priority = assoc_exchg.priority
        exchg._stream_assoc_id = assoc_exchg.stream_id
        exchg._pushed = True
        exchg._req_state = ExchangeStates.DONE
        exchg._res_state = ExchangeStates.WAITING
        self.exchanges[exchg.stream_id] = exchg
        return exchg
        
    def _init_exchg(self, syn_stream_frame):
        exchg = SpdyServerExchange(self.server, self)
        exchg.stream_id = syn_stream_frame.stream_id
        self._highest_accepted_stream_id = exchg.stream_id
        exchg.priority = syn_stream_frame.priority
        if syn_stream_frame.flags == Flags.FLAG_FIN:
            exchg._req_state = ExchangeStates.DONE 
        else:
            exchg._req_state = ExchangeStates.STARTED
        exchg._res_state = ExchangeStates.WAITING
        self.exchanges[exchg.stream_id] = exchg
        return exchg

    def _ensure_can_init(self, exchange):
        if exchange._res_state != ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Response already sent.'))
            return False
        if exchange._pushed:
            if self._received_goaway:
                exchange.emit('error', error.ExchangeStateError(
                    'Cannot push new stream after receiving session GOAWAY.'))
                return False
            try:
                assoc_exchg = self.exchanges[exchange._stream_assoc_id]
                if assoc_exchg._res_state == ExchangeStates.DONE:
                    exchange.emit('error',
                        err.ExchangeStateError('Cannot push new stream for '
                        'closed associated stream.'))
                    return False
            except KeyError:
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
                error.ExchangeStateError('Response already sent or exchange cancelled.'))
            return False
        return True
        
    def _res_start(self, exchange, status, scheme, host, path, res_hdrs, done):
        if not self._ensure_can_init(exchange):
            return
        res_hdrs = clean_headers(res_hdrs, res_remove_hdrs)
        # FIXME: is status necessary on pushed streams?
        res_hdrs.append((':status', str(status) if status else ''))
        res_hdrs.append((':version', 'HTTP/1.1'))
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
        exchange._res_state = (ExchangeStates.DONE if done 
            else ExchangeStates.STARTED)
            
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
    
    def _res_done(self, exchange):
        if self._ensure_can_send(exchange):
            self._queue_frame(
                exchange.priority,
                DataFrame(
                    Flags.FLAG_FIN,
                    exchange.stream_id, 
                    ''))
            exchange._res_state = ExchangeStates.DONE

    ### Output-related method called by common.SpdySession
    
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
            self._loop.schedule(0, self._write_frame_callback)
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

    ### TCP handling methods 
            
    def _handle_pause(self, paused):
        SpdySession._handle_pause(self, paused)
        self._output_paused = paused
        if not paused:
            self._schedule_write()
        
    ### Frame input handler method called by frames.SpdySession._handle_frame
    
    def _frame_data(self, frame):
        exchange = self._exchange_or_die(frame.stream_id)
        if exchange:
            if exchange._req_state != ExchangeStates.STARTED:
                """
                If an endpoint receives a data frame after the stream is 
                half-closed from the sender (e.g. the endpoint has already 
                received a prior frame for the stream with the FIN flag set), 
                it MUST send a RST_STREAM to the sender with the status
                STREAM_ALREADY_CLOSED.
                """
                # NOTE: exchange._req_state can never be ExchangeStates.WAITING
                # on the server side because a received SYN_STREAM implies
                # that a request has started
                self._handle_error(error.ProtocolError(
                    'DATA frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            else:
                exchange.emit('request_body', frame.data)
                if frame.flags == Flags.FLAG_FIN:
                    exchange._req_state = ExchangeStates.DONE
                    exchange.emit('request_done')
            
    def _frame_syn_stream(self, frame):
        if self._sent_goaway:
            """
            After sending a GOAWAY message, the sender must ignore all 
            SYN_STREAM frames for new streams.
            """
            self.emit('error', error.ProtocolError(
                'Server received SYN_STREAM after sending GOAWAY.'))
        elif self._valid_new_stream_id(frame.stream_id):
            exchange = self._init_exchg(frame)
            err = self._header_error(frame.hdr_tuples, request_hdrs)
            if err:
                """
                If a client sends a SYN_STREAM without all of the method, 
                host, path, scheme, and version headers, the server MUST 
                reply with a HTTP 400 Bad Request reply.
                """
                self.emit('exchange', exchange)
                exchange.emit('error', err)
                exchange.response_start(None, "400 Bad Request", done=True)
                # TODO: exchange._req_state = ExchangeStates.DONE ?
            else:
                self.emit('exchange', exchange)
                exchange.emit('request_start', header_dict(frame.hdr_tuples))
                exchange._req_state = ExchangeStates.STARTED
                if frame.flags == Flags.FLAG_FIN:
                    exchange._req_state = ExchangeStates.DONE
                    exchange.emit('request_done')
                elif frame.flags == Flags.FLAG_UNIDIRECTIONAL:
                    exchange.emit('error', error.ProtocolError(
                        'Client set FLAG_UNIDIRECTIONAL in SYN_STREAM.'))
    
    def _frame_headers(self, frame):
        exchange = self._exchange_or_die(frame.stream_id)
        if exchange:
            if exchange._req_state != ExchangeStates.STARTED:
                # See handling for FrameTypes.DATA
                self._handle_error(error.ProtocolError(
                    'HEADERS frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            else:
                exchange.emit('request_headers', header_dict(frame.hdr_tuples))
                if frame.flags == Flags.FLAG_FIN:
                    exchange._req_state = ExchangeStates.DONE
                    exchange.emit('request_done')
                    
    def _frame_rst_stream(self, frame):
        """
        After receiving a RST_STREAM on a stream, the recipient must not 
        send additional frames for that stream, and the stream moves into 
        the closed state.
        """
        try:
            exchange = self.exchanges[frame.stream_id]
        except KeyError:
            # FIXME: should the session be terminated in this case?
            self.emit('error', error.ProtocolError(
                'Server received RST_STREAM for unknown stream with ID %d' %
                frame.stream_id))
            return
        self._close_exchange(exchange)
        """
        To cancel all server push streams related to a request, the client 
        may issue a stream error (Section 2.4.2) with error code CANCEL on
        the associated-stream-id. By cancelling that stream, the server MUST
        immediately stop sending frames for any streams with 
        in-association-to for the original stream.
        """
        # FIXME: looping like this can take too much time
        if frame.status == StatusCodes.CANCEL:
            for exchange in self.exchanges.values():
                if (exchange._pushed and 
                    exchange._stream_assoc_id == frame.stream_id):
                    self._close_exchange(exchange)
        exchange.emit('error', error.RstStreamError(
            'Status code %s' % StatusCodes.str[frame.status]))
        
    def _frame_syn_reply(self, frame):
        # clients should never be sending SYN_REPLY
        self.emit('error', error.ProtocolError(
            'Server received SYN_REPLY from client with stream ID %d.' %
            frame.stream_id))
                
#-------------------------------------------------------------------------------

# TODO: figure out appropriate logging
# TODO: spdy over tls (needs npn support)
# TODO: read timeout for receiving a complete request on a stream?

class SpdyServer(EventEmitter):
    """
    An asynchronous SPDY server.
    
    Event handlers that can be added:
        session(session) -- a new SpdyServerSession connection has been accepted
    """
    def __init__(self,
            host='localhost',
            port=8080,
            idle_timeout=None, # seconds a conn is kept open until a frame is received
            loop=None,
            spdy_session_class=SpdyServerSession,
            tcp_server_class=TcpServer):
        EventEmitter.__init__(self)
        self._host = host
        self._port = port
        self._idle_timeout = idle_timeout if idle_timeout > 0 else None
        self._spdy_session_class = spdy_session_class
        self._loop = loop or global_loop
        self._loop.on('stop', self.shutdown)
        self._tcp_server = tcp_server_class(host, port, loop=self._loop)
        self._tcp_server.on('connect', self._handle_conn)
        
        # TODO:
        self.use_tls = False # TODO: SPDY over TLS
        self.certfile = None
        self.keyfile = None
 
    def _handle_conn(self, tcp_conn):
        """
        Process a new client connection, tcp_conn.
        """
        session = self._spdy_session_class(self, tcp_conn)
        self.emit('session', session)
        
    def shutdown(self):
        """
        Stop the server.
        """
        self._tcp_server.shutdown()
        # TODO: close existing sessions? (we have no reference to them here..)

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    pass
