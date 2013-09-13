#!/usr/bin/env python

"""
Thor SPDY Client
"""

__author__ = "Alex Stefanescu <alex.stefa@gmail.com>"
__copyright__ = """\
Copyright (c) 2013 Alex Stefanescu

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
from urllib.parse import urlsplit, urlunsplit

from thor.loop import _loop as global_loop
from thor.events import EventEmitter
from thor.tcp import TcpClient
from thor.tls import TlsClient, TlsConfig
from thor.spdy import error
from thor.spdy.common import *
from thor.spdy.frames import *
    
req_remove_hdrs = invalid_hdrs + request_hdrs

#-------------------------------------------------------------------------------

class SpdyClientExchange(SpdyExchange):
    """
    A SPDY request-response exchange with support for server push streams

    Event handlers that can be added:
        response_start(header_dict)
        response_headers(header_dict)
        response_body(chunk)
        response_done()
        pause(paused)
        error(err)
        pushed_response(exchange) -- new server pushed response associated with  
            this exchange's request wrapped in a SpdyClientExchange instance
    """
    def __init__(self, client, session):
        SpdyExchange.__init__(self)
        self.client = client
        self.session = session
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
        if scheme not in ['http', 'https']:
            self.emit('error', error.UrlError('Only HTTP(S) URLs are supported.'))
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
        path = urlunsplit(('', '', path, query, fragment))
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
        self.session._close_exchange(self, StatusCodes.CANCEL)
        for e in self.session.exchanges.values():
            if (e._pushed and 
                e._stream_assoc_id == self.stream_id):
                    self.session._close_exchange(e)

#-------------------------------------------------------------------------------

class SpdyClientSession(SpdySession):
    """
    A SPDY connection to a server.
    
    Event handlers that can be added:
        bound(tcp_conn)
        frame(frame)
        output(frame)
        goaway(reason, last_stream_id)
        pause(paused)
        error(err)
        close()
    """
    def __init__(self, client):
        SpdySession.__init__(self, True, client._idle_timeout, client._loop)
        self.client = client
        self._read_timeout = client._read_timeout
        self._output_buffer = list()
        self.frame_handlers[FrameTypes.DATA].append(self._frame_data)
        self.frame_handlers[FrameTypes.SYN_STREAM].append(self._frame_syn_stream)
        self.frame_handlers[FrameTypes.SYN_REPLY].append(self._frame_syn_reply)
        self.frame_handlers[FrameTypes.HEADERS].append(self._frame_headers)
        self.frame_handlers[FrameTypes.RST_STREAM].append(self._frame_rst_stream)

    ### "Public" methods
        
    def exchange(self):
        """
        Returns a new exchange useful to make a new request.
        """
        return SpdyClientExchange(self.client, self)
    
    ### Exchange request methods
    
    def _init_pushed_exchg(self, syn_stream_frame):
        exchg = SpdyClientExchange(self.client, self)
        exchg.stream_id = syn_stream_frame.stream_id
        self._highest_accepted_stream_id = syn_stream_frame.stream_id
        exchg.priority = syn_stream_frame.priority
        exchg._stream_assoc_id = syn_stream_frame.stream_assoc_id
        exchg._pushed = True
        exchg._req_state = ExchangeStates.DONE
        exchg._res_state = ExchangeStates.WAITING
        self.exchanges[exchg.stream_id] = exchg
        return exchg
                
    def _ensure_can_init(self, exchange):
        if exchange._pushed:
            exchange.emit('error', error.ExchangeStateError(
                'Cannont make a request on a pushed stream.'))
            return False
        if self._received_goaway:
            exchange.emit('error', error.ExchangeStateError(
                'Cannot make new request after receiving session GOAWAY.'))
            return False
        if exchange._req_state != ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent.'))
            return False
        return True

    def _ensure_can_send(self, exchange):
        if exchange._pushed:
            exchange.emit('error', error.ExchangeStateError(
                'Cannont make a request on a pushed stream.'))
            return False
        if exchange._req_state == ExchangeStates.WAITING:
            exchange.emit('error', 
                error.ExchangeStateError('Request headers not sent.'))
            return False
        elif exchange._req_state == ExchangeStates.DONE:
            exchange.emit('error', 
                error.ExchangeStateError('Request already sent or exchange cancelled.'))
            return False
        return True
    
    def _req_start(self, exchange, method, scheme, host, path, req_hdrs, done):
        if not self._ensure_can_init(exchange):
            return
        req_hdrs = clean_headers(req_hdrs, req_remove_hdrs)
        req_hdrs.append((':method', method if method else ''))
        req_hdrs.append((':version', 'HTTP/1.1'))
        req_hdrs.append((':scheme', scheme if scheme else ''))
        req_hdrs.append((':host', host if host else ''))
        req_hdrs.append((':path', path if path else ''))
        exchange.stream_id = self._next_created_stream_id()
        self.exchanges[exchange.stream_id] = exchange
        if done:
            self._queue_frame(
                exchange.priority,
                SynStreamFrame(
                    Flags.FLAG_FIN, 
                    exchange.stream_id,
                    req_hdrs,
                    exchange.priority,
                    0, 0)) # stream_assoc_id, slot
            exchange._req_state = ExchangeStates.DONE
            self._set_read_timeout(exchange, 'start')
        else:
            self._queue_frame(
                exchange.priority,
                SynStreamFrame(
                    Flags.FLAG_NONE, 
                    exchange.stream_id,
                    req_hdrs,
                    exchange.priority,
                    0, 0)) # stream_assoc_id, slot
            exchange._req_state = ExchangeStates.STARTED
    
    def _req_headers(self, exchange, req_hdrs):
        if self._ensure_can_send(exchange):
            req_hdrs = clean_headers(req_hdrs, req_remove_hdrs)
            self._queue_frame(
                exchange.priority,
                HeadersFrame(
                    Flags.FLAG_NONE,
                    exchange.stream_id,
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
                    b''))
            exchange._req_state = ExchangeStates.DONE
            self._set_read_timeout(exchange, 'start')
                    
    ### Output-related methods called by common.SpdySession

    def _queue_frame_do(self, priority, frame):
        self._output(frame.serialize(self))

    def _output(self, chunk):
        self._output_buffer.append(chunk)
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write(b''.join(self._output_buffer))
            self._output_buffer = []
            
    def _is_write_pending(self):
        return False
        
    def _init_output(self):
        self._output(b'')
                        
    ### TCP handling methods
    
    def _handle_connect_error(self, err_type, err_id, err_str):
        """
        The connection to the server has failed.
        """
        self._handle_error(error.ConnectError(err_str))
        
    def _handle_pause(self, paused):
        SpdySession._handle_pause(self, paused)
        # TODO: actually pause sending data from _output_buffer
    
    ### Timeouts
    
    def _close_exchange(self, exchange, status=None):
        self._clear_read_timeout(exchange)
        SpdySession._close_exchange(self, exchange, status)

    def _set_read_timeout(self, entity, kind):
        """
        Set the read timeout associated to entity.
        """
        if self._read_timeout and entity._read_timeout_ev is None:
            entity._read_timeout_ev = self._loop.schedule(
                self._read_timeout, 
                self._handle_error, 
                error.ReadTimeoutError(kind),
                StatusCodes.CANCEL,
                entity.stream_id)

    def _clear_read_timeout(self, entity):
        """
        Clear the read timeout associated to entity.
        """
        if entity._read_timeout_ev:
            entity._read_timeout_ev.delete()
            entity._read_timeout_ev = None
    
    ### Frame input handler method called by frames.SpdySession._handle_frame
    
    def _frame_data(self, frame):
        exchange = self._exchange_or_die(frame.stream_id)
        if exchange:
            if exchange._res_state == ExchangeStates.DONE:
                """
                If an endpoint receives a data frame after the stream is 
                half-closed from the sender (e.g. the endpoint has already 
                received a prior frame for the stream with the FIN flag set), 
                it MUST send a RST_STREAM to the sender with the status
                STREAM_ALREADY_CLOSED.
                """
                self._handle_error(error.ProtocolError(
                    'DATA frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            elif exchange._res_state == ExchangeStates.WAITING:
                """
                If the endpoint which created the stream receives a data frame 
                before receiving a SYN_REPLY on that stream, it is a protocol 
                error, and the recipient MUST issue a stream error with the 
                status code PROTOCOL_ERROR for the stream-id.
                """
                self._handle_error(error.ProtocolError(
                    'DATA frame received before SYN_REPLY.'),
                    StatusCodes.PROTOCOL_ERROR, frame.stream_id)
            else:
                exchange.emit('response_body', frame.data)
                self._clear_read_timeout(exchange)
                if frame.flags == Flags.FLAG_FIN:
                    exchange._res_state = ExchangeStates.DONE
                    exchange.emit('response_done')
                else:
                    self._set_read_timeout(exchange, 'body')
            
    def _frame_syn_stream(self, frame):
        if self._sent_goaway:
            """
            After sending a GOAWAY message, the sender must ignore all 
            SYN_STREAM frames for new streams.
            """
            self.emit('error', error.ProtocolError(
                'Client received SYN_STREAM after sending GOAWAY.'))
        elif self._valid_new_stream_id(frame.stream_id):
            try:
                assoc_exchg = self.exchanges[frame.stream_assoc_id]
            except KeyError:
                self._handle_error(error.ProtocolError(
                    ('Client received pushed SYN_STREAM associated '
                     'to unknown stream ID %d.') % frame.stream_assoc_id),
                    StatusCodes.INVALID_STREAM, frame.stream_id)
                return
            if assoc_exchg._res_state == ExchangeStates.DONE:
                self._handle_error(error.ProtocolError(
                    ('Client received pushed SYN_STREAM associated '
                     'to closed stream ID %d.') % frame.stream_assoc_id),
                    StatusCodes.INVALID_STREAM, frame.stream_id)
            else:
                err = self._header_error(frame.hdr_tuples, response_pushed_hdrs)
                if err:
                    """
                    When a client receives a SYN_STREAM from the server 
                    without the ':host', ':scheme', and ':path' headers i
                    n the Name/Value section, it MUST reply with a 
                    RST_STREAM with error code HTTP_PROTOCOL_ERROR.
                    """
                    # NOTE: there is no HTTP_PROTOCOL_ERROR in spdy/3 spec
                    self._handle_error(err, 
                        StatusCodes.PROTOCOL_ERROR, frame.stream_id)
                else:
                    exchange = self._init_pushed_exchg(frame)
                    assoc_exchg.emit('pushed_response', exchange)
                    exchange.emit('response_start', header_dict(frame.hdr_tuples))
                    if frame.flags == Flags.FLAG_FIN:
                        exchange._res_state = ExchangeStates.DONE
                        exchange.emit('response_done')
                    elif frame.flags == Flags.FLAG_UNIDIRECTIONAL:
                        self._set_read_timeout(exchange, 'body')
                    else:
                        exchange.emit('error', error.ProtocolError(
                            'Server did not set FLAG_UNIDIRECTIONAL in SYN_STREAM.'))
    
    def _frame_headers(self, frame):
        exchange = self._exchange_or_die(frame.stream_id)
        if exchange:
            if exchange._res_state == ExchangeStates.DONE:
                # See handling for FrameTypes.DATA
                self._handle_error(error.ProtocolError(
                    'HEADERS frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            elif exchange._res_state == ExchangeStates.WAITING:
                # See handling for FrameTypes.DATA
                self._handle_error(error.ProtocolError(
                    'HEADERS frame received before SYN_REPLY.'),
                    StatusCodes.PROTOCOL_ERROR, frame.stream_id)
            else:
                exchange.emit('response_headers', header_dict(frame.hdr_tuples))
                self._clear_read_timeout(exchange)
                if frame.flags == Flags.FLAG_FIN:
                    exchange._res_state = ExchangeStates.DONE
                    exchange.emit('response_done')
                else:
                    self._set_read_timeout(exchange, 'body')
                    
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
        exchange.emit('error', error.RstStreamError(
            'Status code %s' % StatusCodes.str[frame.status]))
        
    def _frame_syn_reply(self, frame):
        exchange = self._exchange_or_die(frame.stream_id)
        if exchange:
            if exchange._pushed:
                self._handle_error(error.ProtocolError(
                    'SYN_REPLY frame received on server pushed stream.'),
                    StatusCodes.PROTOCOL_ERROR, frame.stream_id)
            elif exchange._res_state == ExchangeStates.DONE:
                # See handling for FrameTypes.DATA
                self._handle_error(error.ProtocolError(
                    'SYN_REPLY frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            elif exchange._res_state == ExchangeStates.STARTED:
                """
                If an endpoint receives multiple SYN_REPLY frames for the same 
                active stream ID, it MUST issue a stream error with the error 
                code STREAM_IN_USE.
                """
                self._handle_error(error.ProtocolError(
                    'Duplicate SYN_REPLY frame received.'),
                    StatusCodes.STREAM_IN_USE, frame.stream_id)
            else:
                err = self._header_error(frame.hdr_tuples, response_hdrs)
                if err:
                    """
                    If a client receives a SYN_REPLY without a status or 
                    without a version header, the client must reply with a 
                    RST_STREAM frame indicating a PROTOCOL ERROR.
                    """
                    self._handle_error(err, 
                        StatusCodes.PROTOCOL_ERROR, frame.stream_id)
                else:
                    exchange.emit('response_start', header_dict(frame.hdr_tuples))
                    self._clear_read_timeout(exchange)
                    if frame.flags == Flags.FLAG_FIN:
                        exchange._res_state = ExchangeStates.DONE
                        exchange.emit('response_done')
                    else:
                        exchange._res_state = ExchangeStates.STARTED
                        self._set_read_timeout(exchange, 'body')
        
#-------------------------------------------------------------------------------

# TODO: proxy support
# TODO: implement connect retry? 

class SpdyClient(EventEmitter):
    """
    An asynchronous SPDY client.
    """
    tcp_client_class = TcpClient
    tls_client_class = TlsClient
    spdy_session_class = SpdyClientSession
    
    def __init__(self, 
            connect_timeout=None, # seconds to wait for connect until throwing error
            read_timeout=None, # seconds to wait for a response to request from server
            idle_timeout=None, # seconds a conn is kept open until a frame is received
            tls_config=None,
            loop=None):
        EventEmitter.__init__(self)
        self._connect_timeout = connect_timeout if int(connect_timeout or 0) > 0 else None
        self._read_timeout = read_timeout if int(read_timeout or 0) > 0 else None
        self._idle_timeout = idle_timeout if int(idle_timeout or 0) > 0 else None
        self._tls_config = tls_config
        self._sessions = dict()
        self._loop = loop or global_loop
        self._loop.on('stop', self.shutdown)

    def session(self, origin):
        """
        Find an idle connection for (host, port), or create a new one.
        """
        session = self._sessions.get(origin, None)
        if not session or not session.is_active:
            session = self.spdy_session_class(self)
            if self._tls_config is None:
                tcp_client = self.tcp_client_class(self._loop)
            else:
                tcp_client = self.tls_client_class(self._tls_config, self._loop)
            tcp_client.on('connect', session._bind)
            tcp_client.on('connect_error', session._handle_connect_error)
            (host, port) = origin # FIXME: add scheme?
            tcp_client.connect(host, port, self._connect_timeout)
            self._sessions[origin] = session
        return session
        
    def _remove_session(self, session):
        """
        Removes (closed) session from dictionary.
        """
        try:
            if self._sessions[session._origin] == session:
                del self._sessions[session._origin]
        except KeyError:
            pass
            
    def shutdown(self):
        """
        Close all SPDY sessions.
        """
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()
        
#-------------------------------------------------------------------------------            

if __name__ == "__main__":
    pass
