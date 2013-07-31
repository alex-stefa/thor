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
    
req_remove_hdrs = invalid_hdrs + request_hdrs

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
            idle_timeout=None, 
            loop=None, 
            spdy_session_class=SpdyClientSession, 
            tcp_client_class=TcpClient):
        EventEmitter.__init__(self)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._idle_timeout = idle_timeout
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
            tcp_client.on('connect', session._bind)
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

class SpdyClientExchange(SpdyExchange):
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

class SpdyClientSession(SpdySession):
    """
    A SPDY connection to a server.
    """
    def __init__(self, client, origin):
        SpdySession.__init__(self, True, client._idle_timeout)
        self.client = client
        self.origin = origin # (host, port)
        self._read_timeout = client._read_timeout
        self._output_buffer = list()

    ### "Public" methods
    
    def close(self, reason=GoawayReasons.OK):
        SpdySession.close(self, reason)
        self.client._remove_session(self)

    ### Exchange request methods
                
    def _ensure_can_init(self, exchange):
        if exchage._pushed:
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
                    
    ### Output-related methods called by common.SpdyMessageHandler

    def _queue_frame(self, priority, frame):
        self._clear_idle_timeout()
        self._set_idle_timeout()
        self._output(frame.serialize(self))

    def _output(self, chunk):
        self._output_buffer.append(chunk)
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.write(''.join(self._output_buffer))
            self._output_buffer = []

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

    def _set_read_timeout(self, entity, kind):
        """
        Set the read timeout associated to entity.
        """
        if self._read_timeout and entity._read_timeout_ev is None:
            entity._read_timeout_ev = self.client._loop.schedule(
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
    
    ### Frame handling methods called by common.SpdyMessageHandler
    
    def _handle_frame(self, frame):
        SpdySession._handle_frame(self, frame)
        
        if frame.type == FrameTypes.DATA:
            exchange = self._exchange_or_die(frame.stream_id)
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
            
        elif frame.type == FrameTypes.SYN_STREAM:
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
                    self.server.emit('exchange', exchange)
                    exchange.emit('error', err)
                    exchange.response_start(None, "400 Bad Request", done=True)
                    # TODO: exchange._req_state = ExchangeStates.DONE ?
                else:
                    self.server.emit('exchange', exchange)
                    exchange.emit('request_start', hdr_dict(frame.hdr_tuples))
                    if frame.flags == Flags.FLAG_FIN:
                        exchange._req_state = ExchangeStates.DONE
                        exchange.emit('request_done')
                    elif frame.flags == Flags.FLAG_UNIDIRECTIONAL:
                        exchange.emit('error', error.ProtocolError(
                            'Client set FLAG_UNIDIRECTIONAL in SYN_STREAM.'))
                    
        elif frame.type == FrameTypes.HEADERS:
            # TODO: "If the server sends a HEADER frame containing duplicate headers with a previous HEADERS frame for the same stream, the client must issue a stream error (Section 2.4.2) with error code PROTOCOL ERROR."
            # TODO: "If the server sends a HEADERS frame after sending a data frame for the same stream, the client MAY ignore the HEADERS frame. Ignoring the HEADERS frame after a data frame prevents handling of HTTP's trailing headers."
            exchange = self._exchange_or_die(frame.stream_id)
            if exchange._req_state != ExchangeStates.STARTED:
                # See handling for FrameTypes.DATA
                self._handle_error(error.ProtocolError(
                    'HEADERS frame received on closed stream.'),
                    StatusCodes.STREAM_ALREADY_CLOSED, frame.stream_id)
            else:
                exchange.emit('request_headers', hdr_dict(frame.hdr_tuples))
                if frame.flags == Flags.FLAG_FIN:
                    exchange._req_state = ExchangeStates.DONE
                    exchange.emit('request_done')
                    
        elif frame.type == FrameTypes.RST_STREAM:
            """
            After receiving a RST_STREAM on a stream, the recipient must not 
            send additional frames for that stream, and the stream moves into 
            the closed state.
            """
            try:
                exchange = self.exchanges[frame.stream_id]
                self._close_exchg(exchange)
                exchange.emit('error', error.RstStreamError(
                    StatusCodes.str[frame.status]))
            else:
                self.emit('error', error.ProtocolError(
                    'Server received RST_STREAM for unknown stream with ID %d' %
                    frame.stream_id))
                # FIXME: should the session be terminated in this case?
        
        elif frame.type == FrameTypes.SYN_REPLY:
            # clients should never be sending SYN_REPLY
            self.emit('error', error.ProtocolError(
                'Server received SYN_REPLY from client with stream ID %d.' %
                frame.stream_id))
        
    
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
