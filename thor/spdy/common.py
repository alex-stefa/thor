#!/usr/bin/env python

"""
Shared SPDY infrastructure

This module contains utility functions for thor and a base class
for the SPDY-specific portions of the client and server.
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

import time
from urlparse import urlunsplit
from collections import defaultdict

import thor
from thor.spdy import error
from thor.spdy.frames import *

#-------------------------------------------------------------------------------

invalid_hdrs = ['connection', 'keep-alive', 'proxy-authenticate',
                   'proxy-authorization', 'te', 'trailers',
                   'transfer-encoding', 'upgrade', 'proxy-connection']
request_hdrs = [':method', ':version', ':scheme', ':host', ':path']
response_hdrs = [':status', ':version']
response_pushed_hdrs = [':scheme', ':host', ':path']

def header_names(hdr_tuples):
    """
    Given a list of header tuples, return the set of the header names seen.
    """
    return set([n.lower() for n, v in hdr_tuples])

def header_dict(hdr_tuples, omit=None):
    """
    Given a list of header tuples, return a dictionary keyed upon the
    lower-cased header names.

    If omit is defined, each header listed (by lower-cased name) will not be
    returned in the dictionary.
    """
    out = defaultdict(list)
    for (n, v) in hdr_tuples:
        n = n.lower()
        if n in (omit or []):
            continue
        # out[n].extend([i.strip() for i in v.split(',')]) # FIXME: do we want this?
        out[n].append(v.strip())
    return HeaderDict(out)

def get_header(hdr_tuples, name):
    """
    Given a list of header tuples, returns a list of the tuples with 
    the given name (lowercase).
    """
    return [i for i in hdr_tuples if i[0].lower() == name]
    
def get_values(hdr_tuples, name):
    """
    Given a list of (name, value) header tuples and a header name (lowercase),
    return a list of all values for that header.

    This includes header lines with multiple values separated by a comma;
    such headers will be split into separate values. As a result, it is NOT
    safe to use this on headers whose values may include a comma (e.g.,
    Set-Cookie, or any value with a quoted string).
    """
    # TODO: support quoted strings
    return [v.strip() for v in sum(
               [l.split(',') for l in
                    [i[1] for i in hdr_tuples if i[0].lower() == name]], []) 
            if len(v) > 0]

def collapse_dups(hdr_tuples):
    """
    Given a list of header tuples, collapses values for identical header names
    into a single string separated by nulls.
    """
    d = defaultdict(list)
    for (n, v) in hdr_tuples:
        d[n].extend([v])
    return [(n, '\x00'.join(v)) for (n, v) in d.items()]
    
def expand_dups(hdr_tuples):
    """
    Given a list of header tuples, unpacks multiple null separated values
    for the same header name.
    """
    out_tuples = list()
    for (n, v) in hdr_tuples:
        for val in v.split('\x00'):
            if len(val) > 0:
                out_tuples.append((n, val))
    return out_tuples
    
def clean_headers(hdr_tuples, invalid_hdrs):
    """
    Given a list of header tuples, filters out tuples with empty header names
    or in the specified invalid header names list.
    """
    if hdr_tuples is None:
        return list()
    clean_tuples = list()
    for entry in hdr_tuples:
        if not entry[0]:
            continue
        name = entry[0].strip().lower()
        value = entry[1] if entry[1] else ''
        if name not in invalid_hdrs:
            clean_tuples.append((name, value))
    return clean_tuples
    
class HeaderDict(dict):
    """
    Standard dict() with additional helper methods for headers.
    """
    @property
    def method(self):
        try:
            return self[':method'][-1]
        except:
            return None
    @property
    def path(self):
        try:
            return self[':path'][-1]
        except:
            return None
    @property
    def host(self):
        try:
            return self[':host'][-1]
        except:
            return None
    @property
    def version(self):
        try:
            return self[':version'][-1]
        except:
            return None
    @property
    def scheme(self):
        try:
            return self[':scheme'][-1]
        except:
            return None
    @property
    def uri(self):
        return urlunsplit((self.scheme, self.host, self.path, '', ''))
    @property
    def status(self):
        try:
            status = self[':status'][-1]
        except:
            return (None, None)
        try:
            code, phrase = status.split(None, 1)
        except ValueError:
            code = status.rstrip()
            phrase = ''
        return (code, phrase)
    # TODO: ensure there is at most one header value

#-------------------------------------------------------------------------------

ExchangeStates = enum('WAITING', 'STARTED', 'DONE')
# FIXME: do we need an ERROR state?

class SpdyExchange(EventEmitter):
    """
    Holds information about a SPDY request-response exchange (a SPDY stream).
    """
    def __init__(self):
        EventEmitter.__init__(self)
        self.session = None
        self.timestamp = time.time()
        self.stream_id = None
        self.priority = Priority.MIN
        self._stream_assoc_id = None
        self._req_state = ExchangeStates.WAITING
        self._res_state = ExchangeStates.WAITING
        self._pushed = False # is it a server pushed stream?
                
    def __str__(self):
        return ('[STREAM ID%s AID%s P%d %s REQ_%s RES_%s %s]' % (
            str(self.stream_id) if self.stream_id else '?',
            str(self._stream_assoc_id) if self._stream_assoc_id else '?',
            self.priority,
            'PUSHED' if self._pushed else '',
            ExchangeStates.str[self._req_state],
            ExchangeStates.str[self._res_state],
            time.strftime('%H:%M:%S', time.gmtime(self.timestamp))
        ))
    
    @property
    def is_active(self):
        return (self._req_state != ExchangeStates.DONE or
                self._res_state != ExchangeStates.DONE)
  
#-------------------------------------------------------------------------------

class PingTimer(EventEmitter):
    """
    Allows measurement of round-trip time (RTT) between endpoints.
    
    Event handlers that can be added:
        timeout()
        pong(rtt) -- RTT in seconds
    """
    def __init__(self, session, ping_timeout):
        EventEmitter.__init__(self)
        self._session = session
        self._ping_timeout = ping_timeout
        self._ping_timeout_ev = None
        self._ping_id = None
        self._ping_timestamp = None
        self._pong_timestamp = None
        self._is_active = False
        
    @property
    def is_active(self):
        return self._is_active

    def ping(self):
        self._session._send_ping(self)
        
    def cancel(self):
        self._session._notify_ping(self._ping_id, cancel=True)

#-------------------------------------------------------------------------------

class SpdySession(SpdyMessageHandler, EventEmitter):
    """
    A generic SPDY connection, contains common functionality for 
    client and server sides.
    
    Event handlers that can be added:
        bound(tcp_conn)
        frame(frame)
        goaway(reason, last_stream_id)
        pause(paused)
        error(err)
        close()
    """
    def __init__(self, is_client, idle_timeout=None):
        SpdyMessageHandler.__init__(self)
        EventEmitter.__init__(self)
        self.exchanges = dict()
        self.tcp_conn = None
        self._idle_timeout = idle_timeout
        self._idle_timeout_ev = None
        self._sent_goaway = False
        self._received_goaway = False
        self._pings = dict()
        if is_client:
            self._highest_created_stream_id = -1
            self._highest_accepted_stream_id = 0
            self._valid_local_stream_id = self._valid_client_stream_id
            self._valid_remote_stream_id = self._valid_server_stream_id
            self._highest_ping_id = -1
        else:
            self._highest_created_stream_id = 0
            self._highest_accepted_stream_id = -1
            self._valid_local_stream_id = self._valid_server_stream_id
            self._valid_remote_stream_id = self._valid_client_stream_id
            self._highest_ping_id = 0
        self.frame_handlers = defaultdict(list)
        self.frame_handlers[FrameTypes.PING] = [self._frame_ping]
        self.frame_handlers[FrameTypes.GOAWAY] = [self._frame_goaway]
        self.frame_handlers[FrameTypes.SETTINGS] = [self._frame_settings]
        self.frame_handlers[FrameTypes.CREDENTIAL] = [self._frame_credential]
        self.frame_handlers[FrameTypes.WINDOW_UPDATE] = [self._frame_window_update]
        
    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.tcp_conn:
            status.append(
              self.tcp_conn.tcp_connected and 'connected' or 'disconnected')
        return "<%s at %#x>" % (", ".join(status), id(self))
        
    ### Output methods to be implemented by inheriting classes

    def _queue_frame(self, priority, frame):
        raise NotImplementedError
        
    def _output(self, chunk):
        raise NotImplementedError

    ### "Public" methods
    
    @property
    def is_active(self):
        """
        Session alive or not.
        """
        return self.tcp_conn is not None
    
    def ping_timer(self, ping_timeout=None):
        """
        Returns a PingTimer instance useful to measure round-trip times.
        """
        return PingTimer(self, ping_timeout)
    
    def pause_input(self, paused):
        """
        Temporarily stop / restart receiving input from remote side.
        """
        if self.tcp_conn and self.tcp_conn.tcp_connected:
            self.tcp_conn.pause(paused)
            
    def goaway(self, reason=GoawayReasons.OK):
        """
        Sends a GOAWAY frame to tell remote endpoint that new streams will no
        longer be accepted.
        """
        self._sent_goaway = True
        if reason is not None:
            self._queue_frame(
                Priority.MAX,
                GoawayFrame(max(self._highest_accepted_stream_id, 0), reason))
        
    def close(self, reason=GoawayReasons.OK):
        """
        Tear down the SPDY session for given reason.
        """
        if not self.is_active:
            return
        self._sent_goaway = True
        if reason is not None:
            self._queue_frame(
                Priority.MAX,
                GoawayFrame(max(self._highest_accepted_stream_id, 0), reason))
        self._clear_idle_timeout()
        self._close_active_exchanges(error.ConnectionClosedError(
                'Local endpoint has closed the connection.'))
        if self.tcp_conn:
            self.tcp_conn.close()
            self.tcp_conn = None
        self.emit('close')

    ### TCP handling methods
        
    def _bind(self, tcp_conn):
        """
        Binds the session to a TCP connection; should be called only once.
        """
        self.tcp_conn = tcp_conn
        self.tcp_conn.on('data', self._handle_input)
        self.tcp_conn.on('close', self._handle_closed)
        self.tcp_conn.on('pause', self._handle_pause)
        seld._clear_idle_timeout()
        self._set_idle_timeout()
        self._output('') # kick the output buffer
        # FIXME: is the above call necessary and should we wait for when we need to send data first?
        self.tcp_conn.pause(False)
        self.emit('bound', tcp_conn)
    
    def _handle_closed(self):
        """
        The remote side closed the connection.
        """
        if self._input_buffer:
            self._handle_input('')
        self._handle_error(error.ConnectionClosedError(
            'Remote endpoint has closed the connection.'))
        # TODO: what if conn closed while in the middle of reading frame data?
        
   def _handle_pause(self, paused):
        """
        The application has requested to pause/unpause sending data. 
        Should be overrided by inheriting classes so that it actually 
        pauses output.
        """
        self.emit('pause', paused)
        for (stream_id, exchange) in self.exchanges.items():
            if exchange.is_active:
                exchange.emit('pause', paused)
    
    ### Error handler method called by frames.SpdyMessageHandler
         
    def _handle_error(self, err, status=None, stream_id=None, fatal=True):
        """
        Properly handle a SPDY stream-level error with given @status code
        for @stream_id, or a session-level error if @stream_id is None.
        """
        if stream_id is None: # session error
            if err is not None:
                self.emit('error', err)
            if fatal:
                self._close_active_exchanges(err)
                self._close(status)
        else: # stream error
            try:
                exchange = self.exchanges[stream_id]
            except:
                exchange = None
            if exchange is not None:
                if err is not None:
                    exchange.emit('error', err)
                if fatal:
                    self._close_exchange(exchange, status)
            else:
                if err is not None:
                    self.emit('error', err)
                if status is not None:
                    self._queue_frame(
                        Priority.MAX,
                        RstStreamFrame(exchange.stream_id, status))
            
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
                self._close_exchange(exchange, None)
                if err is not None:
                    exchange.emit('error', err)

    ### Ping methods

    def _send_ping(ping_timer):
        self._highest_ping_id += 2
        self._notify_ping(ping_timer._ping_id, cancel=True)
        ping_timer._ping_id = self._highest_ping_id
        ping_timer._is_active = True
        self._pings[ping_timer._ping_id] = ping_timer
        self._queue_frame(
            Priority.MAX,
            PingFrame(ping_timer._ping_id))
        ping_timer._ping_timestamp = time.time()
        ping_timer._pong_timestamp = None
        if ping_timer._ping_timeout and ping_timer._ping_timeout_ev is None:
            ping_timer._ping_timeout_ev = thor.schedule(
                ping_timer._ping_timeout,
                self._notify_ping, ping_timer._ping_id, False, False)
    
    def _notify_ping(ping_id, success=True, cancel=False):
        if ping_id is None:
            return
        try:
            ping_timer = self._pings[ping_id]
        except:
            """
            If a server receives an even numbered PING which it did not 
            initiate, it must ignore the PING. If a client receives an odd 
            numbered PING which it did not initiate, it must ignore the PING.
            """
            self.emit('error', error.PingError(
                'Duplicate or invalid reply to ping ID %d' % ping_id))
            return
        del self._pings[ping_id]
        ping_timer._is_active = False
        if ping_timer._ping_timeout_ev:
            ping_timer._ping_timeout_ev.delete()
            ping_timer._ping_timeout_ev = None
        if not cancel:
            if success:
                ping_timer._pong_timestamp = time.time()
                ping_timer.emit('pong', 
                    ping_timer._pong_timestamp - ping_timer._sent_timestamp)
            else:
                ping_timer.emit('timeout')
    
    ### Timeouts
    
    def _set_idle_timeout(self):
        """
        Set the session idle timeout.
        """
        if self._idle_timeout and self._idle_timeout_ev is None:
            self._idle_timeout_ev = thor.schedule(
                self._idle_timeout,
                self._handle_error,
                error.IdleTimeoutError('No frame received for %d seconds.' 
                    % self._idle_timeout),
                GoawayReasons.OK)
    
    def _clear_idle_timeout(self):
        """
        Clear the session idle timeout.
        """
        if self._idle_timeout_ev:
            self._idle_timeout_ev.delete()
            self._idle_timeout_ev = None

    ### Helper methods
    
    def _next_created_stream_id(self):
        self._highest_created_stream_id += 2
        if self._highest_created_stream_id > STREAM_MASK:
            raise ValueError('Next stream ID is larger than 31 bits.')
        return self._highest_created_stream_id

    def _valid_server_stream_id(self, stream_id):
        """
        If the server is initiating the stream, the Stream-ID must be even.
        """
        if stream_id % 2 == 1:
            self._handle_error(error.StreamIdError(
                'New stream ID %d expected to be even.' %
                stream_id), GoawayReasons.PROTOCOL_ERROR)
            return False
        return True
    
    def _valid_client_stream_id(self, stream_id):
        """
        If the client is initiating the stream, the Stream-ID must be odd.
        """
        if stream_id % 2 == 0:
            self._handle_error(error.StreamIdError(
                'New stream ID %d expected to be odd.' %
                stream_id), GoawayReasons.PROTOCOL_ERROR)
            return False
        return True
        
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
        Check stream-id is odd/even according to which side created it.
        """
        if !self._valid_remote_stream_id(stream_id):
            return False
        return True
       
    def _exchange_or_die(self, stream_id):
        try:
            return self.exchanges[stream_id]
            # TODO: ideally, closed streams should be purged from memory
            # NOTE: returned exchange should be checked if active.
        except:
            """
            If an endpoint receives a data frame for a stream-id which is not 
            open and the endpoint has not sent a GOAWAY (Section 2.6.6) frame,
            it MUST issue a stream error (Section 2.4.2) with the error code
            INVALID_STREAM for the stream-id.
            """
            self.emit('error', error.StreamIdError(
                'Invalid or inactive stream referenced by ID %d.' % stream_id))
            self._queue_frame(
                Priority.MAX,
                RstStreamFrame(stream_id, StatusCodes.INVALID_STREAM))
        return None
       
    def _header_error(self, hdr_tuples, hdr_names):
        """
        Returns error if missing or multiple values for each given header name.
        """
        for hdr_name in hdr_names:
            values = get_header(hdr_tuples, hdr_name)
            if len(values) == 0:
                return error.HeaderError(
                    'Missing %s header.' % hdr_name)
            if len(values) > 1:
                return error.HeaderError(
                    'Multiple %s header values received.' % hdr_name)
        return None

    ### Main frame handling method
    
    def _handle_frame(self, frame):
        self.emit('frame', frame)
        self._clear_idle_timeout()
        self._set_idle_timeout()
        for handler in self.frame_handlers.get(frame.type, []):
            handler(frame)
        
    def _frame_ping(self, frame):
        if (frame.ping_id % 2) != (self._highest_ping_id % 2):
            self._queue_frame(
                Priority.MAX,
                PingFrame(frame.ping_id))
        else:
            self._notify_ping(frame._ping_id, success=True)

    def _frame_goaway(self, frame):
        self._received_goaway = True
        self.emit('goaway', frame.reason, frame.last_stream_id)

    def _frame_settings(self, frame):
        pass
       
    def _frame_credential(self, frame):
        pass
        
    def _frame_window_update(self, frame):
        pass
