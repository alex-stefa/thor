#!/usr/bin/env python

"""
shared SPDY infrastructure

This module contains utility functions for nbhttp and a base class
for the SPDY-specific portions of the client and server.
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

import struct
import c_zlib


compressed_hdrs = True
dictionary = \
	"\x00\x00\x00\x07\x6f\x70\x74\x69\x6f\x6e\x73\x00\x00\x00\x04\x68" \
	"\x65\x61\x64\x00\x00\x00\x04\x70\x6f\x73\x74\x00\x00\x00\x03\x70" \
	"\x75\x74\x00\x00\x00\x06\x64\x65\x6c\x65\x74\x65\x00\x00\x00\x05" \
	"\x74\x72\x61\x63\x65\x00\x00\x00\x06\x61\x63\x63\x65\x70\x74\x00" \
	"\x00\x00\x0e\x61\x63\x63\x65\x70\x74\x2d\x63\x68\x61\x72\x73\x65" \
	"\x74\x00\x00\x00\x0f\x61\x63\x63\x65\x70\x74\x2d\x65\x6e\x63\x6f" \
	"\x64\x69\x6e\x67\x00\x00\x00\x0f\x61\x63\x63\x65\x70\x74\x2d\x6c" \
	"\x61\x6e\x67\x75\x61\x67\x65\x00\x00\x00\x0d\x61\x63\x63\x65\x70" \
	"\x74\x2d\x72\x61\x6e\x67\x65\x73\x00\x00\x00\x03\x61\x67\x65\x00" \
	"\x00\x00\x05\x61\x6c\x6c\x6f\x77\x00\x00\x00\x0d\x61\x75\x74\x68" \
	"\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e\x00\x00\x00\x0d\x63\x61\x63" \
	"\x68\x65\x2d\x63\x6f\x6e\x74\x72\x6f\x6c\x00\x00\x00\x0a\x63\x6f" \
	"\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x00\x00\x00\x0c\x63\x6f\x6e\x74" \
	"\x65\x6e\x74\x2d\x62\x61\x73\x65\x00\x00\x00\x10\x63\x6f\x6e\x74" \
	"\x65\x6e\x74\x2d\x65\x6e\x63\x6f\x64\x69\x6e\x67\x00\x00\x00\x10" \
	"\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x61\x6e\x67\x75\x61\x67\x65" \
	"\x00\x00\x00\x0e\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67" \
	"\x74\x68\x00\x00\x00\x10\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x6f" \
	"\x63\x61\x74\x69\x6f\x6e\x00\x00\x00\x0b\x63\x6f\x6e\x74\x65\x6e" \
	"\x74\x2d\x6d\x64\x35\x00\x00\x00\x0d\x63\x6f\x6e\x74\x65\x6e\x74" \
	"\x2d\x72\x61\x6e\x67\x65\x00\x00\x00\x0c\x63\x6f\x6e\x74\x65\x6e" \
	"\x74\x2d\x74\x79\x70\x65\x00\x00\x00\x04\x64\x61\x74\x65\x00\x00" \
	"\x00\x04\x65\x74\x61\x67\x00\x00\x00\x06\x65\x78\x70\x65\x63\x74" \
	"\x00\x00\x00\x07\x65\x78\x70\x69\x72\x65\x73\x00\x00\x00\x04\x66" \
	"\x72\x6f\x6d\x00\x00\x00\x04\x68\x6f\x73\x74\x00\x00\x00\x08\x69" \
	"\x66\x2d\x6d\x61\x74\x63\x68\x00\x00\x00\x11\x69\x66\x2d\x6d\x6f" \
	"\x64\x69\x66\x69\x65\x64\x2d\x73\x69\x6e\x63\x65\x00\x00\x00\x0d" \
	"\x69\x66\x2d\x6e\x6f\x6e\x65\x2d\x6d\x61\x74\x63\x68\x00\x00\x00" \
	"\x08\x69\x66\x2d\x72\x61\x6e\x67\x65\x00\x00\x00\x13\x69\x66\x2d" \
	"\x75\x6e\x6d\x6f\x64\x69\x66\x69\x65\x64\x2d\x73\x69\x6e\x63\x65" \
	"\x00\x00\x00\x0d\x6c\x61\x73\x74\x2d\x6d\x6f\x64\x69\x66\x69\x65" \
	"\x64\x00\x00\x00\x08\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x00\x00\x00" \
	"\x0c\x6d\x61\x78\x2d\x66\x6f\x72\x77\x61\x72\x64\x73\x00\x00\x00" \
	"\x06\x70\x72\x61\x67\x6d\x61\x00\x00\x00\x12\x70\x72\x6f\x78\x79" \
	"\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x00\x00\x00" \
	"\x13\x70\x72\x6f\x78\x79\x2d\x61\x75\x74\x68\x6f\x72\x69\x7a\x61" \
	"\x74\x69\x6f\x6e\x00\x00\x00\x05\x72\x61\x6e\x67\x65\x00\x00\x00" \
	"\x07\x72\x65\x66\x65\x72\x65\x72\x00\x00\x00\x0b\x72\x65\x74\x72" \
	"\x79\x2d\x61\x66\x74\x65\x72\x00\x00\x00\x06\x73\x65\x72\x76\x65" \
	"\x72\x00\x00\x00\x02\x74\x65\x00\x00\x00\x07\x74\x72\x61\x69\x6c" \
	"\x65\x72\x00\x00\x00\x11\x74\x72\x61\x6e\x73\x66\x65\x72\x2d\x65" \
	"\x6e\x63\x6f\x64\x69\x6e\x67\x00\x00\x00\x07\x75\x70\x67\x72\x61" \
	"\x64\x65\x00\x00\x00\x0a\x75\x73\x65\x72\x2d\x61\x67\x65\x6e\x74" \
	"\x00\x00\x00\x04\x76\x61\x72\x79\x00\x00\x00\x03\x76\x69\x61\x00" \
	"\x00\x00\x07\x77\x61\x72\x6e\x69\x6e\x67\x00\x00\x00\x10\x77\x77" \
	"\x77\x2d\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x00\x00" \
	"\x00\x06\x6d\x65\x74\x68\x6f\x64\x00\x00\x00\x03\x67\x65\x74\x00" \
	"\x00\x00\x06\x73\x74\x61\x74\x75\x73\x00\x00\x00\x06\x32\x30\x30" \
	"\x20\x4f\x4b\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x00\x00" \
	"\x00\x08\x48\x54\x54\x50\x2f\x31\x2e\x31\x00\x00\x00\x03\x75\x72" \
	"\x6c\x00\x00\x00\x06\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x0a\x73" \
	"\x65\x74\x2d\x63\x6f\x6f\x6b\x69\x65\x00\x00\x00\x0a\x6b\x65\x65" \
	"\x70\x2d\x61\x6c\x69\x76\x65\x00\x00\x00\x06\x6f\x72\x69\x67\x69" \
	"\x6e\x31\x30\x30\x31\x30\x31\x32\x30\x31\x32\x30\x32\x32\x30\x35" \
	"\x32\x30\x36\x33\x30\x30\x33\x30\x32\x33\x30\x33\x33\x30\x34\x33" \
	"\x30\x35\x33\x30\x36\x33\x30\x37\x34\x30\x32\x34\x30\x35\x34\x30" \
	"\x36\x34\x30\x37\x34\x30\x38\x34\x30\x39\x34\x31\x30\x34\x31\x31" \
	"\x34\x31\x32\x34\x31\x33\x34\x31\x34\x34\x31\x35\x34\x31\x36\x34" \
	"\x31\x37\x35\x30\x32\x35\x30\x34\x35\x30\x35\x32\x30\x33\x20\x4e" \
	"\x6f\x6e\x2d\x41\x75\x74\x68\x6f\x72\x69\x74\x61\x74\x69\x76\x65" \
	"\x20\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x32\x30\x34\x20" \
	"\x4e\x6f\x20\x43\x6f\x6e\x74\x65\x6e\x74\x33\x30\x31\x20\x4d\x6f" \
	"\x76\x65\x64\x20\x50\x65\x72\x6d\x61\x6e\x65\x6e\x74\x6c\x79\x34" \
	"\x30\x30\x20\x42\x61\x64\x20\x52\x65\x71\x75\x65\x73\x74\x34\x30" \
	"\x31\x20\x55\x6e\x61\x75\x74\x68\x6f\x72\x69\x7a\x65\x64\x34\x30" \
	"\x33\x20\x46\x6f\x72\x62\x69\x64\x64\x65\x6e\x34\x30\x34\x20\x4e" \
	"\x6f\x74\x20\x46\x6f\x75\x6e\x64\x35\x30\x30\x20\x49\x6e\x74\x65" \
	"\x72\x6e\x61\x6c\x20\x53\x65\x72\x76\x65\x72\x20\x45\x72\x72\x6f" \
	"\x72\x35\x30\x31\x20\x4e\x6f\x74\x20\x49\x6d\x70\x6c\x65\x6d\x65" \
	"\x6e\x74\x65\x64\x35\x30\x33\x20\x53\x65\x72\x76\x69\x63\x65\x20" \
	"\x55\x6e\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x4a\x61\x6e\x20\x46" \
	"\x65\x62\x20\x4d\x61\x72\x20\x41\x70\x72\x20\x4d\x61\x79\x20\x4a" \
	"\x75\x6e\x20\x4a\x75\x6c\x20\x41\x75\x67\x20\x53\x65\x70\x74\x20" \
	"\x4f\x63\x74\x20\x4e\x6f\x76\x20\x44\x65\x63\x20\x30\x30\x3a\x30" \
	"\x30\x3a\x30\x30\x20\x4d\x6f\x6e\x2c\x20\x54\x75\x65\x2c\x20\x57" \
	"\x65\x64\x2c\x20\x54\x68\x75\x2c\x20\x46\x72\x69\x2c\x20\x53\x61" \
	"\x74\x2c\x20\x53\x75\x6e\x2c\x20\x47\x4d\x54\x63\x68\x75\x6e\x6b" \
	"\x65\x64\x2c\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x2c\x69\x6d\x61" \
	"\x67\x65\x2f\x70\x6e\x67\x2c\x69\x6d\x61\x67\x65\x2f\x6a\x70\x67" \
	"\x2c\x69\x6d\x61\x67\x65\x2f\x67\x69\x66\x2c\x61\x70\x70\x6c\x69" \
	"\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69" \
	"\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b\x78\x6d\x6c" \
	"\x2c\x74\x65\x78\x74\x2f\x70\x6c\x61\x69\x6e\x2c\x74\x65\x78\x74" \
	"\x2f\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x2c\x70\x75\x62\x6c" \
	"\x69\x63\x70\x72\x69\x76\x61\x74\x65\x6d\x61\x78\x2d\x61\x67\x65" \
	"\x3d\x67\x7a\x69\x70\x2c\x64\x65\x66\x6c\x61\x74\x65\x2c\x73\x64" \
	"\x63\x68\x63\x68\x61\x72\x73\x65\x74\x3d\x75\x74\x66\x2d\x38\x63" \
	"\x68\x61\x72\x73\x65\x74\x3d\x69\x73\x6f\x2d\x38\x38\x35\x39\x2d" \
	"\x31\x2c\x75\x74\x66\x2d\x2c\x2a\x2c\x65\x6e\x71\x3d\x30\x2e"      

def dummy(*args, **kw):
    "Dummy method that does nothing; useful to ignore a callback."
    pass

# see http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['str'] = reverse
    return type('Enum', (), enums)
    
InputStates = enum('WAITING', 'READING_FRAME_DATA')

ExchangeStates = enum('REQ_WAITING', 'REQ_STARTED', 'REQ_DONE', 
    'RES_STARTED', 'RES_DONE')

StreamStates = enum('OPEN', 'REMOTE_CLOSED', 'REPLIED', 'LOCAL_CLOSED', 'ERROR')
# TODO: review spdy/3 spec

Flags = enum(FLAG_NONE = 0x00, FLAG_FIN = 0x01, FLAG_UNIDIRECTIONAL = 0x02)

FrameTypes = enum(
    DATA = 0x00,
    SYN_STREAM = 0x01,
    SYN_REPLY = 0x02,
    RST_STREAM = 0x03,
    SETTINGS = 0x04,
    PING = 0x06,
    GOAWAY = 0x07,
    HEADERS = 0x08,
    WINDOW_UPDATE = 0x09,
    CREDENTIAL = 0x10
)


WAITING, READING_FRAME_DATA = 1, 2

# frame types
DATA_FRAME = 0x00
# Control frame, version number is 2.
CTL_FRM = 0x8002
CTL_SYN_STREAM = 0x01
CTL_SYN_REPLY = 0x02
CTL_RST_STREAM = 0x03
CTL_SETTINGS = 0x04
CTL_NOOP = 0x05
CTL_PING = 0x06
CTL_GOAWAY = 0x07

# flags
FLAG_NONE = 0x00
FLAG_FIN = 0x01
FLAG_UNIDIRECTIONAL = 0x02

STREAM_MASK = 0x7fffffff

invalid_hdrs = ['connection', 'keep-alive', 'proxy-authenticate',
                   'proxy-authorization', 'te', 'trailers',
                   'transfer-encoding', 'upgrade', 'proxy-connection']
                   
#-------------------------------------------------------------------------------

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
        out[n].extend([i.strip() for i in v.split(',')])
    return out

def get_header(hdr_tuples, name):
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
                    [i[1] for i in hdr_tuples if i[0].lower() == name]
               ]
            , [])
    ]
    
#-------------------------------------------------------------------------------

class SpdyStream:
    
    def __init__(self, stream_id, send_hdrs, recv_hdrs, 
            stream_assoc_id=None, priority=0, pushed=False):
        self.timestamp = time()
        self.stream_id = stream_id
        self.stream_assoc_id = stream_assoc_id
        self.send_hdrs = send_hdrs # dictionary of list values
        self.recv_hdrs = recv_hdrs
        self.state = StreamStates.OPEN
        self.priority = priority # 0 highest to 7 lowest
        self.pushed = pushed # is server pushed?
                
    def __str__(self):
        return ('[#%d A%s P%d %s %s %s %s]' % (
            self.stream_id,
            str(self.stream_assoc_id) if self.stream_assoc_id else '?',
            self.priority,
            StreamStates.str[self.state],
            strftime('%H:%M:%S', gmtime(self.timestamp))
        ))
    
#-------------------------------------------------------------------------------
    
class SpdyMessageHandler:
    """
    This is a base class for something that has to parse and/or serialise
    SPDY messages, request or response.

    For parsing, it expects you to override _input_start, _input_body and
    _input_end, and call _handle_input when you get bytes from the network.

    For serialising, it expects you to override _output.
    """

        
    
    def __init__(self):
        self.log = lambda a:a
        self._input_buffer = ""
        self._input_state = WAITING
        self._input_frame_type = None
        self._input_flags = None
        self._input_stream_id = None
        self._input_frame_len = 0
        if compressed_hdrs:
            self._compress = c_zlib.Compressor(-1, dictionary)
            self._decompress = c_zlib.Decompressor(dictionary)
        else:
            self._compress = dummy
            self._decompress = dummy

    def handle_frame(self, frame):
        raise NotImplementedError
     
    def handle_error(self, err):
        raise NotImplementedError
    
    def handle_pause(session, paused):
        raise NotImplementedError

    ### input-related methods
    
    def _input_start(self, stream_id, hdr_tuples):
        """
        Take the top set of headers from a new request and queue it
        to be processed by the application.
        """
        raise NotImplementedError

    def _input_body(self, stream_id, chunk):
        "Process a body chunk from the wire."
        raise NotImplementedError

    def _input_end(self, stream_id):
        "Indicate that the response body is complete."
        raise NotImplementedError

    def _input_error(self, stream_id, err, detail=None):
        "Indicate a parsing problem with the body."
        raise NotImplementedError

    def _handle_input(self, data):
        """
        Given a chunk of input, figure out what state we're in and handle it,
        making the appropriate calls.
        """
        # TODO: look into reading/writing directly from the socket buffer with struct.pack_into / unpack_from.
        if self._input_buffer != "":
            data = self._input_buffer + data # will need to move to a list if writev comes around
            self._input_buffer = ""
        if self._input_state == WAITING: # waiting for a complete frame header
            if len(data) >= 8:
                (d1, self._input_flags, d2, d3) = struct.unpack("!IBBH", data[:8])
                if d1 >> 31 & 0x01: # control frame
                    version = ( d1 >> 16 ) & 0x7fff # TODO: check version
                    # FIXME: we use 0x00 internally to indicate data frame
                    self._input_frame_type = d1 & 0x0000ffff
                    self._input_stream_id = None
                else: # data frame
                    self._input_frame_type = DATA_FRAME
                    self._input_stream_id = d1 & STREAM_MASK
                self._input_frame_len = (( d2 << 16 ) + d3)
                self._input_state = READING_FRAME_DATA
                self._handle_input(data[8:])
            else:
                self._input_buffer = data
        elif self._input_state == READING_FRAME_DATA:
            if len(data) >= self._input_frame_len:
                frame_data = data[:self._input_frame_len]
                rest = data[self._input_frame_len:]
                if self._input_frame_type == DATA_FRAME:
                    self._input_body(self._input_stream_id, frame_data)
                    stream_id = self._input_stream_id # for FLAG_FIN below
                elif self._input_frame_type in [CTL_SYN_STREAM, CTL_SYN_REPLY]:
                    stream_id = struct.unpack("!I", frame_data[:4])[0] & STREAM_MASK # FIXME: what if they lied about the frame len?
                    tuple_pos = 4 + 2
                    if self._input_frame_type == CTL_SYN_STREAM:
                      associated_stream_id = struct.unpack("!I", frame_data[4:8])[0]
                      tuple_pos += 4
                    hdr_tuples = self._parse_hdrs(frame_data[tuple_pos:]) or self._input_error(stream_id, 1) # FIXME: proper error here
                    # FIXME: expose pri
                    self._input_start(stream_id, hdr_tuples)
                elif self._input_frame_type == CTL_RST_STREAM:
                    stream_id = struct.unpack("!I", frame_data[:4])[0] & STREAM_MASK
                    self._input_end(stream_id)
                elif self._input_frame_type == CTL_SETTINGS:
                    pass # FIXME
                elif self._input_frame_type == CTL_NOOP:
                    pass
                elif self._input_frame_type == CTL_PING:
                    pass # FIXME
                elif self._input_frame_type == CTL_GOAWAY:
                    pass # FIXME
                else: # unknown frame type
                    raise ValueError, "Unknown frame type" # FIXME: don't puke
                if self._input_flags & FLAG_FIN: # FIXME: invalid on CTL_RST_STREAM
                    self._input_end(stream_id)
                self._input_state = WAITING
                if rest:
                    self._handle_input(rest)
            else: # don't have complete frame yet
                self._input_buffer = data
        else:
            raise Exception, "Unknown input state %s" % self._input_state

    def _parse_hdrs(self, data):
        "Given a control frame data block, return a list of (name, value) tuples."
        # TODO: separate null-delimited into separate instances
        data = self._decompress(data) # FIXME: catch errors
        cursor = 2
        (num_hdrs,) = struct.unpack("!h", data[:cursor]) # FIXME: catch errors
        hdrs = []
        while cursor < len(data):
            try:
                (name_len,) = struct.unpack("!h", data[cursor:cursor+2]) # FIXME: catch errors
                cursor += 2
                name = data[cursor:cursor+name_len] # FIXME: catch errors
                cursor += name_len
            except IndexError:
                raise
            except struct.error:
                raise
            try:
                (val_len,) = struct.unpack("!h", data[cursor:cursor+2]) # FIXME: catch errors
                cursor += 2
                value = data[cursor:cursor+val_len] # FIXME: catch errors
                cursor += val_len
            except IndexError:
                raise
            except struct.error:
                print len(data), cursor, data # FIXME
                raise
            hdrs.append((name, value))
        return hdrs

    ### output-related methods

    def _output(self, out):
        raise NotImplementedError

    def _handle_error(self, err):
        raise NotImplementedError

    def _ser_syn_frame(self, type, flags, stream_id, hdr_tuples):
        "Returns a SPDY SYN_[STREAM|REPLY] frame."
        hdrs = self._compress(self._ser_hdrs(hdr_tuples))
        if (type == CTL_SYN_STREAM):
          data = struct.pack("!IIH%ds" % len(hdrs),
              STREAM_MASK & stream_id,
              0x00,  # associated stream id
              0x00,  # unused
              hdrs
           )
        else:
          data = struct.pack("!IH%ds" % len(hdrs),
              STREAM_MASK & stream_id,
              0x00,  # unused
              hdrs
          )
        return self._ser_ctl_frame(type, flags, data)

    @staticmethod
    def _ser_ctl_frame(type, flags, data):
        "Returns a SPDY control frame."
        # TODO: check that data len doesn't overflow
        return struct.pack("!HHI%ds" % len(data),
            CTL_FRM,
            type,
            (flags << 24) + len(data),
            data
        )

    @staticmethod
    def _ser_data_frame(stream_id, flags, data):
        "Returns a SPDY data frame."
        # TODO: check that stream_id and data len don't overflow
        return struct.pack("!II%ds" % len(data),
            STREAM_MASK & stream_id,
            (flags << 24) + len(data),
            data
        )

    @staticmethod
    def _ser_hdrs(hdr_tuples):
        "Returns a SPDY header block from a list of (name, value) tuples."
        # TODO: collapse dups into null-delimited
        hdr_tuples.sort() # required by Chromium
        fmt = ["!H"]
        args = [len(hdr_tuples)]
        for (n,v) in hdr_tuples:
            # TODO: check for overflowing n, v lengths
            fmt.append("H%dsH%ds" % (len(n), len(v)))
            args.extend([len(n), n, len(v), v])
        return struct.pack("".join(fmt), *args)
