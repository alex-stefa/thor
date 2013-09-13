#!/usr/bin/env python

"""
Thor SPDY Errors
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

# TODO: error numbers

# from thor.enum import enum
#
# Errnos = enum(
#     'ESPDY' # Generic SPDY error
# )
# 
# 
# class SpdyError(Exception):
#     desc = 'Unknown Error'
#     _errnos = set([Errnos.ESPDY])
# 
#     def __init__(self, detail=None, errno=Errnos.ESPDY):
#         Exception.__init__(self)
#         self.detail = detail
#         self.errno = errno if errno in self._errnos else Errnos.ESPDY
#         self.strerror = '[%s] %s%s' % (
#             Errnos.str[self.errno],
#             self.desc,
#             (': ' + str(self.detail)) if self.detail else '')
# 
#     def __repr__(self):
#         status = [self.__class__.__module__ + '.' + self.__class__.__name__,
#             self.strerror]
#         return '<%s at %#x>' % (', '.join(status), id(self))
#         
#     def __str__(self):
#         return '[<%s> %s]' % (self.__class__.__name__, self.strerror)
# 
        
class SpdyError(Exception):
    desc = 'Unknown Error'

    def __init__(self, detail=None):
        Exception.__init__(self)
        self.detail = detail
        
    @property
    def strerror(self):
        return '%s%s' % (
            self.desc,
            (': ' + str(self.detail)) if self.detail else '')

    def __repr__(self):
        status = [self.__class__.__module__ + '.' + self.__class__.__name__,
            self.strerror]
        return '<%s at %#x>' % (', '.join(status), id(self))
        
    def __str__(self):
        return '[<%s> %s]' % (self.__class__.__name__, self.strerror)
        

# Timeout errors

class ReadTimeoutError(SpdyError):
    desc = 'Read Timeout'

class IdleTimeoutError(SpdyError):
    desc = 'Idle Timeout'

# TCP connection errors

class ConnectionClosedError(SpdyError):
    desc = 'TCP connection has been closed'

class ConnectError(SpdyError):
    desc = 'TCP Connection failed'
    
# SPDY stream specific errors 

class UrlError(SpdyError):
    desc = 'Unsupported or invalid URI'
    
class ExchangeStateError(SpdyError):
    desc = 'Cannot perform operation'

class RstStreamError(SpdyError):
    desc = 'Received RST_STREAM'

# SPDY session specific errors

class FrameSizeError(SpdyError):
    desc = 'Invalid frame size received'
    
class ParsingError(SpdyError):
    desc = 'Error parsing SPDY frame'
    
class SpdyVersionError(SpdyError):
    desc = 'Unsupported SPDY protocol'
    
class FlagError(SpdyError):
    desc = 'Invalid flag set for frame'

class StreamIdError(SpdyError):
    desc = 'Invalid stream ID for session'

class HeaderError(SpdyError):
    desc = 'Invalid headers'
    
class ProtocolError(SpdyError):
    desc = 'SPDY protocol error'
    
class PingError(SpdyError):
    desc = 'Invalid ping ID'

