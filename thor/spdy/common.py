#!/usr/bin/env python

"""
shared SPDY infrastructure

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

import struct
import time
from urlparse import urlunsplit
from collections import defaultdict
from operator import itemgetter

from thor.spdy import error

compressed_hdrs = True
try:
    import c_zlib
except TypeError:
    # c_zlib loads "libz". However, that fails on Windows.
    compressed_hdrs = False
    import sys
    print >>sys.stderr, ('WARNING: sdpy_common: import c_zlib failed. '
                         'Using uncompressed headers.')

#-------------------------------------------------------------------------------

_dictionary_chars = [
	0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,   # - - - - o p t i
	0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,   # o n s - - - - h
	0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,   # e a d - - - - p
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,   # o s t - - - - p
	0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,   # u t - - - - d e
	0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,   # l e t e - - - -
	0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,   # t r a c e - - -
	0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,   # - a c c e p t -
	0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,   # - - - a c c e p
	0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   # t - c h a r s e
	0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,   # t - - - - a c c
	0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   # e p t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,   # d i n g - - - -
	0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,   # a c c e p t - l
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,   # a n g u a g e -
	0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,   # - - - a c c e p
	0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,   # t - r a n g e s
	0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,   # - - - - a g e -
	0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,   # - - - a l l o w
	0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,   # - - - - a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,   # o r i z a t i o
	0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,   # n - - - - c a c
	0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,   # h e - c o n t r
	0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,   # o l - - - - c o
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,   # n n e c t i o n
	0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,   # - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,   # e n t - b a s e
	0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,   # - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   # e n t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,   # d i n g - - - -
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,   # c o n t e n t -
	0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,   # l a n g u a g e
	0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,   # - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,   # e n t - l e n g
	0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,   # t h - - - - c o
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,   # n t e n t - l o
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,   # c a t i o n - -
	0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   # - - c o n t e n
	0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,   # t - m d 5 - - -
	0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,   # - c o n t e n t
	0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,   # - r a n g e - -
	0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   # - - c o n t e n
	0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,   # t - t y p e - -
	0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,   # - - d a t e - -
	0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,   # - - e t a g - -
	0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,   # - - e x p e c t
	0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,   # - - - - e x p i
	0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,   # r e s - - - - f
	0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,   # r o m - - - - h
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,   # o s t - - - - i
	0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,   # f - m a t c h -
	0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,   # - - - i f - m o
	0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,   # d i f i e d - s
	0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,   # i n c e - - - -
	0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,   # i f - n o n e -
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,   # m a t c h - - -
	0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,   # - i f - r a n g
	0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,   # e - - - - i f -
	0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,   # u n m o d i f i
	0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,   # e d - s i n c e
	0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,   # - - - - l a s t
	0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,   # - m o d i f i e
	0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,   # d - - - - l o c
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,   # a t i o n - - -
	0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,   # - m a x - f o r
	0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,   # w a r d s - - -
	0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,   # - p r a g m a -
	0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,   # - - - p r o x y
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,   # - a u t h e n t
	0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,   # i c a t e - - -
	0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,   # - p r o x y - a
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,   # u t h o r i z a
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,   # t i o n - - - -
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,   # r a n g e - - -
	0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,   # - r e f e r e r
	0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,   # - - - - r e t r
	0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,   # y - a f t e r -
	0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,   # - - - s e r v e
	0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,   # r - - - - t e -
	0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,   # - - - t r a i l
	0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,   # e r - - - - t r
	0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,   # a n s f e r - e
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,   # n c o d i n g -
	0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,   # - - - u p g r a
	0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,   # d e - - - - u s
	0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,   # e r - a g e n t
	0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,   # - - - - v a r y
	0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,   # - - - - v i a -
	0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,   # - - - w a r n i
	0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,   # n g - - - - w w
	0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,   # w - a u t h e n
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,   # t i c a t e - -
	0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,   # - - m e t h o d
	0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,   # - - - - g e t -
	0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,   # - - - s t a t u
	0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,   # s - - - - 2 0 0
	0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,   # - O K - - - - v
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,   # e r s i o n - -
	0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,   # - - H T T P - 1
	0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,   # - 1 - - - - u r
	0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,   # l - - - - p u b
	0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,   # l i c - - - - s
	0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,   # e t - c o o k i
	0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,   # e - - - - k e e
	0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,   # p - a l i v e -
	0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,   # - - - o r i g i
	0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,   # n 1 0 0 1 0 1 2
	0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,   # 0 1 2 0 2 2 0 5
	0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,   # 2 0 6 3 0 0 3 0
	0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,   # 2 3 0 3 3 0 4 3
	0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,   # 0 5 3 0 6 3 0 7
	0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,   # 4 0 2 4 0 5 4 0
	0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,   # 6 4 0 7 4 0 8 4
	0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,   # 0 9 4 1 0 4 1 1
	0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,   # 4 1 2 4 1 3 4 1
	0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,   # 4 4 1 5 4 1 6 4
	0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,   # 1 7 5 0 2 5 0 4
	0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,   # 5 0 5 2 0 3 - N
	0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,   # o n - A u t h o
	0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,   # r i t a t i v e
	0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,   # - I n f o r m a
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,   # t i o n 2 0 4 -
	0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,   # N o - C o n t e
	0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,   # n t 3 0 1 - M o
	0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,   # v e d - P e r m
	0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,   # a n e n t l y 4
	0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,   # 0 0 - B a d - R
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,   # e q u e s t 4 0
	0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,   # 1 - U n a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,   # o r i z e d 4 0
	0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,   # 3 - F o r b i d
	0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,   # d e n 4 0 4 - N
	0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,   # o t - F o u n d
	0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,   # 5 0 0 - I n t e
	0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,   # r n a l - S e r
	0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,   # v e r - E r r o
	0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,   # r 5 0 1 - N o t
	0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,   # - I m p l e m e
	0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,   # n t e d 5 0 3 -
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,   # S e r v i c e -
	0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,   # U n a v a i l a
	0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,   # b l e J a n - F
	0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,   # e b - M a r - A
	0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,   # p r - M a y - J
	0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,   # u n - J u l - A
	0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,   # u g - S e p t -
	0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,   # O c t - N o v -
	0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,   # D e c - 0 0 - 0
	0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,   # 0 - 0 0 - M o n
	0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,   # - - T u e - - W
	0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,   # e d - - T h u -
	0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,   # - F r i - - S a
	0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,   # t - - S u n - -
	0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,   # G M T c h u n k
	0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,   # e d - t e x t -
	0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,   # h t m l - i m a
	0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,   # g e - p n g - i
	0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,   # m a g e - j p g
	0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,   # - i m a g e - g
	0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   # i f - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   # c a t i o n - x
	0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   # m l - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   # c a t i o n - x
	0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,   # h t m l - x m l
	0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,   # - t e x t - p l
	0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,   # a i n - t e x t
	0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,   # - j a v a s c r
	0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,   # i p t - p u b l
	0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,   # i c p r i v a t
	0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,   # e m a x - a g e
	0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,   # - g z i p - d e
	0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,   # f l a t e - s d
	0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   # c h c h a r s e
	0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,   # t - u t f - 8 c
	0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,   # h a r s e t - i
	0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,   # s o - 8 8 5 9 -
	0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,   # 1 - u t f - - -
	0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e          # - e n q - 0 -
]
dictionary = ''.join([chr(c) for c in _dictionary_chars])
                   
#-------------------------------------------------------------------------------

def dummy(*args, **kw):
    """
    Dummy method that does nothing; useful to ignore a callback.
    """
    pass

# see http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
def enum(*sequential, **named):
    """
    Creates an enumeration. Can receive both sequential and named parameters.
    
    Example:
        Numbers = enum('ONE', 'TWO', 'THREE', 'FOUR'='four', 'FIVE'=555)
        Numbers.ONE
        >> 0
        Numbers.TWO
        >> 1
        Numbers.THREE
        >> 2
        Numbers.FOUR
        >> 'four'
        Numbers.FIVE
        >> 555
        Numbers.str[Numbers.ONE]
        >> 'ONE'
        Numbers.str[0]
        >> 'ONE'
        Numbers.str[Numbers.FOUR]
        >> 'FOUR'
        Numbers.str['four']
        >> 'FOUR'
    """
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['str'] = reverse
    return type('Enum', (), enums)

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
    CREDENTIAL = 0x10)
    
Flags = enum(
    FLAG_NONE = 0x00, 
    FLAG_FIN = 0x01, 
    FLAG_UNIDIRECTIONAL = 0x02
    FLAG_SETTINGS_CLEAR_SETTINGS = 0x01) # FIXME: Flags.str[..] won't work here

StatusCodes = enum(
    PROTOCOL_ERROR = 1,
    INVALID_STREAM = 2, 
    REFUSED_STREAM = 3,
    UNSUPPORTED_VERSION = 4,
    CANCEL = 5,
    INTERNAL_ERROR = 6,
    FLOW_CONTROL_ERROR = 7,
    STREAM_IN_USE = 8,
    STREAM_ALREADY_CLOSED = 9,
    INVALID_CREDENTIALS = 10,
    FRAME_TOO_LARGE = 11)
    
GoawayReasons = enum(
    OK = 0,
    PROTOCOL_ERROR = 1,
    INTERNAL_ERROR = 2)

SettingsFlags = enum(
    FLAG_SETTINGS_NONE = 0x00,
    FLAG_SETTINGS_PERSIST_VALUE = 0x01,
    FLAG_SETTINGS_PERSISTED = 0x02)
    
SettingsIDs = enum(
    SETTINGS_UPLOAD_BANDWIDTH = 1,
    SETTINGS_DOWNLOAD_BANDWIDTH = 2,
    SETTINGS_ROUND_TRIP_TIME = 3,
    SETTINGS_MAX_CONCURRENT_STREAMS = 4,
    SETTINGS_CURRENT_CWND = 5,
    SETTINGS_DOWNLOAD_RETRANS_RATE = 6,
    SETTINGS_INITIAL_WINDOW_SIZE = 7,
    SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE = 8)

Priority = enum(
    MIN = 7,
    MAX = 0,
    range = xrange(0, 8), # FIXME: replace with range(..) if Python 3.x
    count = 8)    

STREAM_MASK = 0x7fffffff # masks control bit (=0) 
MAX_STREAM_ID = 1 << 31 - 1 # maximum possible stream ID (31 bits)

#-------------------------------------------------------------------------------

class SpdyFrame(object):    
    """
    Base type for all SPDY frames.
    """    
    def __init__(self, type, flags):
        self.type = type
        self.flags = flags
    
    def __str__(self):
        return '>> [%s] %s' % (FrameTypes.str[self.type], Flags.str[self.flags])
        
    @staticmethod
    def _serialize_control_frame(type, flags, data):
        # TODO: check that data len doesn't overflow
        return struct.pack("!HHI%ds" % len(data),
                0x8003, # control bit (=1) and SPDY/3 version
                type,
                (flags << 24) + len(data),
                data)

    @staticmethod
    def _serialize_headers(hdr_tuples):
        hdr_tuples.sort() # required by Chromium
        hdr_tuples = collapse_dups(hdr_tuples)
        fmt = ["!I"]
        args = [len(hdr_tuples)]
        for (n,v) in hdr_tuples:
            # TODO: check for overflowing n, v lengths
            fmt.append("I%dsI%ds" % (len(n), len(v)))
            args.extend([len(n), n, len(v), v])
        return struct.pack("".join(fmt), *args)
        
    @staticmethod
    def _str_tuples(hdr_tuples):
        return '\t' + '\n\t'.join(['%s: %s' % (n, v) for (n, v) in hdr_tuples])

    def serialize(self, context):
        """
        Serializes the frame to a byte string. Needs a compression context.
        """
        return NotImplementedError
        
class DataFrame(SpdyFrame):
    """
    A SPDY DATA frame.
    """
    def __init__(self, flags, stream_id, data):
        SpdyFrame.__init__(self, FrameTypes.DATA, flags)
        self.stream_id = stream_id
        self.data = data
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d L%d\n\t%s' % (
            self.stream_id, len(self.data), data[:70])
        
    def serialize(self, context):
        # TODO: check that stream_id and data len don't overflow
        return struct.pack("!II%ds" % len(self.data),
                STREAM_MASK & self.stream_id,
                (self.flags << 24) + len(self.data),
                self.data)
        
class SynSteamFrame(SpdyFrame):
    """
    A SPDY SYN_STREAM frame.
    """
    def __init__(self, flags, stream_id, hdr_tuples, 
            priority=Priority.MIN, stream_assoc_id=0, slot=0):
        SpdyFrame.__init__(self, FrameTypes.SYN_STREAM, flags)
        self.stream_id = stream_id
        self.hdr_tuples = hdr_tuples
        self.priority = priority
        self.stream_assoc_id = stream_assoc_id
        self.slot = slot
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d A%d P%d S%d H%d\n%s' % (
            self.stream_id,
            self.stream_assoc_id,
            self.priority,
            self.slot,
            len(self.hdr_tuples),
            self._str_tuples(self.hdr_tuples))

    def serialize(self, context):
        hdrs = context._compress(self._serialize_headers(self.hdr_tuples))
        data = struct.pack("!IIBBH%ds" % len(hdrs),
                STREAM_MASK & self.stream_id,
                STREAM_MASK & self.stream_assoc_id,
                (self.priority << 5),
                self.slot,
                0x0000, # padding
                hdrs)
        return self._serialize_control_frame(self.type, self.flags, data)

class SynReplyFrame(SpdyFrame):
    """
    A SPDY SYN_REPLY frame.
    """
    def __init__(self, flags, stream_id, hdr_tuples):
        SpdyFrame.__init__(self, FrameTypes.SYN_REPLY, flags)
        self.stream_id = stream_id
        self.hdr_tuples = hdr_tuples
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d H%d\n%s' % (
            self.stream_id, 
            len(self.hdr_tuples), 
            self._str_tuples(self.hdr_tuples))

    def serialize(self, context):
        hdrs = context._compress(self._serialize_headers(self.hdr_tuples))
        data = struct.pack("!I%ds" % len(hdrs), 
                STREAM_MASK & self.stream_id, 
                hdrs)
        return self._serialize_control_frame(self.type, self.flags, data)
    
class HeadersFrame(SpdyFrame):
    """
    A SPDY HEADERS frame.
    """
    def __init__(self, flags, stream_id, hdr_tuples):
        SpdyFrame.__init__(self, FrameTypes.HEADERS, flags)
        self.stream_id = stream_id
        self.hdr_tuples = hdr_tuples
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d H%d\n%s' % (
            self.stream_id, 
            len(self.hdr_tuples), 
            self._str_tuples(self.hdr_tuples))

    def serialize(self, context):
        hdrs = context._compress(self._serialize_headers(self.hdr_tuples))
        data = struct.pack("!I%ds" % len(hdrs), 
                STREAM_MASK & self.stream_id, 
                hdrs)
        return self._serialize_control_frame(self.type, self.flags, data)
    
class RstStreamFrame(SpdyFrame):
    """
    A SPDY RST_STREAM frame.
    """
    def __init__(self, stream_id, status):
        SpdyFrame.__init__(self, FrameTypes.RST_STREAM, Flags.FLAG_NONE)
        self.stream_id = stream_id
        self.status = status
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d %s' % (
            self.stream_id, StatusCodes.str[self.status])

    def serialize(self, context):
        data = struct.pack("!II", STREAM_MASK & self.stream_id, self.status)
        return self._serialize_control_frame(self.type, self.flags, data)

class SettingsFrame(SpdyFrame):
    """
    A SPDY SETTINGS frame.
    """
    def __init__(self, flags, settings_tuples):
        SpdyFrame.__init__(self, FrameTypes.SETTINGS, flags)
        self.settings_tuples = settings_tuples
        
    def __str__(self):
        return SpdyFrame.__str__(self) + '\n\t%s' % (
            '\n\t'.join(['%s = %s (%s)' % (
                    SettingsIDs.str[s_id],
                    str(s_val),
                    SettingsFlags.str[s_flag]) 
                for (s_flag, s_id, s_val) in self.settings_tuples]))

    def serialize(self, context):
        self.settings_tuples.sort(key=itemgetter(1))
        fmt = ["!I"]
        args = [len(self.settings_tuples)]
        for (flag, id, value) in self.settings_tuples:
            fmt.append("II")
            args.extend([(flag << 24) + id, value])
        data = struct.pack("".join(fmt), *args)
        return self._serialize_control_frame(self.type, self.flags, data)
        
class PingFrame(SpdyFrame):
    """
    A SPDY PING frame.
    """
    def __init__(self, ping_id):
        SpdyFrame.__init__(self, FrameTypes.PING, Flags.FLAG_NONE)
        self.ping_id = ping_id
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' PING_ID=%d' % self.ping_id

    def serialize(self, context):
        data = struct.pack("!I", self.ping_id)
        return self._serialize_control_frame(self.type, self.flags, data)
        
class GoawayFrame(SpdyFrame):
    """
    A SPDY GOAWAY frame.
    """
    def __init__(self, last_stream_id, reason):
        SpdyFrame.__init__(self, FrameTypes.GOAWAY, Flags.FLAG_NONE)
        self.last_stream_id = last_stream_id
        self.reason = reason
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d %s' % (
            self.last_stream_id, GoawayReasons.str[self.reason])

    def serialize(self, context):
        data = struct.pack("!II", 
                STREAM_MASK & self.last_stream_id, 
                self.reason)
        return self._serialize_control_frame(self.type, self.flags, data)

class WindowUpdateFrame(SpdyFrame):
    """
    A SPDY WINDOW_UPDATE frame.
    """
    def __init__(self, stream_id, size):
        SpdyFrame.__init__(self, FrameTypes.WINDOW_UPDATE, Flags.FLAG_NONE)
        self.stream_id = stream_id
        self.size = size
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ' #%d SIZE=%d' % (
            self.stream_id, self.size)

    def serialize(self, context):
        data = struct.pack("!II", 
                STREAM_MASK & self.stream_id, 
                STREAM_MASK & self.size)
        return self._serialize_control_frame(self.type, self.flags, data)
        
class CredentialFrame(SpdyFrame): # TODO: add CREDENTIAL frame support
    """
    A SPDY CREDENTIAL frame.
    """
    def __init__(self, *args):
        SpdyFrame.__init__(self, FrameTypes.CREDENTIAL, Flags.FLAG_NONE)
        
    def __str__(self):
        return SpdyFrame.__str__(self) + ''

    def serialize(self, context):
        data = ''
        return self._serialize_control_frame(self.type, self.flags, data)
    
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
        self._pushed = False # is server pushed?
                
    def __str__(self):
        return ('[#%s A%s P%d%s REQ_%s RES_%s %s]' % (
            str(self.stream_id) if self.stream_id else '?',
            str(self._stream_assoc_id) if self._stream_assoc_id else '?',
            self.priority,
            '!' if self._pushed else '',
            ExchangeStates.str[self._req_state],
            ExchangeStates.str[self._res_state],
            time.strftime('%H:%M:%S', time.gmtime(self.timestamp))
        ))
    
    @property
    def is_active(self):
        return (self._req_state != ExchangeStates.DONE or
                self._res_state != ExchangeStates.DONE)
                
#-------------------------------------------------------------------------------

InputStates = enum('WAITING', 'READING_FRAME_DATA')
    
class SpdyMessageHandler(object):
    """
    This is a base class for something that has to parse and/or serialize
    SPDY messages, request or response.

    For parsing, it expects you to override _input_start, _input_body and
    _input_end, and call _handle_input when you get bytes from the network.

    For serialising, it expects you to override _output.
    """
    def __init__(self):
        self._input_buffer = ""
        self._input_state = InputStates.WAITING
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
        self._max_control_frame_size = 8192 
        """
        Note that full length control frames (16MB) can be large for 
        implementations running on resource-limited hardware. In such cases,
        implementations MAY limit the maximum length frame supported. However,
        all implementations MUST be able to receive control frames of at least 
        8192 octets in length.
        """
        
    ### main frame handling method
    
    def _handle_frame(self, frame):
        raise NotImplementedError
    
    ### error handler
    
    def _handle_error(self, err, status=None, stream_id=None):
        raise NotImplementedError

    ### output-related methods

    def _queue_frame(self, priority, frame):
        raise NotImplementedError
        
    def _output(self, chunk):
        raise NotImplementedError

    ### frame parsing methods

    def _handle_input(self, data):
        """
        Given a chunk of input, figure out what state we're in and handle it,
        making the appropriate calls.
        """
        # TODO: look into reading/writing directly from the socket buffer with struct.pack_into / unpack_from.
        if self._input_buffer != "":
            data = self._input_buffer + data # will need to move to a list if writev comes around
            self._input_buffer = ""
        if self._input_state == InputStates.WAITING: # waiting for a complete frame header
            if len(data) >= 8:
                (d1, self._input_flags, d2, d3) = struct.unpack("!IBBH", data[:8])
                if d1 >> 31 & 0x01: # control frame
                    version = ( d1 >> 16 ) & 0x7fff # TODO: check version
                    self._input_frame_type = d1 & 0x0000ffff
                    self._input_stream_id = None
                else: # data frame
                    self._input_frame_type = FrameTypes.DATA
                    self._input_stream_id = d1 & STREAM_MASK
                self._input_frame_len = (( d2 << 16 ) + d3)
                self._input_state = InputStates.READING_FRAME_DATA
                self._handle_input(data[8:])
            else:
                self._input_buffer = data
        elif self._input_state == InputStates.READING_FRAME_DATA:
            if len(data) >= self._input_frame_len:
                frame_data = data[:self._input_frame_len]
                rest = data[self._input_frame_len:]
                if self._input_frame_type == FrameTypes.DATA:
                    self._handle_frame(DataFrame(
                        self._input_flags, 
                        self._input_stream_id, 
                        frame_data))
                elif self._input_frame_type == FrameTypes.SYN_STREAM:
                    # FIXME: what if they lied about the frame len?
                    # FIXME: assert frame len > 20
                    (s_id, sa_id, pri, slot) = struct.unpack("!IIBB", frame_data[:10])
                    hdr_tuples = self._parse_hdrs(frame_data[12:])
                    # FIXME: proper error on failure
                    self._handle_frame(SynSteamFrame(
                        self._input_flags,
                        s_id & STREAM_MASK,
                        sa_id & STREAM_MASK,
                        pri >> 5,
                        slot,
                        hdr_tuples))
                elif self._input_frame_type == FrameTypes.SYN_REPLY:
                    # FIXME: assert frame len > 12
                    s_id = struct.unpack("!I", frame_data[:4])[0]
                    hdr_tuples = self._parse_hdrs(frame_data[4:])
                    # FIXME: proper error on failure
                    self._handle_frame(SynReplyFrame(
                        self._input_flags,
                        s_id & STREAM_MASK,
                        hdr_tuples))
                elif self._input_frame_type == FrameTypes.RST_STREAM:
                    # FIXME: assert frame len = 16
                    (s_id, status) = struct.unpack("!II", frame_data)
                    self._handle_frame(RstStreamFrame(
                        s_id & STREAM_MASK, status))
                elif self._input_frame_type == FrameTypes.SETTINGS:
                    # FIXME: assert frame len > 8
                    settings_tuples = self._parse_settings(frame_data)
                    # FIXME: proper error on failure
                    self._handle_frame(SettingsFrame(
                        self._input_flags, settings_tuples))
                elif self._input_frame_type == FrameTypes.PING:
                    # FIXME: assert frame len = 12
                    ping_id = struct.unpack("!I", frame_data)[0]
                    self._handle_frame(PingFrame(
                        ping_id))
                elif self._input_frame_type == FrameTypes.GOAWAY:
                    # FIXME: assert frame len = 16
                    (lgs_id, reason) = struct.unpack("!II", frame_data)
                    self._handle_frame(GoawayFrame(
                        lgs_id & STREAM_MASK, reason))
                elif self._input_frame_type == FrameTypes.HEADERS:
                    # FIXME: assert frame len > 12
                    s_id = struct.unpack("!I", frame_data[:4])[0]
                    hdr_tuples = self._parse_hdrs(frame_data[4:])
                    # FIXME: proper error on failure
                    self._handle_frame(HeadersFrame(
                        self._input_flags,
                        s_id & STREAM_MASK,
                        hdr_tuples))
                elif self._input_frame_type == FrameTypes.WINDOW_UPDATE:
                    # FIXME: assert frame len = 16
                    (s_id, size) = struct.unpack("!II", frame_data)
                    self._handle_frame(WindowUpdateFrame(
                        s_id & STREAM_MASK,
                        size & STREAM_MASK))
                elif self._input_frame_type == FrameTypes.CREDENTIAL:
                    raise NotImplementedError
                else: # unknown frame type
                    raise ValueError, "Unknown frame type" # FIXME: don't puke
                self._input_state = WAITING
                if rest:
                    self._handle_input(rest)
            else: # don't have complete frame yet
                self._input_buffer = data
        else:
            raise Exception, "Unknown input state %s" % self._input_state

    def _parse_hdrs(self, data):
        """
        Given a control frame data block, return a list of (name, value) tuples.
        """
        data = self._decompress(data) # FIXME: catch errors
        cursor = 4
        (num_hdrs,) = struct.unpack("!i", data[:cursor]) # FIXME: catch errors
        hdrs = []
        while cursor < len(data):
            try:
                (name_len,) = struct.unpack("!i", data[cursor:cursor+4]) # FIXME: catch errors
                cursor += 4
                name = data[cursor:cursor+name_len] # FIXME: catch errors
                cursor += name_len
            except IndexError:
                raise
            except struct.error:
                raise
            try:
                (val_len,) = struct.unpack("!i", data[cursor:cursor+4]) # FIXME: catch errors
                cursor += 4
                value = data[cursor:cursor+val_len] # FIXME: catch errors
                cursor += val_len
            except IndexError:
                raise
            except struct.error:
                print len(data), cursor, data # FIXME
                raise
            hdrs.append((name, value))
        return expand_dups(hdrs)
    
    # TODO: use this somewhere?
    def _valid_frame_size(self, size, stream_id):
        """
        If an endpoint receives a SYN_STREAM/REPLY which is larger than the 
        implementation supports, it MAY send a RST_STREAM with error code 
        FRAME_TOO_LARGE.
        """
        if size > self._max_control_frame_size:
            self._handle_error(
                error.FrameSizeError('Received control frame size %d '
                    'exceeded maximum accepted size %d.' %
                    size, self._max_control_frame_size), 
                StatusCodes.FRAME_TOO_LARGE, 
                stream_id)
            return False
        return True
    
    def _parse_settings(self, data):
        """
        Given a SETTINGS frame data block, return a list of (flag, id, value) 
        settings tuples.
        """
        # TODO:
        
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
        self._sent_timestamp = None
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
        
    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.tcp_conn:
            status.append(
              self.tcp_conn.tcp_connected and 'connected' or 'disconnected')
        return "<%s at %#x>" % (", ".join(status), id(self))

    ### "Public" methods
    
    @property
    def is_active(self):
        """
        Session alive or not.
        """
        return self.tcp_conn is not None
    
    def ping(self, ping_timeout=None):
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
        # FIXME: is the above call necessary and should we wait for 
        #   when we need to send data first?
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
    
    ### Error handler method called by SpdyMessageHandler
         
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
        ping_timer._sent_timestamp = time.time()
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
                ping_timer.emit('pong', time.time() - 
                    ping_timer._sent_timestamp)
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
        if self._highest_created_stream_id > MAX_STREAM_ID:
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
            # TODO: ideally, closed streams should be purged from memory;
            #       returned exchange should be checked if active.
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

    ### Main frame handling method (should be extended by inheriting classes)
    
    def _handle_frame(self, frame):
        self.emit('frame', frame)
        self._clear_idle_timeout()
        self._set_idle_timeout()

        if frame.type == FrameTypes.PING:
            if (frame.ping_id % 2) != (self._highest_ping_id % 2):
                self._queue_frame(
                    Priority.MAX,
                    PingFrame(frame.ping_id))
            else:
                self._notify_ping(frame._ping_id, success=True)
                
        elif frame.type == FrameTypes.GOAWAY:
            self._received_goaway = True
            self.emit('goaway', frame.reason, frame.last_stream_id)

        elif frame.type == FrameTypes.SETTINGS:
            pass
            
        elif frame.type == FrameTypes.CREDENTIAL:
            pass
            
        elif frame.type == FrameTypes.WINDOW_UPDATE:
            pass

