#!/usr/bin/env python

"""
SPDY frame parsing methods.
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
    enums['values'] = reverse.keys()
    enums['keys'] = reverse.values()
    return type('Enum', (), enums)
    
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
    
ValidFlags = {
    FrameTypes.DATA: [Flags.NONE, Flags.FIN],
    FrameTypes.SYN_STREAM: [Flags.NONE, Flags.FIN, Flags.FLAG_UNIDIRECTIONAL],
    FrameTypes.SYN_REPLY: [Flags.NONE, Flags.FIN],
    FrameTypes.RST_STREAM: [Flags.NONE],
    FrameTypes.SETTINGS: [Flags.NONE, FLAG_SETTINGS_CLEAR_SETTINGS],
    FrameTypes.PING: [Flags.NONE],
    FrameTypes.GOAWAY: [Flags.NONE],
    FrameTypes.HEADERS: [Flags.NONE, Flags.FLAG_FIN],
    FrameTypes.WINDOW_UPDATE: [Flags.NONE],
    FrameTypes.CREDENTIAL: [Flags.NONE]} # no flags mentioned in spdy/3 spec

MinFrameLen = {
    FrameTypes.DATA: 0,
    FrameTypes.SYN_STREAM: 10,
    FrameTypes.SYN_REPLY: 4,
    FrameTypes.RST_STREAM: 8,
    FrameTypes.SETTINGS: 4, # spdy/3 spec is not clear about this
    FrameTypes.PING: 4,
    FrameTypes.GOAWAY: 8,
    FrameTypes.HEADERS: 4,
    FrameTypes.WINDOW_UPDATE: 8,
    FrameTypes.CREDENTIAL: 6} # spdy/3 spec is not clear about this

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

SPDY_VERSION = 3
STREAM_MASK = 0x7fffffff # masks highest bit (value equals to max stream ID)

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
                0x8000 + SPDY_VERSION, # control bit (=1)
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
        data = struct.pack("!IIBB%ds" % len(hdrs),
                STREAM_MASK & self.stream_id,
                STREAM_MASK & self.stream_assoc_id,
                (self.priority << 5),
                self.slot,
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

InputStates = enum('WAITING', 'READING_FRAME_DATA')
    
class SpdyMessageHandler(object):
    """
    This is a base class for parsing SPDY frames.
    """
    def __init__(self):
        self._input_buffer = ""
        self._input_state = InputStates.WAITING
        self._input_frame_type = None
        self._input_flags = None
        self._input_stream_id = None
        self._input_frame_len = 0
        self._input_frame_version = None
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
        
    ### main frame handling method to be implemented by inheriting classes
    
    def _handle_frame(self, frame):
        raise NotImplementedError
    
    ### error handler to be implemented by inheriting classes
    
    def _handle_error(self, err, status, stream_id, fatal):
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
                (d1, self._input_flags, d2, d3) = struct.unpack_from("!IBBH", data)
                if d1 >> 31 & 0x01: # control frame
                    self._input_frame_version = ( d1 >> 16 ) & 0x7fff
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
                if (self._valid_frame_type() and
                    self._valid_frame_version(frame_data) and
                    self._valid_frame_flags() and
                    self._valid_frame_size(frame_data)): # pre-check done
                    if self._input_frame_type == FrameTypes.DATA:
                        self._handle_frame(DataFrame(
                            self._input_flags, 
                            self._input_stream_id, 
                            frame_data))
                    elif self._input_frame_type == FrameTypes.SYN_STREAM:
                        (stream_id, stream_assoc_id, priority, slot) = \
                            struct.unpack_from("!IIBB", frame_data)
                        stream_id &= STREAM_MASK
                        stream_assoc_id &= STREAM_MASK
                        priority >>= 5
                        hdr_tuples = self._parse_hdrs(frame_data[10:], stream_id)
                        if hdr_tuples is not None:
                            self._handle_frame(SynSteamFrame(
                                self._input_flags,
                                stream_id,
                                stream_assoc_id,
                                priority,
                                slot,
                                hdr_tuples))
                    elif self._input_frame_type == FrameTypes.SYN_REPLY:
                        stream_id = struct.unpack_from("!I", frame_data)[0]
                        stream_id &= STREAM_MASK
                        hdr_tuples = self._parse_hdrs(frame_data[4:], stream_id)
                        if hdr_tuples is not None:
                            self._handle_frame(SynReplyFrame(
                                self._input_flags,
                                stream_id,
                                hdr_tuples))
                    elif self._input_frame_type == FrameTypes.RST_STREAM:
                        (stream_id, status) = struct.unpack_from("!II", frame_data)
                        stream_id &= STREAM_MASK
                        self._handle_frame(RstStreamFrame(stream_id, status))
                    elif self._input_frame_type == FrameTypes.SETTINGS:
                        settings_tuples = self._parse_settings(frame_data)
                        self._handle_frame(SettingsFrame(
                            self._input_flags, settings_tuples))
                    elif self._input_frame_type == FrameTypes.PING:
                        ping_id = struct.unpack_from("!I", frame_data)[0]
                        self._handle_frame(PingFrame(ping_id))
                    elif self._input_frame_type == FrameTypes.GOAWAY:
                        (last_stream_id, reason) = struct.unpack_from("!II", frame_data)
                        last_stream_id &= STREAM_MASK
                        self._handle_frame(GoawayFrame(last_stream_id, reason))
                    elif self._input_frame_type == FrameTypes.HEADERS:
                        stream_id = struct.unpack_from("!I", frame_data)[0]
                        stream_id &= STREAM_MASK
                        hdr_tuples = self._parse_hdrs(frame_data[4:], stream_id)
                        if hdr_tuples is not None:
                            self._handle_frame(HeadersFrame(
                                self._input_flags,
                                stream_id,
                                hdr_tuples))
                    elif self._input_frame_type == FrameTypes.WINDOW_UPDATE:
                        (stream_id, size) = struct.unpack_from("!II", frame_data)
                        stream_id &= STREAM_MASK
                        size &= STREAM_MASK
                        self._handle_frame(WindowUpdateFrame(stream_id, size))
                    elif self._input_frame_type == FrameTypes.CREDENTIAL:
                        # TODO: parse it
                        self._handle_frame(CredentialFrame())
                    else: # this should not be reachable
                        raise Exception('Unknown frame type %d.' % self._input_frame_type)
                self._input_state = WAITING
                if rest:
                    self._handle_input(rest)
            else: # don't have complete frame yet
                self._input_buffer = data
        else: # this should not be reachable
            raise Exception('Unknown input state %s.' % str(self._input_state))

    def _parse_hdrs(self, data, stream_id):
        """
        Given a control frame data block, return a list of (name, value) tuples.
        """
        if len(data) == 0:
            return list()
        try:
            data = self._decompress(data)
        except Exception as err:
            self._handle_error(error.ParsingError(
                'Failed while decompressing header block [%s].' % str(err)),
                GoawayReasons.INTERNAL_ERROR, None, True)
            return None
        try:
            cursor = 4
            num_hdrs = struct.unpack("!I", data[:cursor])[0]
            if num_hdrs == 0:
                return list()
            hdrs = list()
            names = set()
            while cursor < len(data):
                name_len = struct.unpack("!I", data[cursor:cursor+4])[0]
                """
                Note that in practice, this length must not exceed 2^24, 
                as that is the maximum size of a SPDY frame.
                """
                if name_len > (1 << 24):
                    self._handle_error(error.HeaderError(
                        'Received header name length %d is too high.' % 
                        name_len),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                """
                The length of each name must be greater than zero. A recipient 
                of a zero-length name MUST issue a stream error with the status 
                code PROTOCOL_ERROR for the stream-id.
                """
                if name_len == 0:
                    self._handle_error(error.HeaderError(
                        'Received zero length header name.'),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                cursor += 4
                name = data[cursor:cursor+name_len]
                """
                Header names are encoded using the US-ASCII character set 
                and must be all lower case.
                """
                if name.lower() != name:
                    self._handle_error(error.HeaderError(
                        'Received header name %s not in lower case.' % name),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                """
                Name: 0 or more octets, 8-bit sequences of data, excluding 0.
                """
                if '\x00' in name:
                    self._handle_error(error.HeaderError(
                        'Received header name %s containing null byte.' % 
                        name),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                cursor += name_len
                """
                Duplicate header names are not allowed.
                """
                if name in names:
                    self._handle_error(error.HeaderError(
                        'Received duplicate header name %s.' % name),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                names.add(name)
                val_len = struct.unpack("!I", data[cursor:cursor+4])[0]
                """
                Note that in practice, this length must not exceed 2^24, 
                as that is the maximum size of a SPDY frame.
                """
                if val_len > (1 << 24):
                    self._handle_error(error.HeaderError(
                        'Received header value length %d is too high.' % val_len),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                cursor += 4
                value = data[cursor:cursor+val_len]
                """
                A header value can either be empty (e.g. the length is zero) or 
                it can contain multiple, NUL-separated values, each with length 
                greater than zero.
                The value never starts nor ends with a NUL character. 
                Recipients of illegal value fields MUST issue a stream error 
                with the status code PROTOCOL_ERROR for the stream-id.
                """
                if ((value[0] == '\x00') or 
                    (value[-1] == '\x00') or 
                    ('\x00\x00' in value)):
                    self._handle_error(error.HeaderError(
                        'Received invalid header value %s.' % value),
                        StatusCodes.PROTOCOL_ERROR, stream_id, False)
                    return None
                cursor += val_len
                hdrs.append((name, value))
            if num_hdrs != len(hdrs):
                self._handle_error(error.HeaderError(
                    'Number of headers read %d does not match expected value %d.' %
                    (num_hdrs, len(hdrs))),
                    StatusCodes.PROTOCOL_ERROR, stream_id, False)
                return None
            return expand_dups(hdrs)
        except:
            self._handle_error(error.ParsingError(
                'Failed while parsing header block.'),
                GoawayReasons.INTERNAL_ERROR, None, True)
        return None
        
    def _parse_settings(self, data):
        """
        Given a SETTINGS frame data block, return a list of (flag, id, value) 
        settings tuples.
        """
        if len(data) == 0:
            return list()
        try:
            cursor = 4
            num_entry = struct.unpack("!I", data[:cursor])[0]
            if num_entry == 0:
                return list()
            entries = list()
            while cursor < len(data):
                (flags, d1, d2, value) = struct.unpack("!BBHI", data[cursor:cursor+8])
                id = (d1 << 16) + d2
                if flags not in SettingsFlags.values:
                    self._handle_error(error.ParsingError(
                        'Received unknown settings flags %d.' % flags)), 
                        GoawayReasons.PROTOCOL_ERROR, None, False)
                    return None
                if id not in SettingsIDs.values:
                    self._handle_error(error.ParsingError(
                        'Received unknown settings ID %d.' % id)), 
                        GoawayReasons.PROTOCOL_ERROR, None, False)
                    return None
                entries.append((flags, id, value))
                cursor += 8
            if num_entry != len(entries):
                self._handle_error(error.ParsingError(
                    'Number of settings read %d does not match expected value %d.' %
                    (num_entry, len(entries))),
                    GoawayReasons.PROTOCOL_ERROR, None, False)
                return None
            return entries
        except:
            self._handle_error(error.ParsingError(
                'Failed while parsing settings block.'),
                GoawayReasons.INTERNAL_ERROR, None, False)
        return None
     
    def _valid_frame_size(self, data):
        """
        If an endpoint receives a SYN_STREAM/REPLY which is larger than the 
        implementation supports, it MAY send a RST_STREAM with error code 
        FRAME_TOO_LARGE.
        
        If FRAME_TOO_LARGE is sent for a SYN_STREAM, HEADERS, or SYN_REPLY frame
        without fully processing the compressed portion of those frames, then 
        the compression state will be out-of-sync with the other endpoint. 
        In this case, senders of FRAME_TOO_LARGE MUST close the session.
        """
        if self._input_frame_type == FrameTypes.DATA:
            # FIXME: can there be a too large data frame?
            return True
        size = self._input_frame_len + 8
        err = error.FrameSizeError(
                    ('Received control frame with size %d '
                    'larger than maximum accepted size %d.') %
                    size, self._max_control_frame_size)
        if size > self._max_control_frame_size:
            if len(data) >= 4 and (self._input_frame_type in 
                [FrameTypes.SYN_STREAM, FrameTypes.SYN_REPLY, FrameTypes.HEADERS]):
                stream_id = struct.unpack_from("!I", data) & STREAM_MASK
                self._handle_error(err, 
                    StatusCodes.FRAME_TOO_LARGE, stream_id, False)
                self._handle_error(None, 
                    GoawayReasons.INTERNAL_ERROR, None, True)
            else
                self._handle_error(err,
                    GoawayReasons.INTERNAL_ERROR, None, True)
            return False
        """
        Check that read frame length is large enough to cover fixed size
        fields in each frame type.
        """
        if self._input_frame_len < MinFrameLen[self._input_frame_type]:
            self._handle_error(error.ParsingError(
                'Frame length %d is too small for a %s frame' %
                (self._input_frame_len, FrameTypes.str[self._input_frame_type])),
                GoawayReasons.INTERNAL_ERROR, None, True)
                return False
        return True
    
    def _valid_frame_version(self, data):
        """
        Check for correct frame version.
        """
        if self._input_frame_type == FrameTypes.DATA:
            return True
        err = error.SpdyVersionError('Version %d.' % self._input_frame_version)
        if self._input_frame_version != SPDY_VERSION:
            if len(data) >= 4 and (self._input_frame_type in 
                [FrameTypes.SYN_STREAM, FrameTypes.SYN_REPLY, FrameTypes.HEADERS]):
                stream_id = struct.unpack_from("!I", data) & STREAM_MASK
                self._handle_error(err,
                    StatusCodes.UNSUPPORTED_VERSION, stream_id, False)
            else:
                self._handle_error(err,
                    GoawayReasons.PROTOCOL_ERROR, None, True)
            return False
        return True
        
    def _valid_frame_type(self):
        """
        Check for supported frame type.
        """
        if self._input_frame_type not in FrameTypes.values:
            self._handle_error(error.ParsingError(
                'Unsupported frame type %d.' % self._input_frame_type),
                GoawayReasons.PROTOCOL_ERROR, None, True)
            return False
        return True

    def _valid_frame_flags(self):
        """
        Check that frame flags are defined for the frame type.
        """
        if self._input_flags not in ValidFlags[self._input_frame_type]:
            self._handle_error(error.ParsingError(
                'Invalid flag %d set for %s frame.' % 
                (self._input_flags, FrameTypes.str[self._input_frame_type])),
                GoawayReasons.PROTOCOL_ERROR, None, True)
            return False
        return True
            
    

