#!/usr/bin/env python

"""
Simple enumeration type implementation in Python
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


# see http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
def enum(*sequential, **named):
    """
    Creates an enumeration. Can receive both sequential and named parameters.
    
    Example:
        Numbers = enum('ONE', 'TWO', 'THREE', FOUR='four', FIVE=555)
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
        Numbers.values
        >> [0, 1, 2, 'four', 555]
        Numbers.keys
        >> ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE']
    """
    enums = dict(list(zip(sequential, list(range(len(sequential))))), **named)
    reverse = dict((value, key) for key, value in enums.items())
    enums['str'] = reverse
    enums['values'] = reverse.keys()
    enums['keys'] = reverse.values()
    return type('Enum', (), enums)
    
