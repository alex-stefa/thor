#!/usr/bin/env python

"""
Simple Event-Driven IO for Python

Thor is a Python library for evented IO, with a focus on enabling
high-performance HTTP intermediaries.
"""

__version__ = "0.3.0"

from sys import hexversion as _hexversion
assert _hexversion > 0x03030000, \
    "Thor needs Python version 3.3 or higher for SPDY NPN support."
# NOTE: future NPN support in Python ssl module for Python2.X is unlikely
# see: http://bugs.python.org/issue14204

from thor.loop import run, stop, time, schedule, running
from thor.tcp import TcpClient, TcpServer
from thor.tls import TlsClient, TlsServer, TlsConfig
from thor.udp import UdpEndpoint
from thor.events import on
from thor.enum import enum
from thor.http import HttpClient, HttpServer
from thor.spdy import SpdyClient, SpdyServer
