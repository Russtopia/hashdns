#!/usr/bin/env python

#
## HashDNS submit program - simple util to submit hashDNS requests to a
## hashDNS server.
##
## Copyright (c) 2013 Russ Magee, rmagee@gmail.com
##
## This code is hereby released by Russ Magee ("author" and "copyright holder")
## under the terms of the GPL v3 (https://www.gnu.org/licenses/gpl.txt);
## you should have received a copy of the full license in a file named 'gpl.txt'
## in the same directory as this source code, or at the top-level of any archive
## containing this software as its primary component.
##
## In the event of an alleged violation of the license, authorization to act as
## an agent in all regards on behalf of the author is hereby granted to the FSF
## (Free Software Foundation) and the FSF may operate on the author's behalf for
## legal purposes relating to the protection of this software under the license.
##
## -Russ Magee 2013-03-31
##  rmagee@gmail.com
##
#####

import sys
import os
import socket
import SocketServer
import urllib
import shelve
import sha

defrequester = "requester@example.com"
defstamp = """1:18:130411:requester@example.com:ureq(u)=http%3a//72.53.8.87/~russtopia/add_foo_com.urequ;ureq(v)=http%3a//72.53.8.87/~russtopia/add_foo_com.ureqv;ureq-hash=f2fae3dcb0f761fe92b31fe193fb13efe8f017de:2Q+37FKTbjqKORQs:00000ISJ"""
add_foo_com_stamp = defstamp
add_bar_com_stamp = """1:18:130411:requester@example.com:ureq(u)=http%3a//72.53.8.87/~russtopia/add_bar_com.urequ;ureq(v)=http%3a//72.53.8.87/~russtopia/add_bar_com.ureqv;ureq-hash=f83a4c192d9035e58085c75c97567297364f6a76:H1nuGn2ZgZt1udqj:00002Xmh"""
del_foo_com_stamp = """1:18:130411:requester@example.com:ureq(u)=http%3a//72.53.8.87/~russtopia/del_foo_com.urequ;ureq(v)=http%3a//72.53.8.87/~russtopia/del_foo_com.ureqv;ureq-hash=f87a2c210e72628030f61ec135cd9449fc182aef:oNxVojGLUX3pmD0S:00001CPY"""
xfer_foo_com_stamp = """1:18:130411:requester@example.com:ureq(u)=http%3a//72.53.8.87/~russtopia/xfer_foo_com.urequ;ureq(v)=http%3a//72.53.8.87/~russtopia/xfer_foo_com.ureqv;ureq-hash=a60a3d9005203acd6d4b8b0d346bd599aa95448d:6s6qBfYbXoAIVqbp:0002zH"""

#
# @brief print if debug is desired
# 
# @param[in] v - varargs
###
def dprint(*v):
  for i in v:
    print i,
  print
##



## TODO
## -take args for server, ureq(u), ureq(v)
## -form submission (URS)
## -connect to server
## -submit URS
## -confirm submission status to user, exit

