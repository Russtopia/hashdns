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
##
## Tool Dependencies
## hashcash  (debian: hashcash)
## sha1sum   (debian: coreutils)
##
## Example usage
## ./hdns_sub.py <hdns_server> <strength> <expirity-yymmdd> <email> \
##      <ureq_u_ip> <ureq_v_ip> <urs_filestem>
## ... where <urs_filestem> is the name of the urequ, ureqv files without the
##     .urequ or .ureqv extensions. <expiry> is given in hashcash syntax, for
##     example '48h' for 48 hours, or '2d' for the same, etc. (see hashcash
##     usage documentation). Eg.,
##
## ./hdns_sub.py localhost 24 48h me@example.com 72.53.8.2 72.53.8.2 dom1
##
## ... expects files 'dom1.urequ' and 'dom1.ureqv' to be present on host
##     72.53.8.2.
#####

import sys
import os
import socket
import urllib
import shelve
import subprocess
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

## return (op, urs)
###################
def buildURS(urequ_file, ureqv_file, str, expiry, requester, urequ_ip, ureqv_ip):
  op = None
  stat = 0
  urlf = None
  h = None      ## to-be SHA1 hash object

  urequ_uri = 'http%3a//{}/{}'.format(urequ_ip,urequ_file)
  ureqv_uri = 'http%3a//{}/{}'.format(ureqv_ip,ureqv_file)

  # Fetch urequ,ureqv to generate hash
  dprint("Fetching parts...")
  urlf = urllib.urlopen( urllib.unquote(urequ_uri) )
  urequ = urlf.read().strip()
  urlf.close()
  op = urequ.split(':')[1]

  urlf = urllib.urlopen( urllib.unquote(ureqv_uri) )
  ureqv = urlf.read().strip()
  urlf.close()

  h = sha.new(urequ + ureqv).hexdigest()

  dprint("ureq(u) at {}:{}".format(urequ_uri, urequ))
  dprint("ureq(v) at {}:{}".format(ureqv_uri, ureqv))
  dprint("ureq-hash:{}".format(h))

  # urequ-uri, ureqv-uri, urec-hash comprise the hashcash stamp ext field
  ext = 'ureq(u)={};ureq(v)={};ureq-hash={}'.format(urequ_uri, ureqv_uri, h)
  
#  hc_sub = ["hashcash", "-m", "-b{}".format(str), "-e{}".format(expiry),
#             "-r{}".format(resource), "-x'{}'".format(ext)]
#
#  proc = subprocess.Popen(hc_sub, stdout=subprocess.PIPE,
#            shell=True)
#  (hc_out, hc_err) = proc.communicate()

  hc_out = os.popen("hashcash -m -b{} -e {}h -r {} -x'{}'"\
              .format(str, expiry, resource, ext)).read()

  return (op,hc_out)
## end buildURS()


## TODO
## -take args for server, ureq(u), ureq(v)
## -form submission (URS)
## -connect to server
## -submit URS
## -confirm submission status to user, exit

if __name__ == "__main__":
  hdns_server = sys.argv[1]
  hdns_port = 5300
  stampStr = sys.argv[2]
  expTime = sys.argv[3]
  resource = sys.argv[4]
  ureq_u_ip = sys.argv[5]
  ureq_v_ip = sys.argv[6]
  ureq_f = sys.argv[7]

#  ureq_u_ip = '72.53.8.2'
#  ureq_v_ip = '72.53.8.2'

  [op, urs] = buildURS(ureq_f+'.urequ', ureq_f+'.ureqv',
                      stampStr, expTime, resource, ureq_u_ip, ureq_v_ip)
  dprint('Generated {} URS:{}'.format(op, urs))

  dprint('Submitting URS...')
  s = socket.socket(type=socket.SOCK_DGRAM)
  s.connect((hdns_server,hdns_port))
  s.settimeout(10)
  s.send('{}{}'.format('UUx\0',urs))
  print s.recv(1024)
  s.close()
  
## end main()

