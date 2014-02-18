#!/usr/bin/env python

#
## HashDNS server - proof of concept DNS server using secure two-part
## update request record mechanism and hashcash proof-of-work
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
## DNSQuery object derived from the minDNS.py example written by Francisco Santos,
## posted on http://code.activestate.com/recipes/491264-mini-fake-dns-server/
## (Licensed under the PSF - http://docs.python.org/2/license.html)
#####

#####
# TODO:
# -add peering system to URS submission (forward to list of peers)
# -add caching of legacy DNS lookups?
# -tag legacy DNS lookups if cached, so changes can be flagged to user?
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


#
# @brief Fully flatten a list - solution (7) on http://lemire.me/blog/archives/2006/05/10/flattening-lists-in-python/
#
# @param[in] l - list to flatten
#
# @return flattened list
###
def flatten(x):
  ans = []
  for i in range(len(x)):
    if isinstance(x[i],list):
      ans.extend(flatten(x[i]))
    else:
      ans.append(x[i])
  return ans
## end flatten()


# @brief Validate a stamp (using hashcash cmdline util)
#
# @param[in] resource - resource that should match in stamp
# @param[in] stamp - valid hashcash w/HashDNS ext field info
#
# @return status from hashcash util (eg., 256 = spent token, 0 = ok)
###
def validateStamp(resource=defrequester, stamp=defstamp):
  strength = stamp.split(':')[1]
  stat = os.system('hashcash -cd -b{} -r {} \'{}\''.format(strength, resource, stamp))
  return stat
## end validateStamp()


#
# @brief Return a tuple (urequ_uri, ureqv_uri, ureq-hash) from
#        a stamp
###
def parseStamp(stamp=defstamp):
  fields = stamp.split(':')
  (u,v,h) = fields[4].split(';')

  return (u.split('=')[1],v.split('=')[1],h.split('=')[1])
## end parseStamp()


def processStamp(requester = defrequester, hashdns_stamp = defstamp):
  stat = 0
  urequ_uri = ''
  ureqv_uri = ''
  urlf = None
  ureq_hash = ''
  h = None      ## to-be SHA1 hash object
  op = None     ## to hold operation specified in ureq(u)

  urequ = ''
  ureqv = ''

  ## 1. STAMP VERIFICATION
  ## Here we have received the stamp. Extract ureq(u)-URI, ureq(v)-URI and
  ## ureq-hash so we can put the two together and verify them.

  if validateStamp(requester, hashdns_stamp) != 0:
    dprint("Invalid update request stamp, ignoring. ({})".format(stat))
    stat = 1
  else:
    dprint("Valid update request stamp, extracting info...")
    (urequ_uri, ureqv_uri, ureq_hash) = parseStamp(hashdns_stamp)
    dprint("urequ_uri: {} ureqv_uri: {} ureq_hash: {}".format(urequ_uri, ureqv_uri, ureq_hash))

    dprint("Fetching parts...")
    urlf = urllib.urlopen( urllib.unquote(urequ_uri) )
    urequ = urlf.read().strip()
    urlf.close()

    urlf = urllib.urlopen( urllib.unquote(ureqv_uri) )
    ureqv = urlf.read().strip()
    urlf.close()

    dprint("urequ: {}".format(urequ))
    dprint("ureqv: {}".format(ureqv))

    h = sha.new(urequ + ureqv)
    if( h.hexdigest() != ureq_hash):
      dprint("ureq_hash mismatch! Rejecting ureq.")
      stat = 2
    else:
      dprint("ureq_hash verified, ureq is good.")

      ## 2. OP DETERMINATION
      ## Get IP addr from ureq(u)
      host_addr = urequ_uri.split('//')[1].split('/')[0]
      dprint("ureq(u)_uri specifies addr {}".format(host_addr))

      nonce_addr = ureqv_uri.split('//')[1].split('/')[0]
      dprint("ureq(v)_uri specifies addr {}".format(nonce_addr))

      ## Get operation from urequ
      (host_name,op) = urequ.split(':')
      dprint("ureq op [{}]".format(op))

      ## 3. OP VERIFICATION
      ## For all ops except [transfer] ensure
      ## (a) host_addr already exists in namespace
      ## (b) host_name from ureq(u) is unclaimed (host_name not in namespace.values) -OR-
      ##     host_name from ureq(u) is controlled by current owner (namespace[host_addr] == host_name)

      ## For [transfer], ensure
      ## (a) host_addr already exists in namespace
      ## (b) host_name from ureq(u) is controlled by current owner (namespace[host_addr] == host_name)
      ## (c) nonce_addr (pointing to ureq(v)) is distinct from host_addr (pointing to ureq(u))
      ####

      dprint("Current namespace: {}".format(namespace))
      if op not in {'update', 'delete', 'transfer'}:
        dprint("Invalid op [{}] specified, ignoring.".format(op))
        stat = 3
      else:
        if op == 'update':
          dprint("Request to update '{}'".format(host_name))
          flat_host_list = flatten( [list(i) for i in namespace.values()] )
          if host_name not in flat_host_list:
            dprint("Adding {},'{}' to namespace...".format(host_addr,host_name))
            if host_addr not in namespace:
              namespace[host_addr] = set([host_name])
            else:
              namespace[host_addr] = namespace[host_addr].union([host_name])
          else:
            dprint("host is already claimed.")
            stat = 4
        elif op == 'delete':
          dprint("Request to delete '{}'".format(host_name))
          flat_host_list = flatten( [list(i) for i in namespace.values()] )
          if host_name in flat_host_list:
            dprint("Deleting {},'{}' from namespace...".format(host_addr,host_name))
            namespace[host_addr] = namespace[host_addr].difference([host_name])
          else:
            dprint("Request to delete non-existent {},'{}', ignoring.".format(host_addr, host_name))
            stat = 5
        elif op == 'transfer':
          flat_host_list = flatten( [list(i) for i in namespace.values()] )
          if host_name in flat_host_list:
            if host_addr != nonce_addr:
              dprint("Transferring '{}' from {} to {}".format(host_name, host_addr, nonce_addr))
              namespace[nonce_addr] = namespace[nonce_addr].union([host_name])
              namespace[host_addr] = namespace[host_addr].difference([host_name])
            else:
              dprint("op [transfer] must have unique dest nonce_addr. Ignoring.")
              stat = 6
          else:
            dprint("Request to transfer non-existent {},'{}', ignoring.".format(host_addr, host_name))
            stat = 7
        else:
            dprint("FATAL: Other op [{}]".format(op))
            stat = 8
        ## endif
      ## endif

    ## endif (ureq_hash verified)
    del h
  ## endif

  return stat
## end processStamp()

def lookup(name):
#  name = name[:-1]  ## strip trailing '.'

  for ip in namespace:
    if name in namespace[ip]:
      dprint("[HashDNS found: '{}'->{}".format(name,ip))
      return ip
    ##
  ##
  return ''
## end lookup()


class DNSQuery:
  def __init__(self, data, aa = 0, ra = 0, rd = 0):
    self.data=data
    self.domain=''
    self.aa = aa
    self.ra = ra
    self.rd = rd

    ## [RFC1035, 4.1]
    ##    +---------------------+
    ##    |        Header       |
    ##    +---------------------+
    ##    |       Question      | the question for the name server
    ##    +---------------------+
    ##    |        Answer       | RRs answering the question
    ##    +---------------------+
    ##    |      Authority      | RRs pointing toward an authority
    ##    +---------------------+
    ##    |      Additional     | RRs holding additional information
    ##    +---------------------+

    ## [RFC1035, 4.11]
    ##                                  1  1  1  1  1  1
    ##    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |                      ID                       |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |                    QDCOUNT                    |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |                    ANCOUNT                    |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |                    NSCOUNT                    |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ##  |                    ARCOUNT                    |
    ##  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ####

    opcode = (ord(data[2]) >> 3) & 0x0F # Opcode bits
    if opcode == 0: ## standard query
      q_offs=12
      ## Parse through name -- each subdomain name prefixed with len byte
      len=ord(data[q_offs])
      while len != 0:
        ## Build domain by slicing out each subdomain name + '.'
        self.domain += data[q_offs+1:q_offs+len+1]+'.'
        q_offs += len+1
        len = ord(data[q_offs])
      ##endwhile
    ## endif
  ##end __init__


  ## Return a DNS response of (ip)
  ####
  def response(self, ip, aa = 0, ra = 0, rd = 0):
    packet=''

    resp = [0,0]
    qr = 1
    opcode = 0
    tc = z = rcode = 0

    resp[0] = ( qr<<7 | opcode<<6 | aa <<2 | tc <<1 | rd )
    resp[1] = ( ra<<7 | z<<6 | rcode )

    if self.domain:
      ## fill in response fields and copy (most of) original query back
      ###
      ## Sender's ID plus:
      ## QR=1 (resp), OP=0, AA=(aa), TC=0, RD=(rd), RA=(ra), Z=RCODE=0
      packet+=self.data[:2] + chr(resp[0]) + chr(resp[1])
      ## Questions and Answers Counts - copy QDCOUNT to ANCOUNT; {NS,AR}COUNT=0
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'
      ## Original Domain Name Question: NAME,TYPE,CLASS,TTL,RDLENGTH,RDATA
      packet+=self.data[12:]
      ## Answer's NAME as Pointer to Question
      packet+='\xc0\x0c'
      ## Answer's Response type, ttl and resource data length -> 4 bytes
      ## TYPE:A=0x0001 CLASS:IN=0x0001, TTL:0x0000003c=60s, RDLENGTH:0x0004
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
      ## RDATA:4 bytes of IP
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
    return packet
  ## end DNSQuery.response()
## end class DNSQuery()



class UDP_DNSHandler(SocketServer.BaseRequestHandler):
  """
  This class works similar to the TCP handler class, except that
  self.request consists of a pair of data and client socket, and since
  there is no connection the client address must be given explicitly
  when sending data back via sendto().
  """

  def handle(self):
    data = self.request[0].strip()
    sock = self.request[1]

    # DNS request, or URS (Update Request Stamp)?
    if len(data) >= 4:
      prefix = data[0:4]
      if prefix == 'UUp\0':  ## HashDNS capability query from client
        sock.sendto('[HashDNS v1.0:C:----]\n', self.client_address)
      elif prefix == 'UUx\0': ## HashDNS URS submission
        stat = processStamp('requester@example.com', data[4:])
        sock.sendto('[HashDNS v1.0:S:{}]\n'.format(stat), self.client_address)
      else:
        # dprint("{} wrote:".format(self.client_address[0]))

        p=DNSQuery(data)    ## new DNSQuery object, response packet w/o IP data

        ## Let's see if hostname is in the HashDNS namespace..
        ## ip = lookup(p.getHostName())
        ##    ## this must 'crack' hostname string out of DNS query packet, then
        ##    ## use that as dict key in _namespace_? to find ip
        ip = lookup(p.domain)
        if ip == '':
          ip = socket.gethostbyname(p.domain)
          dprint("[Legacy DNS found: '{}'->{}]".format(p.domain,ip))
        sock.sendto(p.response(ip), self.client_address)
        # dprint('response: {} -> {}'.format(p.domain, ip))
      ## endif (prefix)
    else:
      sock.sendto('[HashDNS v1.0:S:1]\n', self.client_address)
    ## endif (len(data)
  ## end handle()
## end Class UDP_DNSHandler()

def showhelp():
  print("{}: hashdns demonstration server".format(sys.argv[0]))
  print("Usage:");
  print("  <no options currently>")
  print("")
  print("This server runs on port 5300, to avoid conflicts with your")
  print("legacy DNS server, if present. To test hashdns entry submission")
  print("to this server please use the supplied hdns_sub.py example program.")
## end showhelp()

if __name__ == '__main__':
  if len(sys.argv) > 1 and (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
    showhelp()
    sys.exit(1)
  ## endif

#  dprint('hdns:: dom.query. 60 IN A %s' % ip)

  DNS_HOST, DNS_PORT = "localhost", 5300
  dns_server = SocketServer.UDPServer((DNS_HOST, DNS_PORT), UDP_DNSHandler)

  namespace = shelve.open('shelve.hashdns', 'c')  ## protocol=None, writeback=False

  dprint('Starting DNS server...')
  dns_server.serve_forever()

## end main()
