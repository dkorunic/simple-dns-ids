#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-


"""DNS storage and IDS
Purpose: Network communication routines
Requires: Crypto.Cipher
"""

__copyright__ = """Copyright (C) 2008  Dinko Korunic

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
"""

__version__ = '$Id: sniff_core.py,v 9d1636592f6d 2008/11/09 16:51:00 kreator $'

import time
import thread
import cPickle
import sys
import struct
import os
import hmac
import hashlib
import logging
import sniff_filters
from Queue import Queue
from SocketServer import DatagramRequestHandler, ThreadingUDPServer
from Crypto.Cipher import AES
from ConfigParser import ConfigParser

APPNAME = 'sniff_core'
CONFFILE = APPNAME + 'rc'
LOGLEVELS = {'CRITICAL': logging.CRITICAL, 'DEBUG': logging.DEBUG,
        'ERROR': logging.ERROR, 'FATAL': logging.FATAL,
        'INFO': logging.INFO, 'NOTSET': logging.NOTSET,
        'WARNING': logging.WARNING}
LOGFMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DNSFlowHandler(DatagramRequestHandler):
    """UDP encrypted datagram handler. Usage: decryption, CRC checking and
    unpickling. Handler is thread-safe and is used in ThreadedUDPServer;
    cooked packets are queued (with serialisation).
    """
    def handle(self):
        """Request handler: decrypts, checks CRC, unpickles and puts in
        queue. Thread safe. Returns nothing.
        """
        # read/receive message
        msg = self.rfile.read()
        lenmsg = len(msg)

        # message format: 20 bytes HMAC + 16 bytes IV + n * 16 bytes AES128
        # where n >= 1

        # discard message shorther than minimal length
        if lenmsg < 52:
            logging.error('Received message shorter than 52 bytes \
(rcvd from %s), bailing out' % self.client_address)
            return

        # verify HMAC-SHA1 (20 bytes always for SHA1, 16 bytes for MD5)
        hmacsha1 = msg[:20]
        digest = hmac.new(self.server.cryptokey, msg[20:],
                hashlib.sha1).digest()
        if digest != hmacsha1:
            logging.error('Failed CRC in received message \
(rcvd from %s), bailing out' % self.client_address)
            return

        # extract IV sent in cleartext
        cryptoiv = msg[20:(self.server.cryptoblocksize + 20)]
        # extract AES128-CBC crypted string...
        cryptomsg = msg[(self.server.cryptoblocksize + 20):]

        # ... and decrypt if possible
        try:
            s = self.server.cryptocipher(self.server.cryptokey,
                self.server.cryptomode, cryptoiv).decrypt(cryptomsg)
        except (error, ValueError):
            logging.error('Decryption failed (rcvd from %s), \
bailing out' % self.client_address)
            return

        # remove PKCS#7 padding
        try:
            s = self._unpad_pkcs7_block(s, self.server.cryptoblocksize)
        except ValueError:
            logging.error('Unpadding failed (rcvd from %s), bailing out' %
                    self.client_address)
            return

        # unpickle
        try:
            pkttree = cPickle.loads(s)
        except (cPickle.PickleError, cPickle.UnpicklingError, ValueError):
            logging.error('Unpickling failed (rcvd from %s), bailing out'
                    % self.client_address)
            return

        # serialize
        self.server.queue.put((self.client_address, pkttree))

    def _unpad_pkcs7_block(self, msg, blocksize):
        """PKCS#7 unpadding. Returns string."""
        # last byte contains number of padding bytes
        n = ord(msg[-1])
        if msg[-n:] != chr(n) * n:
            raise ValueError, 'Invalid padding'
        return msg[:-n]

class DNSFlowServer(ThreadingUDPServer):
    """Central threading UDP server (central console) class."""
    def __init__(self):
        # read configuration from file (defaults included)
        config = ConfigParser({'loglevel': 'INFO',
            'logfile': APPNAME + 'log',
            'addr': '127.0.0.1', 'port': 5000,
            'cryptokey': 'default'})
        config.read([CONFFILE])

        # set tunables
        self.loglevel = config.get(APPNAME, 'loglevel')
        self.logfile = config.get(APPNAME, 'logfile')
        self.addr = config.get(APPNAME, 'addr')
        self.port = config.getint(APPNAME, 'port')
        self.cryptokey = config.get(APPNAME, 'cryptokey')

        # set local variables
        self.filterlist = ()
        self.pktcount = 0
        self.handler = DNSFlowHandler
        self.server = ThreadingUDPServer((self.addr, self.port),
                self.handler)
        self.server.queue = Queue()

        # initialize and setup logging
        logging.basicConfig(filename=self.logfile, format=LOGFMT)
        self.log = logging.getLogger(APPNAME)
        if self.loglevel in LOGLEVELS:
            self.log.setLevel(LOGLEVELS[self.loglevel])

        # crypto stuff -- choose AES128 CBC
        self.server.cryptocipher = AES.new
        self.server.cryptomode = AES.MODE_CBC
        self.server.cryptoblocksize = AES.block_size
        self.server.cryptokey = self._pad_pkcs7_block(self.cryptokey,
                self.server.cryptoblocksize)
        
        # build a list of DNS IDS filter functions
        callable = lambda i: hasattr(i, '__call__')
        isfilter = lambda o, i: callable(getattr(o, i)) \
                and i[:7] == 'filter_'
        self.filterlist = [getattr(sniff_filters, i) for i in
                dir(sniff_filters) if isfilter(sniff_filters, i)]
       
        # start listening/analysing service
        self.log.info('Started %s @ %s' % (APPNAME, time.asctime()))
        thread.start_new_thread(self.process_flow, ())
        self.server.serve_forever()

    def _pad_pkcs7_block(self, msg, blocksize):
        """PKCS#7 padding. Returns string."""
        nrpad = blocksize - (len(msg) % blocksize)
        return msg + chr(nrpad) * nrpad

    def process_flow(self):
        """Process received flow with registered IDS filters. Returns
        nothing.
        """
        while True:
            addr, pkt = self.server.queue.get()
            self.pktcount += 1

            # dump debug info
            logging.debug('Current time: %s | Packet number: %d \
| Received from: %s | Packet dump: %s' % (time.asctime(), self.pktcount,
                addr, pkt))

            # process IDS filters
            for i in self.filterlist:
                logging.debug('Calling IDS filter: %s', i)
                i(pkt)

def main(argv):
    flow = DNSFlowServer()

if __name__ == '__main__':
    # import Psyco
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass

    sys.exit(main(sys.argv[1:]))
