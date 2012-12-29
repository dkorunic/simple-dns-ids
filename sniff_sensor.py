#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-


"""DNS storage and IDS
Purpose: main module
Requires: Scapy, IPy, Crypto
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

__version__ = '$Id: sniff_sensor.py,v a23ee70590b7 2008/12/07 16:44:50 kreator $'

import time
import thread
import cPickle
import sys
import struct
import os
import hmac
import hashlib
import logging
from scapy.all import *
from Queue import Queue
from Crypto.Cipher import AES
from ConfigParser import ConfigParser

APPNAME = 'sniff_sensor'
CONFFILE = APPNAME + 'rc'
LOGLEVELS = {'CRITICAL': logging.CRITICAL, 'DEBUG': logging.DEBUG,
        'ERROR': logging.ERROR, 'FATAL': logging.FATAL,
        'INFO': logging.INFO, 'NOTSET': logging.NOTSET,
        'WARNING': logging.WARNING}
LOGFMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DNSFlowClient:
    """Central DNS sensor/sniffer class. Implements Scapy DNS callback,
    functions for scapy_pkt->dict conversion and network communication
    with core.
    """
    def __init__(self):
        # read configuration from file (defaults included)
        config = ConfigParser({'loglevel': 'INFO',
            'logfile': APPNAME + 'log', 'pcapexpr': 'port 53',
            'srvaddr': '127.0.0.1', 'srvport': 5000,
            'cryptokey': 'default', 'standalone': False})
        config.read([CONFFILE])

        # set tunables
        self.loglevel = config.get(APPNAME, 'loglevel')
        self.logfile = config.get(APPNAME, 'logfile')
        self.pcapexpr = config.get(APPNAME, 'pcapexpr')
        self.srvaddr = config.get(APPNAME, 'srvaddr')
        self.srvport = config.getint(APPNAME, 'srvport')
        self.cryptokey = config.get(APPNAME, 'cryptokey')
        self.standalone = config.getboolean(APPNAME, 'standalone')

        # set local variables
        self.scapypktqueue = Queue()
        self.sock = None
        self.pktcount = 0
        self.starttime = time.time()

        # initialize and setup logging
        logging.basicConfig(filename=self.logfile, format=LOGFMT)
        self.log = logging.getLogger(APPNAME)
        if self.loglevel in LOGLEVELS:
            self.log.setLevel(LOGLEVELS[self.loglevel])

        # only if not in standalone mode
        if not self.standalone:
            # crypto stuff -- choose AES128 CBC
            self.cryptocipher = AES.new
            self.cryptomode = AES.MODE_CBC
            self.cryptoblocksize = AES.block_size
            self.cryptokey = self._pad_pkcs7_block(self.cryptokey,
                    self.cryptoblocksize)

            # generate AES IV from /dev/urandom...
            if os.path.exists('/dev/urandom'):
                self.cryptoiv = file('/dev/urandom',
                        'rb').read(self.cryptoblocksize)
            # ... or from random pool (much slower)
            else:
                from Crypto.Util import randpool
                pool = randpool.RandomPool(self.cryptoblocksize * 2)
                while size > pool.entropy:
                    pool.add_event()
                self.cryptoiv = pool.get_bytes(self.cryptoblocksize)

        # start sniffing/sending service
        self.log.info('Started %s @ %s' % (APPNAME, time.asctime()))
        if self.standalone:
            self.log.info('Working in standalone mode')
        else:
            self.log.info('Working in normal mode')
        thread.start_new_thread(self.send_flow, ())

    def _pad_pkcs7_block(self, msg, blocksize):
        """PKCS#7 padding. Returns string."""
        nrpad = blocksize - (len(msg) % blocksize)
        return msg + chr(nrpad) * nrpad

    def monitor_callback(self, scapypkt):
        """DNS packet callback for Scapy sniff(). Does not return
        nothing.
        """
        # queue (serialize) only if we really have DNS layer
        if scapypkt.haslayer(DNS):
            self.scapypktqueue.put((time.time(), scapypkt))

    def _get_fields(self, scapypkt, tree):
        """Recursive packet parser, builds tree from dissected Scapy
        packet. Returns dict.
        """
        # make new tree
        if tree is None:
            tree = {}

        # add new hier if not there...
        if not scapypkt.name in tree:
            tree[scapypkt.name] = {}
            node = tree[scapypkt.name]
        else:
            # ... hier already there, so make it into array and append
            if not isinstance(tree[scapypkt.name], list):
                tree[scapypkt.name] = [tree[scapypkt.name]]
            node = {}
            tree[scapypkt.name].append(node)
            node = tree[scapypkt.name][-1]

        # parse packet parts
        for f in scapypkt.fields_desc:
            fvalue = scapypkt.getfieldval(f.name)
            if fvalue is None:
                continue
            # new subpacket
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets
                    and type(fvalue) is list):
                fvalue_gen = SetGen(fvalue,_iterpacket=0)
                subpacket = 0
                for fvalue in fvalue_gen:
                    # subpacket/s
                    node[f.name] = self._get_fields(fvalue, None)
            else:
                # store individual packet parts
                if isinstance(fvalue, basestring):
                    node[f.name] = fvalue[:]
                else:
                    node[f.name] = f.i2repr(self, fvalue)

        # new payload                
        if scapypkt.payload:
            tree = self._get_fields(scapypkt.payload, tree)

        # return complete tree / jump back from recursion
        return tree
    
    def _network_emit(self, pkttree):
        """Highl-level network communication routine. Pickles received
        data, pads, encrypts and emits via UDP.
        """
        # create UDP socket if neccessary
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # pickle pkttree dict with highest protocol (binary)
        try:
            s = cPickle.dumps(pkttree, -1)
        except (cPickle.PickleError, cPickle.PicklingError, ValueError):
            self.log.error('Pickling failed, exiting')
            sys.exit(1)

        # PKCS#7 pad before crypto
        try:
            s = self._pad_pkcs7_block(s, self.cryptoblocksize)
        except ValueError:
            self.log.error('Padding failed, exiting')
            sys.exit(1)

        # crypto with AES128-CBC...
        try:
            s = self.cryptocipher(self.cryptokey, self.cryptomode,
                    self.cryptoiv).encrypt(s)
            # ... and add used IV (cleartext) to message
            s = self.cryptoiv + s
        except (error, ValueError):
            self.log.error('Encryption failed, exiting')
            sys.exit(1)

        # calculate HMAC-SHA1
        try:
            digest = hmac.new(self.cryptokey, s, hashlib.sha1).digest()
            pickledpkt = digest + s
        except (error, ValueError):
            self.log.error('Error calculating HMAC-SHA1, exiting')
            sys.exit(1)

        # ... and off you go!
        try:
            self.sock.sendto(pickledpkt, (self.srvaddr, self.srvport))
        except error:
            self.log.error('Network problem sending to %s:%s' % (self.srvaddr,
                self.srvport))
            pass

    def send_flow(self):
        """Routing which emits received packets when there is any in
        queue, otherwise idles. Returns nothing.
        """
        while True:
            # get packet from queue
            rcvtime, scapypkt = self.scapypktqueue.get()
            self.pktcount += 1

            # decompose and inject into our dict
            pkttree = self._get_fields(scapypkt, None)
            pkttree['rcvtime'] = rcvtime

            # dump debug info
            self.log.debug('Current time: %s | Packet number: %d \
| Packet received at: %s | Packet dump: %s' % (time.asctime(),
                self.pktcount, time.ctime(rcvtime), pkttree))

            if not self.standalone:
                # send network packet
                self._network_emit(pkttree)
            else:
                import sniff_filters

                # build a list of DNS IDS filter functions
                callable = lambda i: hasattr(i, '__call__')
                isfilter = lambda o, i: callable(getattr(o, i)) \
                        and i[:7] == 'filter_'
                self.filterlist = [getattr(sniff_filters, i) for i in
                        dir(sniff_filters) if isfilter(sniff_filters, i)]

                # process IDS filters
                failed = False
                for i in self.filterlist:
                    self.log.debug('Calling IDS filter: %s', i)
                    if i(pkttree):
                        failed = True
                if failed:
                    # log if any of filters previously failed
                    self.log.critical('IDS triggered. Current time: \
%s | Packet number: %d | Packet received at: %s (%d workhour)' %
                        (time.asctime(), self.pktcount,
                        time.ctime(rcvtime),
                        (int)((time.time() - self.starttime) / 3600)))

def main(argv):
    flow = DNSFlowClient()
    sniff(prn=flow.monitor_callback, filter=flow.pcapexpr, store=0)

if __name__ == '__main__':
    # import Psyco
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass

    sys.exit(main(sys.argv[1:]))
