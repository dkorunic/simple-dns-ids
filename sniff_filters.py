#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

"""DNS storage and IDS
Purpose: DNS filters and other IDS-related stuff
Requires: IPy
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

__version__ = '$Id: sniff_filters.py,v 690592d7bf9c 2009/01/07 18:51:43 kreator $'

import socket
import re
import logging
from IPy import IP
from sniff_dnscache import DNScache


APPNAME = 'sniff_filters'
KNOWNTLDS = None
RFC1918 = None
QNAME_RE = None
DNSCACHE = None
TYPE_OBSOLETE = ['MF', 'MD']
TYPE_EXPERIMENTAL = ['MB', 'MG', 'MR', 'NULL', 'MINFO']
TYPE_POSSIBLE_MS06041 = ['TXT', 'HINFO', 'X25', 'ISDN']
KNOWNTLD_FILE = 'known_tlds.txt'

# setup logging system first
log = logging.getLogger(APPNAME)


# === HELPER FUNCTIONS ===
# Non-interactive

def _is_query(pkt):
    """Check if DNS packet is QUERY (qr=0L). Returns bool."""

    return pkt['DNS']['qr'] == '0L'

def _is_answer(pkt):
    """Check if DNS packet is ANSWER (qr=1L). Returns bool."""

    return not _is_query(pkt)

def _is_query_type(pkt, qtype):
    """Check if DNS packet is query and if at least one of question
    records is specific query type. Returns bool.
    """

    if _is_answer(pkt):
        return False

    for i in _get_question(pkt):
        if i['qtype'] == qtype:
            return True
    
    return False

def _is_class(pkt, qrclass):
    """Check if and if at least one of question records or answer records
    (depending if packet is query or answer) is in some CLASS. Returns
    bool.
    """

    # check if query is consists of qclass in CLASS
    if _is_query(pkt):
        for i in _get_question(pkt):
            if i['qclass'] == qrclass:
                return True
    # check if answer consists of rclass in CLASS               
    else:
        for i in _get_answer(pkt):
            if i['rclass'] == qrclass:
                return True

    return False

def _get_id(pkt):
    """Get TXN ID from DNS packet. Returns string representing numeric ID.
    """

    return pkt['DNS']['id']

def _get_opcode(pkt):
    """Get OPCODE from DNS packet. Returns string (usually 'QUERY',
    'IQUERY' or 'STATUS').
    """

    return pkt['DNS']['opcode']

def _get_rcode(pkt):
    """Get RCODE from DNS packet. Returns string ('format-error',
    'server-failure', 'name-error', 'not-implemented' or 'refused').
    """

    return pkt['DNS']['rcode']

def _get_section(pkt, section):
    """Generic function to get RRs from any requested DNS section. Section
    can be 'qd' (question), 'an' (answer), 'ns' (authority) or 'ar'
    (additional). Returns list.
    """
    dnspkt = pkt['DNS']

    # oops, no such section -- return empty list instead
    if section not in dnspkt:
        return []

    # verify are there any QRs/RRs in requested section
    dnspktsec = dnspkt[section]
    if ('DNS Question Record' not in dnspktsec) and \
        ('DNS Resource Record' not in dnspktsec):
            return []

    if section == 'qd':
        # DNS QR
        rrs = dnspktsec['DNS Question Record']
    else:
        # DNS RR
        rrs = dnspktsec['DNS Resource Record']

    # several answers...
    if isinstance(rrs, list):
        return rrs
    # or not
    return [rrs]

def _get_question(pkt):
    """Get QUESTION section from DNS packet. Returns list."""

    return _get_section(pkt, 'qd')

def _get_answer(pkt):
    """Get ANSWER section from DNS packet. Returns list."""

    return _get_section(pkt, 'an')

def _get_authority(pkt):
    """Get AUTHORITY section from DNS packet. Returns list."""

    return _get_section(pkt, 'ns')

def _get_additional(pkt):
    """Get ADDITIONAL section from DNS packet. Returns list."""

    return _get_section(pkt, 'ar')

def _get_rrnames(pkt):
    """Get RRNAMEs from DNS packet. Returns list."""

    rrlist = [i['rrname'] for i in _get_answers(pkt)]
    rrlist2 = [i['rrname'] for i in _get_additional(pkt)]
    rrlist.extend(rrlist2)

    return rrlist

def _get_rrnames_type(pkt, rtype):
    """Get RRNAMEs for specific TYPE from DNS packet. Returns list."""

    rrlist = [i['rrname'] for i in _get_answers(pkt) if i['type'] ==
            rtype]
    rrlist2 = [i['rrname'] for i in _get_additional(pkt) if i['type'] ==
            rtype]
    rrlist.extend(rrlist2)

    return rrlist

def _get_qnames(pkt):
    """Get QNAMEs from DNS packet. Returns list."""

    return [i['qname'] for i in _get_question(pkt)]

def _get_qnames_type(pkt, qtype):
    """Get QNAMEs for specific QTYPE from DNS packet. Returns list."""

    return [i['qname'] for i in _get_question(pkt) if i['qtype'] == qtype]

def _get_types(pkt):
    """Get QTYPEs or TYPEs from DNS packet. Returns list."""

    tlist = [i['qtype'] for i in _get_question(pkt)]
    tlist2 = [i['type'] for i in _get_answer(pkt)]
    tlist3 = [i['type'] for i in _get_additional(pkt)]
    tlist.extend(tlist2)
    tlist.extend(tlist3)

    return tlist

def _get_srcaddr(pkt):
    """Get source IPaddr from DNS packet. Returns string."""

    return pkt['IP']['src']

def _get_dstaddr(pkt):
    """Get destination IPaddr from DNS packet. Returns string."""

    return pkt['IP']['dst']

def _get_ips_from_ptr(pkt):
    """Get reverse IPv4 addresses from given PTR request. Returns list."""

    revips = []

    for qname in _get_qnames(pkt):
        revip = qname.rstrip('.').replace('.in-addr.arpa', '').split('.')
        revip.reverse()
        revip = '.'.join(revip)
        revips.append(revip)

    return revips

def _qname_to_tld(qname):
    """Extract TLD from DNS packet's QNAME"""

    if qname.count('.') > 1:
        qnames = qname.split('.')
        qnames.reverse()
        for x in qnames:
            if x:
                return x.lower()
    if not qname:
        return '.'
    return qname.lower()

# === VARIOUS DNS FILTER FUNCTIONS ===
# return True if triggered (detected an issue)
# return False is all OK

def filter_unknown_tld(pkt):
    """Warn if unknown TLDs in QNAME"""

    # TLD list from: http://www.iana.org/domains/root/db/

    if _is_answer(pkt) or not _is_class(pkt, 'IN'):
        return False

    global KNOWNTLDS

    if KNOWNTLDS is None:
        KNOWNTLDS = {}
        try:
            f = file(KNOWNTLD_FILE, 'r')
        except IOError:
            log.error('Could not open %s' % KNOWNTLD_FILE)
            return False

        for line in f:
            KNOWNTLDS[line.strip()] = 1
        f.close()

    for qname in _get_qnames(pkt):
        tld = _qname_to_tld(qname)
        if tld not in KNOWNTLDS:
            log.critical('Unknown TLD %s in request: %s' % (tld, pkt))
            return True

    return False

def filter_afora(pkt):
    """Warn if A query is for IP address"""

    # IN A query only
    if not _is_query_type(pkt, 'A') or not _is_class(pkt, 'IN'):
        return False

    for qname in _get_qnames(pkt):
        qname = qname.rstrip('.')
        try:
            socket.inet_aton(qname)
            log.critical('A query %s for IP in qname: %s' % (qname,
                pkt))
            return True
        except (socket.error, TypeError):
            pass

    return False

def filter_rfc1918(pkt):
    """Warn if PTR query for RFC1918 address"""

    # IN PTR query only
    if not _is_query_type(pkt, 'PTR') or not _is_class(pkt, 'IN'):
        return False

    global RFC1918

    if RFC1918 is None:
        RFC1918 = [IP('10.0.0.0/8'), IP('172.16.0.0/12'),
                IP('192.168.0.0/16')]

    for ip in _get_ips_from_ptr(pkt):
        try:
            for x in RFC1918:
                if ip in x:
                    log.critical('RFC1918 PTR request for %s: %s' % (ip,
                        pkt))
                    return True
        except ValueError:
            pass

    return False

def filter_invalid_qname(pkt):
    """Check if QNAME is in order"""

    failed = False
    global QNAME_RE

    if QNAME_RE is None:
        # allowed a-z A-Z 0-9 - _ * . / @
        qname_srcre = r'^[a-zA-Z0-9\-_\*\./@]*$'
        QNAME_RE = re.compile(qname_srcre)

    for qname in _get_qnames(pkt):
        if not QNAME_RE.match(qname):
            log.critical('Invalid qname %s in request: %s' % (qname,
                pkt))
            failed = True
    return failed

def filter_rr_types(pkt):
    """Check if query/response contains obsolete/experimental records as
    per RFC 1035
    """

    failed = False

    for i in _get_types(pkt):
        if i in TYPE_OBSOLETE:
            log.critical('Obsolete RR type %s: %s' % (i, pkt))
            failed = True
        elif i in TYPE_EXPERIMENTAL:
            log.critical('Experimental RR type %s: %s' % (i, pkt))
            failed = True

    return failed

def filter_ms06041(pkt):
    """Check if query/response contains possible buffer overflow according
    to MS06-041/KB920683
    """

    names = []

    for i in TYPE_POSSIBLE_MS06041:
        names.extend(_get_qnames_type(pkt, i))

    rcount = len(names)
    if rcount:
        sumlen = reduce(lambda x, y: x+y, map(len, names))
    else:
        sumlen = 0

    if (rcount * 4) + (sumlen * 2) + 4 > 0xFFFF:
        log.critical('Attempted MS06-041 overflow: %s' % pkt)
        return True

    return False

def filter_unknown_opcode(pkt):
    """Check if send opcode is unknown"""

    if _get_opcode(pkt) not in ['QUERY', 'IQUERY', 'STATUS']:
        log.critical('Query contains unknown code: %s' %  pkt)
        return True

    return False

def filter_format_error(pkt):
    """Check if received packet contains rcode format error"""

    if _get_rcode(pkt) == 'format-error':
        log.critical('Query caused format error: %s' % pkt)
        return True

    return False

## implement fast-flux and anti-poison here?
def filter_cache_checks(pkt):
    """Various security checks that need simple DNS caching"""

    failed = False
    global DNSCACHE
   
    if DNSCACHE is None:
        DNSCACHE = DNScache()

    dnsid = _get_id(pkt)

    if _is_query(pkt):
        # queries are cached and indexed by TXN ID and IP dst addr
        dstaddr = _get_dstaddr(pkt)
        DNSCACHE[(dnsid, dstaddr)] = pkt
    else:
        # get old query from query cache
        srcaddr = _get_srcaddr(pkt)
        key = (dnsid, srcaddr)
        if key in DNSCACHE:
            # yes, we have such query cached
            oldpkt = DNSCACHE[key]
            oldquestions = _get_question(oldpkt)
            questions = _get_question(pkt)

            # check for multiple answers for single ID
            if 'checked' not in oldpkt:
                oldpkt['checked'] = 1
            else:
                oldpkt['checked'] += 1
            if oldpkt['checked'] > 3:
                log.critical('3+ answers with same ID %s \
received from %s. Attempted poisoning?' % (dnsid, srcaddr))
                failed = True

            # check if question in answer matches original question sent
            if oldquestions != questions:
                log.critical('Question in answer does not \
match original question: %s' % pkt)
                failed = True
        else:
            # oops, no such query -- timeouted or never sent
            log.critical('Received answer for unknown/old query: %s' %
                    pkt)
            failed = True

    return failed
