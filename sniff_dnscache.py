#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

"""DNS storage/cache
Purpose: simple DNS cache implementation with timeout
Requires: -
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

__version__ = '$Id: sniff_dnscache.py,v 1b8048f83e26 2008/12/07 15:30:49 kreator $'

import time


class DNScache:
    """Simple DNS (or whatever) caching class with time-based expiry. Uses
    two dicts.
    """
    def __init__(self, timeout=300):
        self.__datastore = {} # cached RRs by ID
        self.__timestore = {} # cached IDs by TS
        self.timeout = timeout

    def __contains__(self, obj):
        return obj in self.__datastore

    def __getitem__(self, obj):
        if obj not in self:
            raise KeyError, obj
        rr, ts = self.__datastore[obj]
        return rr

    def __setitem__(self, obj, val):
        ts = time.time()
        # if ID exists, delete old TS
        if obj in self:
            del self[obj]
        self.__timestore[ts] = obj
        self.__datastore[obj] = (val, ts)

    def __delitem__(self, obj):
        if obj not in self:
            raise KeyError, obj
        rr, ts = self.__datastore[obj]
        del self.__timestore[ts]
        del self.__datastore[obj]
        self.__collect()

    def __collect(self):
        now = time.time()
        for ts in [ts for ts in self.__timestore \
                if (now - ts) >= self.timeout]:
            obj = self.__timestore[ts]
            del self.__timestore[ts]
            del self.__datastore[obj]
