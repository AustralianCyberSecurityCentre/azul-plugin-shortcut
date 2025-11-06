"""Wrapper for accessing MAC Address assignment ranges and parsing v1 UUIDs."""

import binascii
import csv
import datetime
import os
import uuid

# Official IEEE assignments downloaded from:
# https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
OUI = os.path.join(os.path.dirname(__file__), "oui.csv")


class LnkGuid(object):
    """Parser for droid file identifier GUIDs.

    Decomposes back to the generating UUID1 fields used.
    This allows (in most cases) recovery of the MAC Address and timestamp
    of where/when the GUID was generated.

    MAC Address prefixes are mapped to vendors where possible.

    NOTE: If no adapter is available when generating a UUID, a random value
    will be used in place of MAC details, in which case the values will be
    misleading.
    """

    def __init__(self, hexstring):
        """Parse the supplied guid hexstring into UUID fields."""
        # later version of LnkParse already convert to uuid string
        if "-" in hexstring:
            self.uuid = uuid.UUID("urn:uuid:" + hexstring)
            self.hex = self.uuid.hex
        else:
            self.hex = hexstring
            self.uuid = uuid.UUID(bytes_le=binascii.unhexlify(self.hex))
        self.seq = self.uuid.clock_seq
        self.ts = parse_time(self.uuid)
        self.mac = "-".join(self.hex[i : i + 2] for i in range(20, 32, 2))
        self.mac_prefix = self.mac[:8]  # including :
        self.mac_vendor = OUI_MAP.get(self.hex[20:26].upper())


def parse_time(u):
    """Given a UUID1 will return a datetime object for when it was generated.

    Rounded to microseconds accuracy.
    """
    # 100ns increments since Oct 15, 1582
    t1 = datetime.datetime(1582, 10, 15)
    delta = datetime.timedelta(microseconds=u.time / 10)
    return t1 + delta


def load_oui(path):
    """Load the given OUI (MAC Prefix) CSV and returns a dict of prefix -> vendor."""
    prefix = {}
    with open(path, "r") as csv_file:
        r = csv.reader(csv_file)
        for row in r:
            prefix[row[1]] = row[2]
    return prefix


OUI_MAP = load_oui(OUI)
