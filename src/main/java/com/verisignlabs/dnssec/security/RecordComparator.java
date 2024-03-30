// Copyright (C) 2000-2003 Network Solutions, Inc., 2022 Verisign, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA

package com.verisignlabs.dnssec.security;

import java.util.Comparator;

import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * This class implements a comparison operator for {@link org.xbill.DNS.Record}
 * objects. It imposes a canonical order consistent with DNSSEC. It does not put
 * records within a RRset into canonical order: see {@link ByteArrayComparator}.
 * 
 * @author David Blacka
 */

public class RecordComparator implements Comparator<Record> {
  public RecordComparator() {
    // nothing to initialize
  }

  /**
   * In general, types are compared numerically. However, SOA, NS, and DNAME are
   * ordered
   * before the rest.
   */
  private int compareTypes(int a, int b) {
    if (a == b)
      return 0;
    if (a == Type.SOA)
      return -1;
    if (b == Type.SOA)
      return 1;

    if (a == Type.NS)
      return -1;
    if (b == Type.NS)
      return 1;

    if (a == Type.DNAME)
      return -1;
    if (b == Type.DNAME)
      return 1;

    if (a < b)
      return -1;

    return 1;
  }

  private int compareRDATA(Record a, Record b) {
    byte[] aRdata = a.rdataToWireCanonical();
    byte[] bRdata = b.rdataToWireCanonical();

    for (int i = 0; i < aRdata.length && i < bRdata.length; i++) {
      int n = (aRdata[i] & 0xFF) - (bRdata[i] & 0xFF);
      if (n != 0)
        return n;
    }
    return (aRdata.length - bRdata.length);
  }

  public int compare(Record a, Record b) {
    if (a == null && b == null)
      return 0;
    if (a == null)
      return 1;
    if (b == null)
      return -1;

    int res = a.getName().compareTo(b.getName());
    if (res != 0)
      return res;

    int aType = a.getType();
    int bType = b.getType();
    int sigType = 0;

    if (aType == Type.RRSIG) {
      aType = ((RRSIGRecord) a).getTypeCovered();
      if (bType != Type.RRSIG)
        sigType = 1;
    }
    if (bType == Type.RRSIG) {
      bType = ((RRSIGRecord) b).getTypeCovered();
      if (a.getType() != Type.RRSIG)
        sigType = -1;
    }

    res = compareTypes(aType, bType);
    if (res != 0)
      return res;

    if (sigType != 0)
      return sigType;

    return compareRDATA(a, b);
  }
}
