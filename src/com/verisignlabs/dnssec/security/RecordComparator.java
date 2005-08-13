// $Id: RecordComparator.java,v 1.2 2004/01/16 17:54:48 davidb Exp $
//
// Copyright (C) 2000-2003 Network Solutions, Inc.
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

import java.util.*;

import org.xbill.DNS.*;

/** This class implements a comparison operator for {@link
 *  org.xbill.DNS.Record} objects.  It imposes a canonical order
 *  consistent with DNSSEC.  It does not put records within a RRset
 *  into canonical order: see {@link ByteArrayComparator}.
 *
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.2 $ */

public class RecordComparator implements Comparator
{
  public RecordComparator()
  {}

  /** In general, types are compared numerically.  However, SOA and NS
   *  are ordered before the rest. */
  private int compareTypes(int a, int b)
  {
    if (a == b) return 0;
    if (a == Type.SOA) return -1;
    if (b == Type.SOA) return 1;

    if (a == Type.NS) return -1;
    if (b == Type.NS) return 1;

    if (a < b) return -1;

    return 1;
  }

  public int compare(Object o1, Object o2)
    throws ClassCastException
  {
    Record a = (Record) o1;
    Record b = (Record) o2;

    if (a == null && b == null) return 0;
    if (a == null) return 1;
    if (b == null) return -1;

    int res = a.getName().compareTo(b.getName());
    if (res != 0) return res;

    int a_type = a.getType();
    int b_type = b.getType();
    int sig_type = 0;

    if (a_type == Type.RRSIG)
    {
      a_type = ((RRSIGRecord) a).getTypeCovered();
      sig_type = 1;
    }
    if (b_type == Type.RRSIG)
    {
      b_type = ((RRSIGRecord) b).getTypeCovered();
      sig_type = -1;
    }

    res = compareTypes(a_type, b_type);
    if (res != 0) return res;

    if (sig_type != 0) return sig_type;

    return 0;
  }
}
