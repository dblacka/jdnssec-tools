// $Id: ZoneUtils.java,v 1.3 2004/01/15 17:32:18 davidb Exp $
//
// Copyright (C) 2003 VeriSign, Inc.
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
import java.io.*;

import org.xbill.DNS.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/** This class contains a bunch of utility methods that are generally
 *  useful in manipulating zones.
 *
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.3 $
 */

public class ZoneUtils
{

  private static Log log;

  static {
    log = LogFactory.getLog(ZoneUtils.class);
  }
  
  /** Load a zone file.
   *
   *  @param zonefile the filename/path of the zonefile to read.
   *  @param origin the origin to use for the zonefile (may be null if
   *  the origin is specified in the zone file itself).
   *  @return a {@link java.util.List} of {@link org.xbill.DNS.Record}
   *  objects.
   *  @throws IOException if something goes wrong reading the zone
   *  file.
   */
  public static List readZoneFile(String zonefile, Name origin)
    throws IOException
  {
    ArrayList records = new ArrayList();
    Master m = new Master(zonefile, origin);

    Record r = null;

    while ( (r = m.nextRecord()) != null )
    {
      records.add(r);
    }

    return records;
  }

  /** Write the records out into a zone file.
   *
   *  @param records a {@link java.util.List} of {@link
   *  org.xbill.DNS.Record} objects forming a zone.
   *  @param zonefile the file to write to.  If null or equal to "-",
   *  System.out is used.
   */
  public static void writeZoneFile(List records, String zonefile)
    throws IOException
  {
    PrintWriter out = null;

    if (zonefile == null || zonefile.equals("-"))
    {
      out = new PrintWriter(System.out);
    }
    else
    {
      out = new PrintWriter(new BufferedWriter(new FileWriter(zonefile)));
    }


    for (Iterator i = records.iterator(); i.hasNext(); )
    {
      out.println(i.next());
    }

    out.close();
  }

  /** Given just the list of records, determine the zone name
   *  (origin).
   *
   *  @param records a list of {@link org.xbill.DNS.Record} or {@link
   *  org.xbill.DNS.RRset} objects.
   *  @return the zone name, if found. null if one couldn't be found.q
   */
  public static Name findZoneName(List records)
  {
    for (Iterator i = records.iterator(); i.hasNext(); )
    {
      int  type = 0;
      Name n    = null;
      
      Object o = i.next();
      
      if (o instanceof Record)
      {
	Record r = (Record) o;
	type 	 = r.getType();
	n 	 = r.getName();
      }
      else if (o instanceof RRset)
      {
	RRset r = (RRset) o;
	type 	= r.getType();
	n 	= r.getName();
      }

      if (type == Type.SOA) return n;
    }
    
    return null;
  }
}