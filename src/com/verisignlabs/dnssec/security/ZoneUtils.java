// $Id$
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

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.xbill.DNS.Master;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * This class contains a bunch of utility methods that are generally useful in
 * manipulating zones.
 * 
 * @author David Blacka (original)
 * @author $Author$
 * @version $Revision$
 */

public class ZoneUtils
{
  /**
   * Load a zone file.
   * 
   * @param zonefile
   *          the filename/path of the zonefile to read.
   * @param origin
   *          the origin to use for the zonefile (may be null if the origin is
   *          specified in the zone file itself).
   * @return a {@link java.util.List} of {@link org.xbill.DNS.Record} objects.
   * @throws IOException
   *           if something goes wrong reading the zone file.
   */
  public static List readZoneFile(String zonefile, Name origin)
      throws IOException
  {
    ArrayList records = new ArrayList();
    Master m = new Master(zonefile, origin);

    Record r = null;

    while ((r = m.nextRecord()) != null)
    {
      records.add(r);
    }

    return records;
  }

  /**
   * Write the records out into a zone file.
   * 
   * @param records
   *          a {@link java.util.List} of {@link org.xbill.DNS.Record} objects
   *          forming a zone.
   * @param zonefile
   *          the file to write to. If null or equal to "-", System.out is used.
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

    for (Iterator i = records.iterator(); i.hasNext();)
    {
      out.println(i.next());
    }

    out.close();
  }

  /**
   * Given just the list of records, determine the zone name (origin).
   * 
   * @param records
   *          a list of {@link org.xbill.DNS.Record} or
   *          {@link org.xbill.DNS.RRset} objects.
   * @return the zone name, if found. null if one couldn't be found.q
   */
  public static Name findZoneName(List records)
  {
    for (Iterator i = records.iterator(); i.hasNext();)
    {
      int type = 0;
      Name n = null;

      Object o = i.next();

      if (o instanceof Record)
      {
        Record r = (Record) o;
        type = r.getType();
        n = r.getName();
      }
      else if (o instanceof RRset)
      {
        RRset r = (RRset) o;
        type = r.getType();
        n = r.getName();
      }

      if (type == Type.SOA) return n;
    }

    return null;
  }
  
  public static List findRRs(List records, Name name, int type)
  {
    List res = new ArrayList();
    for (Iterator i = records.iterator(); i.hasNext();)
    {
      Object o = i.next();
      
      if (o instanceof Record)
      {
        Record r = (Record) o;
        if (r.getName().equals(name) && r.getType() == type) 
        {
          res.add(r);
        }
              }
      else if (o instanceof RRset) 
      {
        RRset r = (RRset) o;
        if (r.getName().equals(name) && r.getType() == type)
        {
          for (Iterator j = r.rrs(); j.hasNext();)
          {
            res.add(j.next());
          }
        }
      }
    }
    
    return res;
  }
  
}

