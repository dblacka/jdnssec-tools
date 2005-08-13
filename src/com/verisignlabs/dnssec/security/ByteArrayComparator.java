// $Id: ByteArrayComparator.java,v 1.2 2004/02/25 20:46:14 davidb Exp $
//
// Copyright (C) 2001-2003 VeriSign, Inc.
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
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

package com.verisignlabs.dnssec.security;

import java.util.*;


/** This class implements a basic comparitor for byte arrays.  It is
 *  primarily useful for comparing RDATA portions of DNS records in
 *  doing DNSSEC canonical ordering.
 *
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.2 $
 */
public class ByteArrayComparator implements Comparator
{
  private int mOffset = 0;
  private boolean mDebug = false;
  
  public ByteArrayComparator()
  {}

  public ByteArrayComparator(int offset, boolean debug)
  {
    mOffset = offset;
    mDebug = debug;
  }
  
  public int compare(Object o1, Object o2) throws ClassCastException
  {
    byte[] b1 = (byte[]) o1;
    byte[] b2 = (byte[]) o2;

    for (int i = mOffset; i < b1.length && i < b2.length; i++)
    {
      if (b1[i] != b2[i])
      {
	if (mDebug)
	{
	  System.out.println("offset " + i + " differs (this is " +
			     (i - mOffset) +" bytes in from our offset.)");
	}
	return (b1[i] & 0xFF) - (b2[i] & 0xFF);
      }
    }

    return b1.length - b2.length;
  }
}
