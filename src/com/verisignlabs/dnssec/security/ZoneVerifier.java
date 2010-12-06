// $Id: DnsSecVerifier.java 172 2009-08-23 19:13:42Z davidb $
//
// Copyright (C) 2010 Verisign, Inc.
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

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base32;

/**
 * A class for whole zone DNSSEC verification. Along with cryptographically
 * verifying signatures, this class will also detect invalid NSEC and NSEC3
 * chains.
 * 
 * @author David Blacka (original)
 * @author $Author: davidb $
 * @version $Revision: 172 $
 */
public class ZoneVerifier
{

  private SortedMap<Name, Set>       mNodeMap;
  private HashMap<String, RRset>     mRRsetMap;
  private SortedMap<Name, MarkRRset> mNSECMap;
  private SortedMap<Name, MarkRRset> mNSEC3Map;
  private Name                       mZoneName;
  private DNSSECType                 mDNSSECType;
  private NSEC3PARAMRecord           mNSEC3params;

  private DnsSecVerifier             mVerifier;
  private base32                     mBase32;
  private ByteArrayComparator        mBAcmp;

  enum DNSSECType
  {
    UNSIGNED, NSEC, NSEC3, NSEC3_OPTOUT;
  }

  enum NodeType
  {
    NORMAL, DELEGATION, GLUE;
  }

  /**
   * This is a subclass of org.xbill.DNS.RRset that adds a "mark".
   */
  private class MarkRRset extends RRset
  {

    private static final long serialVersionUID = 1L;
    private boolean           mIsMarked        = false;

    boolean getMark()
    {
      return mIsMarked;
    }

    void setMark(boolean value)
    {
      mIsMarked = value;
    }
  }

  private class NameComparator implements Comparator
  {
    public int compare(Object o1, Object o2) throws ClassCastException
    {
      Name n1 = (Name) o1;

      return n1.compareTo(o2);
    }
  }

  public ZoneVerifier()
  {
    mVerifier = new DnsSecVerifier();
    mBase32 = new base32(base32.Alphabet.BASE32HEX, false, true);
    mBAcmp = new ByteArrayComparator();
  }

  private static String key(Name n, int type)
  {
    return n.toString() + ':' + type;
  }

  private void addRR(Record r)
  {
    Name r_name = r.getName();
    int r_type = r.getType();
    if (r_type == Type.RRSIG) r_type = ((RRSIGRecord) r).getTypeCovered();

    // Add NSEC and NSEC3 RRs to their respective maps
    if (r_type == Type.NSEC || r_type == Type.NSEC3)
    {
      if (mNSECMap == null)
      {
        mNSECMap = new TreeMap(new NameComparator());
      }
      MarkRRset rrset = mNSECMap.get(r_name);
      if (rrset == null)
      {
        rrset = new MarkRRset();
        mNSECMap.put(r_name, rrset);
      }
      rrset.addRR(r);
      return;
    }

    if (r_type == Type.NSEC3)
    {
      if (mNSEC3Map == null)
      {
        mNSEC3Map = new TreeMap(new NameComparator());
      }
      MarkRRset rrset = mNSEC3Map.get(r_name);
      if (rrset == null)
      {
        rrset = new MarkRRset();
        mNSEC3Map.put(r_name, rrset);
      }
      rrset.addRR(r);
      return;
    }

    // Add the name and type to the node map
    Set typeset = mNodeMap.get(r_name);
    if (typeset == null)
    {
      typeset = new HashSet();
      mNodeMap.put(r_name, typeset);
    }
    typeset.add(r.getType()); // add the original type

    // Add the record to the RRset map
    String k = key(r_name, r_type);
    RRset rrset = mRRsetMap.get(k);
    if (rrset == null)
    {
      rrset = new RRset();
      mRRsetMap.put(k, rrset);
    }
    rrset.addRR(r);
  }

  /**
   * Given an unsorted list of records, load the node and rrset maps, as well as
   * determine the NSEC3 parameters and signing type.
   * 
   * @param records
   */
  private void calculateNodes(List<Record> records)
  {
    Comparator comparator = new NameComparator();

    mNodeMap = new TreeMap<Name, Set>(comparator);
    mRRsetMap = new HashMap<String, RRset>();

    mDNSSECType = DNSSECType.UNSIGNED;

    for (Record r : records)
    {
      Name r_name = r.getName();
      int r_type = r.getType();

      // Add the record to the various maps.
      addRR(r);

      // Learn some things about the zone as we do this pass.
      if (r_type == Type.SOA)
      {
        mZoneName = r_name;
      }

      if (r_type == Type.NSEC3PARAM)
      {
        mNSEC3params = (NSEC3PARAMRecord) r;
      }

      if (r_type == Type.DNSKEY)
      {
        mVerifier.addTrustedKey((DNSKEYRecord) r);
      }

      if (mDNSSECType == DNSSECType.UNSIGNED)
      {
        if (r_type == Type.NSEC) mDNSSECType = DNSSECType.NSEC;
        if (r_type == Type.NSEC3)
        {
          NSEC3Record nsec3 = (NSEC3Record) r;
          if ((nsec3.getFlags() & NSEC3Record.Flags.OPT_OUT) == NSEC3Record.Flags.OPT_OUT)
          {
            mDNSSECType = DNSSECType.NSEC3_OPTOUT;
          }
          else
          {
            mDNSSECType = DNSSECType.NSEC3;
          }
        }
      }
    }
  }

  private NodeType determineNodeType(Name n, Set typeset, Name last_cut)
  {
    // All RRs at the zone apex are normal
    if (n.equals(mZoneName)) return NodeType.NORMAL;

    // If the node is below a zone cut (either a delegation or DNAME), it is glue.
    if (last_cut != null && n.subdomain(last_cut) && !n.equals(last_cut))
    {
      return NodeType.GLUE;
    }

    // If the node has a NS record it is a delegation.
    if (typeset.contains(new Integer(Type.NS))) return NodeType.DELEGATION;

    return NodeType.NORMAL;
  }

  private int processNodes() throws NoSuchAlgorithmException, TextParseException
  {
    int errors = 0;
    Name last_cut = null;

    for (Map.Entry<Name, Set> entry : mNodeMap.entrySet())
    {
      Name n = entry.getKey();
      Set typeset = entry.getValue();

      NodeType ntype = determineNodeType(n, typeset, last_cut);

      // we can ignore glue/invalid RRs.
      if (ntype == NodeType.GLUE) continue;

      // record the last zone cut if this node is a zone cut.
      if (ntype == NodeType.DELEGATION || typeset.contains(Type.DNAME))
      {
        last_cut = n;
      }

      // check all of the RRset that should be signed
      for (Object o : typeset)
      {
        int type = ((Integer) o).intValue();
        if (type == Type.RRSIG) continue;
        // at delegation points, only DS RRs are signed (and NSEC, but those are checked separately)
        if (ntype == NodeType.DELEGATION && type != Type.DS) continue;
        // otherwise, verify the RRset.
        String k = key(n, type);
        RRset rrset = mRRsetMap.get(k);

        errors += processRRset(rrset);
      }

      // cleanup the typesets of delegation nodes.
      // the only types that should be there are NS, DS and RRSIG.
      if (ntype == NodeType.DELEGATION)
      {
        Set newtypeset = new HashSet();
        if (typeset.contains(Type.NS)) newtypeset.add(Type.NS);
        if (typeset.contains(Type.DS)) newtypeset.add(Type.DS);
        if (typeset.contains(Type.RRSIG)) newtypeset.add(Type.RRSIG);

        if (!typeset.equals(newtypeset))
        {
          typeset = newtypeset;
        }
      }

      switch (mDNSSECType)
      {
        case NSEC:
          // all nodes with NSEC records have NSEC and RRSIG types
          typeset.add(Type.NSEC);
          typeset.add(Type.RRSIG);
          errors += processNSEC(n, typeset);
          break;
        case NSEC3:
          errors += processNSEC3(n, typeset, ntype);
          break;
        case NSEC3_OPTOUT:
          if (typeset.contains(Type.DS))
          {
            errors += processNSEC3(n, typeset, ntype);
          }
          break;
      }

    }

    return errors;
  }

  private int processRRset(RRset rrset)
  {
    // FIXME: use the slightly lower level verifySignature to get the list of reasons.
    int res = mVerifier.verify(rrset, null);

    String rrsetname = rrset.getName() + "/" + Type.string(rrset.getType());
    if (res == DNSSEC.Secure)
    {
      System.out.println("RRset " + rrsetname + " verified.");
    }
    else
    {
      System.out.println("RRset " + rrsetname + " did not verify.");
    }
    return res == DNSSEC.Secure ? 0 : 1;
  }

  private String typesetToString(Set typeset)
  {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (Iterator i = typeset.iterator(); i.hasNext();)
    {
      int type = ((Integer) i.next()).intValue();
      if (!first) sb.append(' ');
      sb.append(Type.string(type));
      first = false;
    }

    return sb.toString();
  }

  private String typesToString(int[] types)
  {
    StringBuilder sb = new StringBuilder();
    Arrays.sort(types);

    for (int i = 0; i < types.length; ++i)
    {
      if (i != 0) sb.append(' ');
      sb.append(Type.string(types[i]));
    }

    return sb.toString();
  }

  private boolean checkTypeMap(Set typeset, int[] types)
  {
    // a null typeset means that we are expecting the typemap of an ENT, which should be empty.
    if (typeset == null) return types.length == 0;

    Set compareTypeset = new HashSet();
    for (int i = 0; i < types.length; ++i)
    {
      compareTypeset.add(types[i]);
    }

    return typeset.equals(compareTypeset);
  }

  private int processNSEC(Name n, Set typeset)
  {
    MarkRRset rrset = mNSECMap.get(n);
    if (n == null)
    {
      System.out.println("Missing NSEC for " + n);
      return 1;
    }

    int errors = 0;

    rrset.setMark(true);

    NSECRecord nsec = (NSECRecord) rrset.first();

    // check typemap
    if (!checkTypeMap(typeset, nsec.getTypes()))
    {
      System.out.println("Typemap for NSEC RR " + n
          + " did not match what was expected. Expected '" + typesetToString(typeset)
          + "', got '" + typesToString(nsec.getTypes()));
      errors++;
    }

    // verify rrset
    errors += processRRset(rrset);

    return errors;
  }

  private boolean shouldCheckENTs(Name n, Set typeset, NodeType ntype)
  {
    // if we are just one (or zero) labels longer than the zonename, the node can't create a ENT
    if (n.labels() <= mZoneName.labels() + 1) return false;

    // we probably won't ever get called for a GLUE node
    if (ntype == NodeType.GLUE) return false;

    // if we aren't doing opt-out, then all possible ENTs must be checked.
    if (mDNSSECType == DNSSECType.NSEC3) return true;

    // if we are opt-out, and the node is an insecure delegation, don't check ENTs.
    if (ntype == NodeType.DELEGATION && !typeset.contains(Type.DS))
    {
      return false;
    }

    // otherwise, check ENTs.
    return true;
  }

  private int processNSEC3(Name n, Set typeset, NodeType ntype)
      throws NoSuchAlgorithmException, TextParseException
  {
    // calculate the NSEC3 RR name
    byte[] hash = mNSEC3params.hashName(n);
    if (mBase32 == null)
    {

    }
    String hashstr = mBase32.toString(hash);
    Name hashname = new Name(hashstr, mZoneName);

    MarkRRset rrset = mNSEC3Map.get(hashname);
    if (rrset == null)
    {
      System.out.println("Missing NSEC3 for " + hashname + " corresponding to " + n);
      return 1;
    }

    int errors = 0;

    rrset.setMark(true);

    NSEC3Record nsec3 = (NSEC3Record) rrset.first();

    // check typemap
    if (!checkTypeMap(typeset, nsec3.getTypes()))
    {
      errors++;
    }

    // verify rrset
    errors += processRRset(rrset);

    // check NSEC3 RRs for empty non-terminals.
    // this is recursive.
    if (shouldCheckENTs(n, typeset, ntype))
    {
      Name ent = new Name(n, 1);
      if (!mNodeMap.containsKey(ent))
      {
        errors += processNSEC3(ent, null, NodeType.NORMAL);
      }
    }

    return errors;
  }

  private int processNSECChain()
  {
    int errors = 0;
    NSECRecord lastNSEC = null;

    for (Iterator<Map.Entry<Name, MarkRRset>> i = mNSECMap.entrySet().iterator(); i.hasNext();)
    {
      // check the internal ordering of the previous NSEC record.  This avoids looking at the last one, 
      // which is different.
      if (lastNSEC != null)
      {
        if (lastNSEC.getName().compareTo(lastNSEC.getNext()) >= 0)
        {
          System.out.println("NSEC for " + lastNSEC.getName()
              + " has next name >= owner but is not the last NSEC in the chain.");
          errors++;
        }
      }

      Map.Entry<Name, MarkRRset> entry = i.next();
      Name n = entry.getKey();
      MarkRRset rrset = entry.getValue();

      // check to see if the NSEC is marked.  If not, it was not correlated to a signed node.
      if (!rrset.getMark())
      {
        System.out.println("NSEC RR for " + n + " appears to be extra.");
        errors++;
      }

      NSECRecord nsec = (NSECRecord) rrset.first();

      // This is just a sanity check.  If this isn't true, we are constructing the
      // nsec map incorrectly.
      if (!n.equals(nsec.getName()))
      {
        System.out.println("The NSEC in the map for name " + n + " has name "
            + nsec.getName());
        errors++;
      }

      // If this is the first row, ensure that the owner name equals the zone name
      if (lastNSEC == null && !n.equals(mZoneName))
      {
        System.out.println("The first NSEC in the chain does not match the zone name: name = "
            + n + " zonename = " + mZoneName);
        errors++;
      }

      // Check that the prior NSEC's next name equals this rows owner name.
      if (lastNSEC != null)
      {
        if (!lastNSEC.getNext().equals(nsec.getName()))
        {
          System.out.println("NSEC for " + lastNSEC.getName()
              + " does not point to the next NSEC in the chain: " + n);
          errors++;
        }
      }

      lastNSEC = nsec;
    }

    // check the internal ordering of the last NSEC in the chain
    // the ownername should be >= next name.
    if (lastNSEC.getName().compareTo(lastNSEC.getNext()) < 0)
    {
      System.out.println("The last NSEC RR in the chain did not have an owner >= next: owner = "
          + lastNSEC.getName() + " next = " + lastNSEC.getNext());
      errors++;
    }

    // check to make sure it links to the first NSEC in the chain
    if (!lastNSEC.getNext().equals(mZoneName))
    {
      System.out.println("The last NSEC RR in the chain did not link to the first NSEC");
      errors++;
    }

    return errors;
  }

  private int compareNSEC3Hashes(Name owner, byte[] hash)
  {
    // we will compare the binary images
    String ownerhashstr = owner.getLabelString(0);
    byte[] ownerhash = mBase32.fromString(ownerhashstr);

    return mBAcmp.compare(ownerhash, hash);
  }

  private int processNSEC3Chain()
  {
    int errors = 0;
    NSEC3Record lastNSEC3 = null;
    NSEC3Record firstNSEC3 = null;

    for (Iterator<Map.Entry<Name, MarkRRset>> i = mNSEC3Map.entrySet().iterator(); i.hasNext();)
    {
      // check the internal ordering of the previous NSEC3 record.  This avoids looking at the last one, 
      // which is different.
      if (lastNSEC3 != null)
      {
        if (compareNSEC3Hashes(lastNSEC3.getName(), lastNSEC3.getNext()) >= 0)
        {
          System.out.println("NSEC3 for " + lastNSEC3.getName()
              + " has next name >= owner but is not the last NSEC3 in the chain.");
          errors++;
        }
      }

      Map.Entry<Name, MarkRRset> entry = i.next();
      Name n = entry.getKey();
      MarkRRset rrset = entry.getValue();

      // check to see if the NSEC is marked.  If not, it was not correlated to a signed node.
      if (!rrset.getMark())
      {
        System.out.println("NSEC3 RR for " + n + " appears to be extra.");
        errors++;
      }

      NSEC3Record nsec3 = (NSEC3Record) rrset.first();

      // This is just a sanity check.  If this isn't true, we are constructing the
      // nsec map incorrectly.
      if (!n.equals(nsec3.getName()))
      {
        System.out.println("The NSEC3 in the map for name " + n + " has name "
            + nsec3.getName());
        errors++;
      }

      // If this is the first row, ensure that the owner name equals the zone name
      if (lastNSEC3 == null)
      {
        firstNSEC3 = nsec3;
      }

      // Check that the prior NSEC's next name equals this rows owner name.
      if (lastNSEC3 != null)
      {
        if (compareNSEC3Hashes(nsec3.getName(), lastNSEC3.getNext()) == 0)
        {
          System.out.println("NSEC3 for " + lastNSEC3.getName()
              + " does not point to the next NSEC3 in the chain: " + n);
          errors++;
        }
      }

      lastNSEC3 = nsec3;
    }

    // check the internal ordering of the last NSEC in the chain
    // the ownername should be >= next name.
    if (compareNSEC3Hashes(lastNSEC3.getName(), lastNSEC3.getNext()) < 0)
    {
      String nextstr = mBase32.toString(lastNSEC3.getNext());
      System.out.println("The last NSEC3 RR in the chain did not have an owner >= next: owner = "
          + lastNSEC3.getName() + " next = " + nextstr);
      errors++;
    }

    // check to make sure it links to the first NSEC in the chain
    if (compareNSEC3Hashes(firstNSEC3.getName(), lastNSEC3.getNext()) != 0)
    {
      System.out.println("The last NSEC3 RR in the chain did not link to the first NSEC3");
      errors++;
    }

    return errors;
  }

  public int verifyZone(List records) throws NoSuchAlgorithmException, TextParseException
  {
    int errors = 0;

    calculateNodes(records);

    errors = processNodes();

    if (mDNSSECType == DNSSECType.NSEC)
    {
      errors += processNSECChain();
    }
    else if (mDNSSECType == DNSSECType.NSEC3 || mDNSSECType == DNSSECType.NSEC3_OPTOUT)
    {
      errors += processNSEC3Chain();
    }

    System.out.println("Zone " + mZoneName + " verified with " + errors
        + ((errors == 1) ? " error" : " errors"));

    return errors;
  }
}
