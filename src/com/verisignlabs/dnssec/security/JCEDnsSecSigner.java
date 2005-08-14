// $Id$
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
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA

package com.verisignlabs.dnssec.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * This class contains routines for signing DNS zones.
 * 
 * In particular, it contains both an ability to sign an individual RRset and
 * the ability to sign and entire zone. It primarily glues together the more
 * basic primitives found in {@link SignUtils}.
 * 
 * @author David Blacka (original)
 * @author $Author$
 * @version $Revision$
 */
public class JCEDnsSecSigner
{
  private DnsKeyConverter  mKeyConverter;

  private KeyPairGenerator mRSAKeyGenerator;
  private KeyPairGenerator mDSAKeyGenerator;

  /**
   * Cryptographically generate a new DNSSEC key.
   * 
   * @param owner the KEY RR's owner name.
   * @param ttl the KEY RR's TTL.
   * @param dclass the KEY RR's DNS class.
   * @param algorithm the DNSSEC algorithm (RSAMD5, RSASHA1, or DSA).
   * @param flags any flags for the KEY RR.
   * @param keysize the size of the key to generate.
   * @return a DnsKeyPair with the public and private keys populated.
   */
  public DnsKeyPair generateKey(Name owner, long ttl, int dclass,
      int algorithm, int flags, int keysize) throws NoSuchAlgorithmException
  {
    KeyPair pair;

    if (ttl < 0) ttl = 86400; // set to a reasonable default.

    switch (algorithm)
    {
      case DNSSEC.RSAMD5 :
      case DNSSEC.RSASHA1 :
        if (mRSAKeyGenerator == null)
        {
          mRSAKeyGenerator = KeyPairGenerator.getInstance("RSA");
        }
        mRSAKeyGenerator.initialize(keysize);
        pair = mRSAKeyGenerator.generateKeyPair();
        break;
      case DNSSEC.DSA :
        if (mDSAKeyGenerator == null)
        {
          mDSAKeyGenerator = KeyPairGenerator.getInstance("DSA");
        }
        mDSAKeyGenerator.initialize(keysize);
        pair = mDSAKeyGenerator.generateKeyPair();
        break;
      default :
        throw new NoSuchAlgorithmException("Alg " + algorithm);
    }

    if (mKeyConverter == null)
    {
      mKeyConverter = new DnsKeyConverter();
    }

    DNSKEYRecord keyrec = mKeyConverter.generateDNSKEYRecord(owner,
        dclass,
        ttl,
        flags,
        algorithm,
        pair.getPublic());
    DnsKeyPair dnspair = new DnsKeyPair();
    dnspair.setDNSKEYRecord(keyrec);
    dnspair.setPublic(pair.getPublic()); // keep from conv. the keyrec back.
    dnspair.setPrivate(pair.getPrivate());

    return dnspair;
  }

  /**
   * Sign an RRset.
   * 
   * @param rrset the RRset to sign -- any existing signatures are ignored.
   * @param keypars a list of DnsKeyPair objects containing private keys.
   * @param start the inception time for the resulting RRSIG records.
   * @param expire the expiration time for the resulting RRSIG records.
   * @return a list of RRSIGRecord objects.
   */
  public List signRRset(RRset rrset, List keypairs, Date start, Date expire)
      throws IOException, GeneralSecurityException
  {
    if (rrset == null || keypairs == null) return null;

    // default start to now, expire to start + 1 second.
    if (start == null) start = new Date();
    if (expire == null) expire = new Date(start.getTime() + 1000L);
    if (keypairs.size() == 0) return null;

    // first, pre-calculate the rrset bytes.
    byte[] rrset_data = SignUtils.generateCanonicalRRsetData(rrset);

    ArrayList sigs = new ArrayList(keypairs.size());

    // for each keypair, sign the rrset.
    for (Iterator i = keypairs.iterator(); i.hasNext();)
    {
      DnsKeyPair pair = (DnsKeyPair) i.next();
      DNSKEYRecord keyrec = pair.getDNSKEYRecord();
      if (keyrec == null) continue;

      RRSIGRecord presig = SignUtils.generatePreRRSIG(rrset,
          keyrec,
          start,
          expire,
          rrset.getTTL());
      byte[] sign_data = SignUtils.generateSigData(rrset_data, presig);

      Signature signer = pair.getSigner();

      if (signer == null)
      {
        // debug
        System.out.println("missing private key that goes with:\n"
            + pair.getDNSKEYRecord());
        throw new GeneralSecurityException(
            "cannot sign without a valid Signer "
                + "(probably missing private key)");
      }

      // sign the data.
      signer.update(sign_data);
      byte[] sig = signer.sign();

      // Convert to RFC 2536 format, if necessary.
      if (pair.getDNSKEYAlgorithm() == DNSSEC.DSA)
      {
        sig = SignUtils.convertDSASignature(((DSAPublicKey) pair.getPublic()).getParams(),
            sig);
      }
      RRSIGRecord sigrec = SignUtils.generateRRSIG(sig, presig);
      sigs.add(sigrec);
    }

    return sigs;
  }

  /**
   * Create a completely self-signed KEY RRset.
   * 
   * @param keypairs the public & private keypairs to use in the keyset.
   * @param start the RRSIG inception time.
   * @param expire the RRSIG expiration time.
   * @return a signed RRset.
   */
  public RRset makeKeySet(List keypairs, Date start, Date expire)
      throws IOException, GeneralSecurityException
  {
    // Generate a KEY RR set to sign.

    RRset keyset = new RRset();

    for (Iterator i = keypairs.iterator(); i.hasNext();)
    {
      DnsKeyPair pair = (DnsKeyPair) i.next();
      keyset.addRR(pair.getDNSKEYRecord());
    }

    List records = signRRset(keyset, keypairs, start, expire);

    for (Iterator i = records.iterator(); i.hasNext();)
    {
      keyset.addRR((Record) i.next());
    }

    return keyset;
  }

  /**
   * Conditionally sign an RRset and add it to the toList.
   * 
   * @param toList the list to which we are adding the processed RRsets.
   * @param zonename the zone apex name.
   * @param rrset the rrset under consideration.
   * @param keysigningkeypairs the List of KSKs..
   * @param zonekeypairs the List of zone keys.
   * @param start the RRSIG inception time.
   * @param expire the RRSIG expiration time.
   * @param fullySignKeyset if true, sign the zone apex keyset with both KSKs
   *          and ZSKs.
   * @param last_cut the name of the last delegation point encountered.
   * @return the name of the new last_cut.
   */
  private Name addRRset(List toList, Name zonename, RRset rrset,
      List keysigningkeypairs, List zonekeypairs, Date start, Date expire,
      boolean fullySignKeyset, Name last_cut) throws IOException,
      GeneralSecurityException
  {
    // add the records themselves
    for (Iterator i = rrset.rrs(); i.hasNext();)
    {
      toList.add(i.next());
    }

    int type = SignUtils.recordSecType(zonename,
        rrset.getName(),
        rrset.getType(),
        last_cut);

    // we don't sign non-normal sets (delegations, glue, invalid).
    // we also don't sign the zone key set unless we've been asked.
    if (type == SignUtils.RR_DELEGATION)
    {
      return rrset.getName();
    }
    if (type == SignUtils.RR_GLUE || type == SignUtils.RR_INVALID)
    {
      return last_cut;
    }

    // check for the zone apex keyset.
    if (rrset.getName().equals(zonename) && rrset.getType() == Type.DNSKEY)
    {
      // if we have key signing keys, sign the keyset with them,
      // otherwise we will just sign them with the zonesigning keys.
      if (keysigningkeypairs != null && keysigningkeypairs.size() > 0)
      {
        List sigs = signRRset(rrset, keysigningkeypairs, start, expire);
        toList.addAll(sigs);

        // If we aren't going to sign with all the keys, bail out now.
        if (!fullySignKeyset) return last_cut;
      }
    }

    // otherwise, we are OK to sign this set.
    List sigs = signRRset(rrset, zonekeypairs, start, expire);
    toList.addAll(sigs);

    return last_cut;
  }

  /**
   * Given a zone, sign it.
   * 
   * @param zonename the name of the zone.
   * @param records the records comprising the zone. They do not have to be in
   *          any particular order, as this method will order them as
   *          necessary.
   * @param keysigningkeypairs the key pairs that are designated as "key
   *          signing keys".
   * @param zonekeypair this key pairs that are designated as "zone signing
   *          keys".
   * @param start the RRSIG inception time.
   * @param expire the RRSIG expiration time.
   * @param useOptIn generate Opt-In style NXT records. It will consider any
   *          insecure delegation to be unsigned. To override this, include
   *          the name of the insecure delegation in the NXTIncludeNames list.
   * @param useConservativeOptIn if true, Opt-In NXT records will only be
   *          generated if there are insecure, unsigned delegations in the
   *          span. Not effect if useOptIn is false.
   * @param fullySignKeyset sign the zone apex keyset with all available keys.
   * @param NXTIncludeNames names that are to be included in the NXT chain
   *          regardless. This may be null and is only used if useOptIn is
   *          true.
   * 
   * @return an ordered list of {@link org.xbill.DNS.Record} objects,
   *         representing the signed zone.
   */
  public List signZone(Name zonename, List records, List keysigningkeypairs,
      List zonekeypairs, Date start, Date expire, boolean useOptIn,
      boolean useConservativeOptIn, boolean fullySignKeyset,
      List NSECIncludeNames) throws IOException, GeneralSecurityException
  {

    // Remove any existing DNSSEC records (NSEC, RRSIG)
    SignUtils.removeGeneratedRecords(zonename, records);
    // Sort the zone
    Collections.sort(records, new RecordComparator());

    // Remove any duplicate records.
    SignUtils.removeDuplicateRecords(records);

    // Generate DS records
    SignUtils.generateDSRecords(zonename, records);

    // Generate NXT records
    if (useOptIn)
    {
      SignUtils.generateOptInNSECRecords(zonename,
          records,
          NSECIncludeNames,
          useConservativeOptIn);
    }
    else
    {
      SignUtils.generateNSECRecords(zonename, records);
    }

    // Assemble into RRsets and sign.
    RRset rrset = new RRset();
    ArrayList signed_records = new ArrayList();
    Name last_cut = null;

    for (ListIterator i = records.listIterator(); i.hasNext();)
    {
      Record r = (Record) i.next();

      // First record
      if (rrset.getName() == null)
      {
        rrset.addRR(r);
        continue;
      }

      // Current record is part of the current RRset.
      if (rrset.getName().equals(r.getName())
          && rrset.getDClass() == r.getDClass()
          && rrset.getType() == r.getType())
      {
        rrset.addRR(r);
        continue;
      }

      // Otherwise, we have completed the RRset
      // Sign the records

      // add the RRset to the list of signed_records, regardless of
      // whether or not we actually end up signing the set.
      last_cut = addRRset(signed_records,
          zonename,
          rrset,
          keysigningkeypairs,
          zonekeypairs,
          start,
          expire,
          fullySignKeyset,
          last_cut);

      rrset.clear();
      rrset.addRR(r);
    }

    // add the last RR set
    addRRset(signed_records,
        zonename,
        rrset,
        keysigningkeypairs,
        zonekeypairs,
        start,
        expire,
        fullySignKeyset,
        last_cut);

    return signed_records;
  }
}
