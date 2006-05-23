/*
 * $Id$
 * 
 * Copyright (c) 2006 VeriSign. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. The name of the author may not
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 */

package com.verisignlabs.dnssec.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashMap;
import java.util.logging.Logger;

import org.xbill.DNS.DNSSEC;

/**
 * This class handles translated DNS signing algorithm identifiers into
 * various usable java implementations.
 * 
 * Besides centralizing the logic surrounding matching a DNSKEY algorithm
 * identifier with various crypto implementations, it also handles algorithm
 * aliasing -- that is, defining a new algorithm identifier to be equivalent
 * to an existing identifier.
 * 
 * @author David Blacka (orig)
 * @author $Author: davidb $ (latest)
 * @version $Revision: 2098 $
 */
public class DnsKeyAlgorithm
{

  public static final int UNKNOWN = -1;
  public static final int RSA     = 1;
  public static final int DH      = 2;
  public static final int DSA     = 3;

  private static class Entry
  {
    public String sigName;
    public int    baseType;

    public Entry(String sigName, int baseType)
    {
      this.sigName = sigName;
      this.baseType = baseType;
    }
  }

  /**
   * This is a mapping of algorithm identifier to Entry. The Entry contains
   * the data needed to map the algorithm to the various crypto
   * implementations.
   */
  private HashMap                mAlgorithmMap;
  /**
   * This is a mapping of algorithm mnemonics to algorithm identifiers.
   */
  private HashMap                mMnemonicToIdMap;
  /**
   * This is a mapping of identifiers to preferred mnemonic -- the preferred
   * one is the first defined one
   */
  private HashMap                mIdToMnemonicMap;

  /** This is a cached key pair generator for RSA keys. */
  private KeyPairGenerator       mRSAKeyGenerator;
  /** This is a cache key pair generator for DSA keys. */
  private KeyPairGenerator       mDSAKeyGenerator;

  private Logger                 log       = Logger.getLogger(this.getClass()
                                               .toString());

  /** This is the global instance for this class. */
  private static DnsKeyAlgorithm mInstance = null;

  public DnsKeyAlgorithm()
  {
    mAlgorithmMap = new HashMap();
    mMnemonicToIdMap = new HashMap();
    mIdToMnemonicMap = new HashMap();
    
    // Load the standard DNSSEC algorithms.
    addAlgorithm(DNSSEC.RSAMD5, new Entry("MD5withRSA", RSA));
    addMnemonic("RSAMD5", DNSSEC.RSAMD5);

    addAlgorithm(DNSSEC.DH, new Entry("", DH));
    addMnemonic("DH", DNSSEC.DH);

    addAlgorithm(DNSSEC.DSA, new Entry("SHA1withDSA", DSA));
    addMnemonic("DSA", DNSSEC.DSA);

    addAlgorithm(DNSSEC.RSASHA1, new Entry("SHA1withRSA", RSA));
    addMnemonic("RSASHA1", DNSSEC.RSASHA1);
    addMnemonic("RSA", DNSSEC.RSASHA1);
  }

  private void addAlgorithm(int algorithm, Entry entry)
  {
    Integer a = new Integer(algorithm);
    mAlgorithmMap.put(a, entry);
  }

  private void addMnemonic(String m, int alg)
  {
    Integer a = new Integer(alg);
    mMnemonicToIdMap.put(m.toUpperCase(), a);
    if (! mIdToMnemonicMap.containsKey(a))
    {
      mIdToMnemonicMap.put(a, m);
    }
  }

  public void addAlias(int alias, String mnemonic, int original_algorithm)
  {
    Integer a = new Integer(alias);
    Integer o = new Integer(original_algorithm);

    if (mAlgorithmMap.containsKey(a))
    {
      log.warning("Unable to alias algorithm " + alias
          + " because it already exists.");
      return;
    }

    if (!mAlgorithmMap.containsKey(o))
    {
      log.warning("Unable to alias algorith " + alias
          + " to unknown algorithm identifier " + original_algorithm);
      return;
    }

    mAlgorithmMap.put(a, mAlgorithmMap.get(o));

    if (mnemonic != null)
    {
      addMnemonic(mnemonic, alias);
    }
  }

  private Entry getEntry(int alg)
  {
    return (Entry) mAlgorithmMap.get(new Integer(alg));
  }

  public Signature getSignature(int algorithm)
  {
    Entry entry = getEntry(algorithm);
    if (entry == null) return null;

    Signature s = null;

    try
    {
      s = Signature.getInstance(entry.sigName);
    }
    catch (NoSuchAlgorithmException e)
    {
      log.severe("Unable to get signature implementation for algorithm "
          + algorithm + ": " + e);
    }

    return s;
  }

  public int stringToAlgorithm(String s)
  {
    Integer alg = (Integer) mMnemonicToIdMap.get(s.toUpperCase());
    if (alg != null) return alg.intValue();
    return -1;
  }

  public String algToString(int algorithm)
  {
    return (String) mIdToMnemonicMap.get(new Integer(algorithm));
  }
  
  public int baseType(int algorithm)
  {
    Entry entry = getEntry(algorithm);
    if (entry != null) return entry.baseType;
    return UNKNOWN;
  }

  public int standardAlgorithm(int algorithm)
  {
    switch (baseType(algorithm))
    {
      case RSA :
        return DNSSEC.RSASHA1;
      case DSA :
        return DNSSEC.DSA;
      case DH :
        return DNSSEC.DH;
      default :
        return UNKNOWN;
    }
  }

  public boolean isDSA(int algorithm)
  {
    return (baseType(algorithm) == DSA);
  }

  public KeyPair generateKeyPair(int algorithm, int keysize)
      throws NoSuchAlgorithmException
  {
    KeyPair pair = null;
    switch (baseType(algorithm))
    {
      case RSA :
        if (mRSAKeyGenerator == null)
        {
          mRSAKeyGenerator = KeyPairGenerator.getInstance("RSA");
        }
        mRSAKeyGenerator.initialize(keysize);
        pair = mRSAKeyGenerator.generateKeyPair();
        break;
      case DSA :
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

    return pair;
  }

  public static DnsKeyAlgorithm getInstance()
  {
    if (mInstance == null) mInstance = new DnsKeyAlgorithm();
    return mInstance;
  }
}
