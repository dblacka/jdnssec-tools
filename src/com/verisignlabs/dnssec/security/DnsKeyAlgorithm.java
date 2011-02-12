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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.logging.Logger;

import org.xbill.DNS.DNSSEC;

/**
 * This class handles translating DNS signing algorithm identifiers into various
 * usable java implementations.
 * 
 * Besides centralizing the logic surrounding matching a DNSKEY algorithm
 * identifier with various crypto implementations, it also handles algorithm
 * aliasing -- that is, defining a new algorithm identifier to be equivalent to
 * an existing identifier.
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
   * This is a mapping of algorithm identifier to Entry. The Entry contains the
   * data needed to map the algorithm to the various crypto implementations.
   */
  private HashMap<Integer, Entry>  mAlgorithmMap;
  /**
   * This is a mapping of algorithm mnemonics to algorithm identifiers.
   */
  private HashMap<String, Integer> mMnemonicToIdMap;
  /**
   * This is a mapping of identifiers to preferred mnemonic -- the preferred one
   * is the first defined one
   */
  private HashMap<Integer, String> mIdToMnemonicMap;

  /** This is a cached key pair generator for RSA keys. */
  private KeyPairGenerator         mRSAKeyGenerator;
  /** This is a cache key pair generator for DSA keys. */
  private KeyPairGenerator         mDSAKeyGenerator;

  private Logger                   log       = Logger.getLogger(this.getClass().toString());

  /** This is the global instance for this class. */
  private static DnsKeyAlgorithm   mInstance = null;

  public DnsKeyAlgorithm()
  {
    mAlgorithmMap = new HashMap<Integer, Entry>();
    mMnemonicToIdMap = new HashMap<String, Integer>();
    mIdToMnemonicMap = new HashMap<Integer, String>();

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

    // Load the (now) standard aliases
    addAlias(DNSSEC.DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1", DNSSEC.DSA);
    addAlias(DNSSEC.RSA_NSEC3_SHA1, "RSA-NSEC3-SHA1", DNSSEC.RSASHA1);
    // Also recognize the BIND 9.6 mnemonics
    addMnemonic("NSEC3DSA", DNSSEC.DSA_NSEC3_SHA1);
    addMnemonic("NSEC3RSASHA1", DNSSEC.RSA_NSEC3_SHA1);

    // Algorithms added by RFC 5702.
    // NOTE: these algorithms aren't available in Java 1.4's sunprovider
    // implementation (but are in java 1.5's and later).
    addAlgorithm(8, new Entry("SHA256withRSA", RSA));
    addMnemonic("RSASHA256", 8);

    addAlgorithm(10, new Entry("SHA512withRSA", RSA));
    addMnemonic("RSASHA512", 10);
  }

  private void addAlgorithm(int algorithm, Entry entry)
  {
    mAlgorithmMap.put(algorithm, entry);
  }

  private void addMnemonic(String m, int alg)
  {
    mMnemonicToIdMap.put(m.toUpperCase(), alg);
    if (!mIdToMnemonicMap.containsKey(alg))
    {
      mIdToMnemonicMap.put(alg, m);
    }
  }

  public void addAlias(int alias, String mnemonic, int original_algorithm)
  {
    if (mAlgorithmMap.containsKey(alias))
    {
      log.warning("Unable to alias algorithm " + alias + " because it already exists.");
      return;
    }

    if (!mAlgorithmMap.containsKey(original_algorithm))
    {
      log.warning("Unable to alias algorith " + alias
          + " to unknown algorithm identifier " + original_algorithm);
      return;
    }

    mAlgorithmMap.put(alias, mAlgorithmMap.get(original_algorithm));

    if (mnemonic != null)
    {
      addMnemonic(mnemonic, alias);
    }
  }

  private Entry getEntry(int alg)
  {
    return mAlgorithmMap.get(alg);
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
      log.severe("Unable to get signature implementation for algorithm " + algorithm
          + ": " + e);
    }

    return s;
  }

  public int stringToAlgorithm(String s)
  {
    Integer alg = mMnemonicToIdMap.get(s.toUpperCase());
    if (alg != null) return alg.intValue();
    return -1;
  }

  public String algToString(int algorithm)
  {
    return mIdToMnemonicMap.get(algorithm);
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
      case RSA:
        return DNSSEC.RSASHA1;
      case DSA:
        return DNSSEC.DSA;
      case DH:
        return DNSSEC.DH;
      default:
        return UNKNOWN;
    }
  }

  public boolean isDSA(int algorithm)
  {
    return (baseType(algorithm) == DSA);
  }

  public KeyPair generateKeyPair(int algorithm, int keysize, boolean useLargeExp)
      throws NoSuchAlgorithmException
  {
    KeyPair pair = null;
    switch (baseType(algorithm))
    {
      case RSA:
        if (mRSAKeyGenerator == null)
        {
          mRSAKeyGenerator = KeyPairGenerator.getInstance("RSA");
        }

        RSAKeyGenParameterSpec rsa_spec;
        if (useLargeExp)
        {
          rsa_spec = new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4);
        }
        else
        {
          rsa_spec = new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F0);
        }
        try
        {
          mRSAKeyGenerator.initialize(rsa_spec);
        }
        catch (InvalidAlgorithmParameterException e)
        {
          // Fold the InvalidAlgorithmParameterException into our existing
          // thrown exception. Ugly, but requires less code change.
          throw new NoSuchAlgorithmException("invalid key parameter spec");
        }

        pair = mRSAKeyGenerator.generateKeyPair();
        break;
      case DSA:
        if (mDSAKeyGenerator == null)
        {
          mDSAKeyGenerator = KeyPairGenerator.getInstance("DSA");
        }
        mDSAKeyGenerator.initialize(keysize);
        pair = mDSAKeyGenerator.generateKeyPair();
        break;
      default:
        throw new NoSuchAlgorithmException("Alg " + algorithm);
    }

    return pair;
  }

  public KeyPair generateKeyPair(int algorithm, int keysize)
      throws NoSuchAlgorithmException
  {
    return generateKeyPair(algorithm, keysize, false);
  }

  public static DnsKeyAlgorithm getInstance()
  {
    if (mInstance == null) mInstance = new DnsKeyAlgorithm();
    return mInstance;
  }
}
