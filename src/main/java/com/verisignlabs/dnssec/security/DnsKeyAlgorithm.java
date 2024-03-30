/*
 * Copyright (c) 2006, 2022 Verisign. All rights reserved.
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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
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
 * @author David Blacka
 */
public class DnsKeyAlgorithm {

  // Our base algorithm numbers. This is a normalization of the DNSSEC
  // algorithms (which are really signature algorithms). Thus RSASHA1,
  // RSASHA256, etc. all boil down to 'RSA' here. Similary, ECDSAP256SHA256 and
  // ECDSAP384SHA384 both become 'ECDSA'.
  public enum BaseAlgorithm {
    UNKNOWN,
    RSA,
    DH,
    DSA,
    ECC_GOST,
    ECDSA,
    EDDSA;
  }

  private static class AlgEntry {
    public int dnssecAlgorithm;
    public String sigName;
    public BaseAlgorithm baseType;

    public AlgEntry(int algorithm, String sigName, BaseAlgorithm baseType) {
      this.dnssecAlgorithm = algorithm;
      this.sigName = sigName;
      this.baseType = baseType;
    }
  }

  private static class ECAlgEntry extends AlgEntry {
    public ECParameterSpec ecSpec;

    public ECAlgEntry(int algorithm, String sigName, BaseAlgorithm baseType, ECParameterSpec spec) {
      super(algorithm, sigName, baseType);
      this.ecSpec = spec;
    }
  }

  private static class EdAlgEntry extends AlgEntry {
    public String curveName;
    public NamedParameterSpec paramSpec;

    public EdAlgEntry(int algorithm, String sigName, BaseAlgorithm baseType, String curveName) {
      super(algorithm, sigName, baseType);
      this.curveName = curveName;
      this.paramSpec = new NamedParameterSpec(curveName);
    }
  }

  /**
   * This is a mapping of algorithm identifier to Entry. The Entry contains the
   * data needed to map the algorithm to the various crypto implementations.
   */
  private HashMap<Integer, AlgEntry> mAlgorithmMap;
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
  private KeyPairGenerator mRSAKeyGenerator;
  /** This is a cached key pair generator for DSA keys. */
  private KeyPairGenerator mDSAKeyGenerator;
  /** This is a cached key pair generator for ECC GOST keys. */
  private KeyPairGenerator mECGOSTKeyGenerator;
  /** This is a cached key pair generator for ECDSA_P256 keys. */
  private KeyPairGenerator mECKeyGenerator;
  /** This is a cached key pair generator for EdDSA keys. */
  private KeyPairGenerator mEdKeyGenerator;

  private Logger log = Logger.getLogger(this.getClass().toString());

  /** This is the global instance for this class. */
  private static DnsKeyAlgorithm mInstance = null;

  public DnsKeyAlgorithm() {
    // Attempt to add the bouncycastle provider. This is so we can use this
    // provider if it is available, but not require the user to add it as one of
    // the java.security providers.
    try {
      Class<?> bcProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
      Provider bcProvider = (Provider) bcProviderClass.getDeclaredConstructor().newInstance();
      Security.addProvider(bcProvider);
    } catch (ReflectiveOperationException e) {
      log.fine("Unable to load BC provider");
    }

    initialize();
  }

  private void initialize() {
    mAlgorithmMap = new HashMap<>();
    mMnemonicToIdMap = new HashMap<>();
    mIdToMnemonicMap = new HashMap<>();

    // Load the standard DNSSEC algorithms.
    addAlgorithm(DNSSEC.Algorithm.RSAMD5, "MD5withRSA", BaseAlgorithm.RSA);
    addMnemonic("RSAMD5", DNSSEC.Algorithm.RSAMD5);

    addAlgorithm(DNSSEC.Algorithm.DH, "", BaseAlgorithm.DH);
    addMnemonic("DH", DNSSEC.Algorithm.DH);

    addAlgorithm(DNSSEC.Algorithm.DSA, "SHA1withDSA", BaseAlgorithm.DSA);
    addMnemonic("DSA", DNSSEC.Algorithm.DSA);

    addAlgorithm(DNSSEC.Algorithm.RSASHA1, "SHA1withRSA", BaseAlgorithm.RSA);
    addMnemonic("RSASHA1", DNSSEC.Algorithm.RSASHA1);
    addMnemonic("RSA", DNSSEC.Algorithm.RSASHA1);

    // Load the (now) standard aliases
    addAlias(DNSSEC.Algorithm.DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1", DNSSEC.Algorithm.DSA);
    addAlias(DNSSEC.Algorithm.RSA_NSEC3_SHA1, "RSA-NSEC3-SHA1", DNSSEC.Algorithm.RSASHA1);
    // Also recognize the BIND 9.6 mnemonics
    addMnemonic("NSEC3DSA", DNSSEC.Algorithm.DSA_NSEC3_SHA1);
    addMnemonic("NSEC3RSASHA1", DNSSEC.Algorithm.RSA_NSEC3_SHA1);

    // Algorithms added by RFC 5702.
    addAlgorithm(DNSSEC.Algorithm.RSASHA256, "SHA256withRSA", BaseAlgorithm.RSA);
    addMnemonic("RSASHA256", DNSSEC.Algorithm.RSASHA256);

    addAlgorithm(DNSSEC.Algorithm.RSASHA512, "SHA512withRSA", BaseAlgorithm.RSA);
    addMnemonic("RSASHA512", DNSSEC.Algorithm.RSASHA512);

    // ECC-GOST is not supported by Java 1.8's Sun crypto provider. The
    // bouncycastle.org provider, however, does support it.
    // GostR3410-2001-CryptoPro-A is the named curve in the BC provider, but we
    // will get the parameters directly.
    addAlgorithm(DNSSEC.Algorithm.ECC_GOST, "GOST3411withECGOST3410", BaseAlgorithm.ECC_GOST, null);
    addMnemonic("ECCGOST", DNSSEC.Algorithm.ECC_GOST);
    addMnemonic("ECC-GOST", DNSSEC.Algorithm.ECC_GOST);

    addAlgorithm(DNSSEC.Algorithm.ECDSAP256SHA256, "SHA256withECDSA", BaseAlgorithm.ECDSA, "secp256r1");
    addMnemonic("ECDSAP256SHA256", DNSSEC.Algorithm.ECDSAP256SHA256);
    addMnemonic("ECDSA-P256", DNSSEC.Algorithm.ECDSAP256SHA256);

    addAlgorithm(DNSSEC.Algorithm.ECDSAP384SHA384, "SHA384withECDSA", BaseAlgorithm.ECDSA, "secp384r1");
    addMnemonic("ECDSAP384SHA384", DNSSEC.Algorithm.ECDSAP384SHA384);
    addMnemonic("ECDSA-P384", DNSSEC.Algorithm.ECDSAP384SHA384);

    // For the Edwards Curve implementations, we just initialize Signature and
    // KeyPairGenerator with the curve name.
    addAlgorithm(15, "Ed25519", BaseAlgorithm.EDDSA, "Ed25519");
    addMnemonic("ED25519", 15);
    addAlgorithm(16, "Ed448", BaseAlgorithm.EDDSA, "Ed448");
    addMnemonic(("ED448"), 16);
  }

  private void addAlgorithm(int algorithm, String sigName, BaseAlgorithm baseType) {
    mAlgorithmMap.put(algorithm, new AlgEntry(algorithm, sigName, baseType));
  }

  /**
   * Add a ECDSA (algorithms 13/14) to the set, looking up the curve names.
   *
   * @param algorithm the DNSSEC algorithm number.
   * @param sigName   the name of the signature scheme.
   * @param curveName the official name of the elliptic curve in our crypto
   *                  library (SunEC).
   */
  private void addECDSAAlgorithm(int algorithm, String sigName, String curveName) {
    ECParameterSpec ecSpec = ECSpecFromAlgorithm(algorithm);
    if (ecSpec == null)
      ecSpec = ECSpecFromName(curveName);
    if (ecSpec == null)
      return;

    // Check to see if we can get a Signature object for this algorithm.
    try {
      Signature.getInstance(sigName);
    } catch (NoSuchAlgorithmException e) {
      // for now, let's find out
      log.severe("could not get signature for " + sigName + ": " + e.getMessage());
      // If not, do not add the algorithm.
      return;
    }
    ECAlgEntry entry = new ECAlgEntry(algorithm, sigName, BaseAlgorithm.ECDSA, ecSpec);
    mAlgorithmMap.put(algorithm, entry);
  }

  /**
   * Add an EdDSA (Edwards curve algorithms, DNSSEC algorithms 15/16), looking up
   * the curve.
   * 
   * @param algorithm the DNSSEC algorithm numer.
   * @param sigName   the name of the signing scheme. For EdDSA, this is the same
   *                  as the curve.
   * @param curveName the name of the curve.
   */
  private void addEdDSAAlgorithm(int algorithm, String sigName, String curveName) {
    // Check to see if we can get a Signature object for this algorithm.
    try {
      Signature.getInstance(sigName);
    } catch (NoSuchAlgorithmException e) {
      // for now, let's find out
      log.severe("could not get signature for EdDSA curve" + curveName + ": " + e.getMessage());
      // If not, do not add the algorithm.
      return;
    }
    EdAlgEntry entry = new EdAlgEntry(algorithm, sigName, BaseAlgorithm.EDDSA, curveName);
    mAlgorithmMap.put(algorithm, entry);
  }

  /**
   * Add an Elliptic Curve algorithm given a signing scheme and curve name.
   * 
   * @param algorithm the DNSSEC algorithm number
   * @param sigName   the signature scheme (e.g., which crypto hash function are
   *                  we using?)
   * @param baseType  the base type (either ECDSA or EDDSA).
   * @param curveName the name of the curve.
   */
  private void addAlgorithm(int algorithm, String sigName, BaseAlgorithm baseType, String curveName) {
    if (baseType == BaseAlgorithm.ECDSA) {
      addECDSAAlgorithm(algorithm, sigName, curveName);
    } else if (baseType == BaseAlgorithm.EDDSA) {
      addEdDSAAlgorithm(algorithm, sigName, curveName);
    }
  }

  /**
   * Add an alternate mnemonic for an algorithm.
   * 
   * @param m   the new mnemonic.
   * @param alg the DNSSEC algorithm number.
   */
  private void addMnemonic(String m, int alg) {
    // Do not add mnemonics for algorithms that ended up not actually being
    // supported.
    if (!mAlgorithmMap.containsKey(alg))
      return;

    mMnemonicToIdMap.put(m.toUpperCase(), alg);
    mIdToMnemonicMap.computeIfAbsent(alg, k -> m);
  }

  public void addAlias(int alias, String mnemonic, int origAlgorithm) {
    if (mAlgorithmMap.containsKey(alias)) {
      log.warning("Unable to alias algorithm " + alias + " because it already exists.");
      return;
    }

    if (!mAlgorithmMap.containsKey(origAlgorithm)) {
      log.warning("Unable to alias algorithm " + alias
          + " to unknown algorithm identifier " + origAlgorithm);
      return;
    }

    mAlgorithmMap.put(alias, mAlgorithmMap.get(origAlgorithm));

    if (mnemonic != null) {
      addMnemonic(mnemonic, alias);
    }
  }

  private AlgEntry getEntry(int alg) {
    return mAlgorithmMap.get(alg);
  }

  // For curves where we don't (or can't) get the parameters from a standard
  // name, we can construct the parameters here. For now, we only do this for
  // the ECC-GOST curve.
  private ECParameterSpec ECSpecFromAlgorithm(int algorithm) {
    if (algorithm == DNSSEC.Algorithm.ECC_GOST) {
      // From RFC 4357 Section 11.4
      BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);
      BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16);
      BigInteger b = new BigInteger("A6", 16);
      BigInteger gx = new BigInteger("1", 16);
      BigInteger gy = new BigInteger("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14", 16);
      BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16);

      EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), a, b);
      return new ECParameterSpec(curve, new ECPoint(gx, gy), n, 1);
    }
    return null;
  }

  // Fetch the curve parameters from a named ECDSA curve.
  private ECParameterSpec ECSpecFromName(String stdName) {
    try {
      AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
      ECGenParameterSpec ecgSpec = new ECGenParameterSpec(stdName);
      ap.init(ecgSpec);
      return ap.getParameterSpec(ECParameterSpec.class);
    } catch (NoSuchAlgorithmException e) {
      log.info("Elliptic Curve not supported by any crypto provider: " + e.getMessage());
    } catch (InvalidParameterSpecException e) {
      log.info("Elliptic Curve " + stdName + " not supported");
    }
    return null;
  }

  public String[] supportedAlgMnemonics() {
    Set<Integer> keyset = mAlgorithmMap.keySet();
    Integer[] algs = keyset.toArray(new Integer[keyset.size()]);
    Arrays.sort(algs);

    String[] result = new String[algs.length];
    for (int i = 0; i < algs.length; i++) {
      result[i] = mIdToMnemonicMap.get(algs[i]);
    }

    return result;
  }

  /**
   * Return a Signature object for the specified DNSSEC algorithm.
   * 
   * @param algorithm The DNSSEC algorithm (by number).
   * @return a Signature object.
   */
  public Signature getSignature(int algorithm) {
    AlgEntry entry = getEntry(algorithm);
    if (entry == null)
      return null;

    Signature s = null;

    try {
      s = Signature.getInstance(entry.sigName);
    } catch (NoSuchAlgorithmException e) {
      log.severe("Unable to get signature implementation for algorithm " + algorithm
          + ": " + e);
    }

    return s;
  }

  /**
   * Given one of the ECDSA algorithms (ECDSAP256SHA256, etc.) return the
   * elliptic curve parameters.
   *
   * @param algorithm The DNSSEC algorithm number.
   * @return The calculated JCA ECParameterSpec for that DNSSEC algorithm, or
   *         null if not a recognized/supported EC algorithm.
   */
  public ECParameterSpec getEllipticCurveParams(int algorithm) {
    AlgEntry entry = getEntry(algorithm);
    if (entry == null)
      return null;
    if (!(entry instanceof ECAlgEntry))
      return null;
    ECAlgEntry ecEntry = (ECAlgEntry) entry;

    return ecEntry.ecSpec;
  }

  /**
   * Given one of the EdDSA algorithms (ED25519 or ED448), return the named
   * parameter spec.
   *
   * @param algorithm The DNSSEC algorithm number.
   * @return The NamedParameterSpec for that DNSSEC algorithm, nor null if the
   *         algorithm wasn't a supported EdDSA algorithm.
   */
  public NamedParameterSpec getEdwardsCurveSpec(int algorithm) {
    AlgEntry entry = getEntry(algorithm);
    if (entry == null)
      return null;
    if (!(entry instanceof EdAlgEntry))
      return null;
    EdAlgEntry edEntry = (EdAlgEntry) entry;

    return edEntry.paramSpec;
  }

  /**
   * Translate a possible algorithm alias back to the original DNSSEC algorithm
   * number
   *
   * @param algorithm a DNSSEC algorithm that may be an alias.
   * @return -1 if the algorithm isn't recognised, the orignal algorithm number
   *         if it is.
   */
  public int originalAlgorithm(int algorithm) {
    AlgEntry entry = getEntry(algorithm);
    if (entry == null)
      return -1;
    return entry.dnssecAlgorithm;
  }

  /**
   * Test if a given algorithm is supported.
   *
   * @param algorithm The DNSSEC algorithm number.
   * @return true if the algorithm is a recognized and supported algorithm or
   *         alias.
   */
  public boolean supportedAlgorithm(int algorithm) {
    return mAlgorithmMap.containsKey(algorithm);
  }

  /**
   * Given an algorithm mnemonic, convert the mnemonic to a DNSSEC algorithm
   * number.
   *
   * @param s The mnemonic string. This is case-insensitive.
   * @return -1 if the mnemonic isn't recognized or supported, the algorithm
   *         number if it is.
   */
  public int stringToAlgorithm(String s) {
    Integer alg = mMnemonicToIdMap.get(s.toUpperCase());
    if (alg != null)
      return alg.intValue();
    return -1;
  }

  /**
   * Given a DNSSEC algorithm number, return the "preferred" mnemonic.
   *
   * @param algorithm A DNSSEC algorithm number.
   * @return The preferred mnemonic string, or null if not supported or
   *         recognized.
   */
  public String algToString(int algorithm) {
    return mIdToMnemonicMap.get(algorithm);
  }

  public BaseAlgorithm baseType(int algorithm) {
    AlgEntry entry = getEntry(algorithm);
    if (entry != null)
      return entry.baseType;
    return BaseAlgorithm.UNKNOWN;
  }

  public boolean isDSA(int algorithm) {
    return (baseType(algorithm) == BaseAlgorithm.DSA);
  }

  public KeyPair generateKeyPair(int algorithm, int keysize, boolean useLargeExp)
      throws NoSuchAlgorithmException {
    KeyPair pair = null;
    switch (baseType(algorithm)) {
      case RSA: {
        if (mRSAKeyGenerator == null) {
          mRSAKeyGenerator = KeyPairGenerator.getInstance("RSA");
        }

        RSAKeyGenParameterSpec rsaSpec;
        if (useLargeExp) {
          rsaSpec = new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4);
        } else {
          rsaSpec = new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F0);
        }
        try {
          mRSAKeyGenerator.initialize(rsaSpec);
        } catch (InvalidAlgorithmParameterException e) {
          // Fold the InvalidAlgorithmParameterException into our existing
          // thrown exception. Ugly, but requires less code change.
          throw new NoSuchAlgorithmException("invalid key parameter spec");
        }

        pair = mRSAKeyGenerator.generateKeyPair();
        break;
      }
      case DSA: {
        if (mDSAKeyGenerator == null) {
          mDSAKeyGenerator = KeyPairGenerator.getInstance("DSA");
        }
        mDSAKeyGenerator.initialize(keysize);
        pair = mDSAKeyGenerator.generateKeyPair();
        break;
      }
      case ECC_GOST: {
        if (mECGOSTKeyGenerator == null) {
          mECGOSTKeyGenerator = KeyPairGenerator.getInstance("ECGOST3410");
        }

        ECParameterSpec ecSpec = getEllipticCurveParams(algorithm);
        try {
          mECGOSTKeyGenerator.initialize(ecSpec);
        } catch (InvalidAlgorithmParameterException e) {
          // Fold the InvalidAlgorithmParameterException into our existing
          // thrown exception. Ugly, but requires less code change.
          throw new NoSuchAlgorithmException("invalid key parameter spec");
        }
        pair = mECGOSTKeyGenerator.generateKeyPair();
        break;
      }
      case ECDSA: {
        if (mECKeyGenerator == null) {
          mECKeyGenerator = KeyPairGenerator.getInstance("EC");
        }

        ECParameterSpec ecSpec = getEllipticCurveParams(algorithm);
        try {
          mECKeyGenerator.initialize(ecSpec);
        } catch (InvalidAlgorithmParameterException e) {
          // Fold the InvalidAlgorithmParameterException into our existing
          // thrown exception. Ugly, but requires less code change.
          throw new NoSuchAlgorithmException("invalid key parameter spec");
        }
        pair = mECKeyGenerator.generateKeyPair();
        break;
      }
      case EDDSA: {
        EdAlgEntry entry = (EdAlgEntry) getEntry(algorithm);
        mEdKeyGenerator = KeyPairGenerator.getInstance(entry.curveName);

        pair = mEdKeyGenerator.generateKeyPair();
        break;
      }
      default:
        throw new NoSuchAlgorithmException("Alg " + algorithm);
    }

    return pair;
  }

  public KeyPair generateKeyPair(int algorithm, int keysize)
      throws NoSuchAlgorithmException {
    return generateKeyPair(algorithm, keysize, false);
  }

  public static DnsKeyAlgorithm getInstance() {
    if (mInstance == null)
      mInstance = new DnsKeyAlgorithm();
    return mInstance;
  }
}
