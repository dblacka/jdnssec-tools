// Copyright (C) 2001-2003, 2022 VeriSign, Inc.
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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Name;
import org.xbill.DNS.utils.base64;

/**
 * This class handles conversions between JCA key formats and DNSSEC and BIND9
 * key formats.
 *
 * @author David Blacka
 */
public class DnsKeyConverter {
  private KeyFactory mRSAKeyFactory;
  private KeyFactory mDSAKeyFactory;
  private KeyFactory mDHKeyFactory;
  private KeyFactory mECKeyFactory;
  private KeyFactory mEdKeyFactory;
  private DnsKeyAlgorithm mAlgorithms;
  
  private Logger log = Logger.getLogger(this.getClass().toString());

  public DnsKeyConverter() {
    mAlgorithms = DnsKeyAlgorithm.getInstance();
  }

  /**
   * Given a DNS KEY record, return the JCA public key
   *
   * @throws NoSuchAlgorithmException
   */
  public PublicKey parseDNSKEYRecord(DNSKEYRecord pKeyRecord)
      throws NoSuchAlgorithmException {
    if (pKeyRecord.getKey() == null)
      return null;

    // Because we have arbitrarily aliased algorithms, we need to possibly
    // translate the aliased algorithm back to the actual algorithm.
    int originalAlgorithm = mAlgorithms.originalAlgorithm(pKeyRecord.getAlgorithm());

    if (originalAlgorithm <= 0)
      throw new NoSuchAlgorithmException("DNSKEY algorithm "
          + pKeyRecord.getAlgorithm() + " is unrecognized");

    if (pKeyRecord.getAlgorithm() != originalAlgorithm) {
      pKeyRecord = new DNSKEYRecord(pKeyRecord.getName(), pKeyRecord.getDClass(),
          pKeyRecord.getTTL(), pKeyRecord.getFlags(),
          pKeyRecord.getProtocol(), originalAlgorithm,
          pKeyRecord.getKey());
    }

    try {
      // This uses DNSJava's DNSSEC.toPublicKey() method.
      return pKeyRecord.getPublicKey();
    } catch (DNSSECException e) {
      throw new NoSuchAlgorithmException(e);
    }
  }

  /**
   * Given a JCA public key and the ancillary data, generate a DNSKEY record.
   */
  public DNSKEYRecord generateDNSKEYRecord(Name name, int dclass, long ttl,
      int flags, int alg, PublicKey key) {
    try {
      int origAlgorithm = mAlgorithms.originalAlgorithm(alg);
      DNSKEYRecord keyrec = new DNSKEYRecord(name, dclass, ttl, flags, DNSKEYRecord.Protocol.DNSSEC, origAlgorithm,
          key);
      if (origAlgorithm == alg) {
        return keyrec;
      }
      return new DNSKEYRecord(name, dclass, ttl, flags, DNSKEYRecord.Protocol.DNSSEC, alg, keyrec.getKey());
    } catch (DNSSECException e) {
      log.severe("Unable to generated a DNSKEYRecord: " + e);
      // This mimics the behavior of KEYConverter.buildRecord(), which would
      // return null if the algorithm was unknown.
      return null;
    }
  }

  // Private Key Specific Parsing routines

  /**
   * Convert a PKCS#8 encoded private key into a PrivateKey object.
   */
  public PrivateKey convertEncodedPrivateKey(byte[] key, int algorithm) {
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
    try {
      switch (mAlgorithms.baseType(algorithm)) {
        case RSA:
          return mRSAKeyFactory.generatePrivate(spec);
        case DSA:
          return mDSAKeyFactory.generatePrivate(spec);
        default:
          return null;
      }
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
    }

    return null;
  }

  /**
   * A simple wrapper for parsing integers; parse failures result in the
   * supplied default.
   */
  private static int parseInt(String s, int def) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      return def;
    }
  }

  /**
   * @return a JCA private key, given a BIND9-style textual encoding
   */
  public PrivateKey parsePrivateKeyString(String key)
      throws IOException, NoSuchAlgorithmException {
    StringTokenizer lines = new StringTokenizer(key, "\n");

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      if (line.startsWith("Private-key-format: ")) {
        if (!val.equals("v1.2") && !val.equals("v1.3")) {
          throw new IOException("unsupported private key format: " + val);
        }
      } else if (line.startsWith("Algorithm: ")) {
        // here we assume that the value looks like # (MNEM) or just the
        // number.
        String[] toks = val.split("\\s", 2);
        val = toks[0];
        int alg = parseInt(val, -1);

        switch (mAlgorithms.baseType(alg)) {
          case RSA:
            return parsePrivateRSA(lines);
          case DSA:
            return parsePrivateDSA(lines);
          case DH:
            return parsePrivateDH(lines);
          case ECDSA:
            return parsePrivateECDSA(lines, alg);
          case EDDSA:
            return parsePrivateEdDSA(lines, alg);
          default:
            throw new IOException("unsupported private key algorithm: " + val);
        }
      }
    }
    return null;
  }

  /**
   * @return the value part of an "attribute:value" pair. The value is trimmed.
   */
  private static String value(String av) {
    if (av == null)
      return null;

    int pos = av.indexOf(':');
    if (pos < 0)
      return av;

    if (pos >= av.length())
      return null;

    return av.substring(pos + 1).trim();
  }

  /**
   * Given the rest of the RSA BIND9 string format private key, parse and
   * translate into a JCA private key
   *
   * @throws NoSuchAlgorithmException
   *                                  if the RSA algorithm is not available.
   */
  private PrivateKey parsePrivateRSA(StringTokenizer lines)
      throws NoSuchAlgorithmException {
    BigInteger modulus = null;
    BigInteger publicExponent = null;
    BigInteger privateExponent = null;
    BigInteger primeP = null;
    BigInteger primeQ = null;
    BigInteger primePExponent = null;
    BigInteger primeQExponent = null;
    BigInteger coefficient = null;

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Modulus: ")) {
        modulus = new BigInteger(1, data);
      } else if (line.startsWith("PublicExponent: ")) {
        publicExponent = new BigInteger(1, data);
      } else if (line.startsWith("PrivateExponent: ")) {
        privateExponent = new BigInteger(1, data);
      } else if (line.startsWith("Prime1: ")) {
        primeP = new BigInteger(1, data);
      } else if (line.startsWith("Prime2: ")) {
        primeQ = new BigInteger(1, data);
      } else if (line.startsWith("Exponent1: ")) {
        primePExponent = new BigInteger(1, data);
      } else if (line.startsWith("Exponent2: ")) {
        primeQExponent = new BigInteger(1, data);
      } else if (line.startsWith("Coefficient: ")) {
        coefficient = new BigInteger(1, data);
      }
    }

    try {
      KeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExponent,
          privateExponent, primeP,
          primeQ, primePExponent,
          primeQExponent, coefficient);
      if (mRSAKeyFactory == null) {
        mRSAKeyFactory = KeyFactory.getInstance("RSA");
      }
      return mRSAKeyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9 style DH private key, parse the key
   * info and translate it into a JCA private key.
   *
   * @throws NoSuchAlgorithmException
   *                                  if the DH algorithm is not available.
   */
  private PrivateKey parsePrivateDH(StringTokenizer lines)
      throws NoSuchAlgorithmException {
    BigInteger p = null;
    BigInteger x = null;
    BigInteger g = null;

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Prime(p): ")) {
        p = new BigInteger(1, data);
      } else if (line.startsWith("Generator(g): ")) {
        g = new BigInteger(1, data);
      } else if (line.startsWith("Private_value(x): ")) {
        x = new BigInteger(1, data);
      }
    }

    try {
      KeySpec spec = new DHPrivateKeySpec(x, p, g);
      if (mDHKeyFactory == null) {
        mDHKeyFactory = KeyFactory.getInstance("DH");
      }
      return mDHKeyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9 style DSA private key, parse the key
   * info and translate it into a JCA private key.
   *
   * @throws NoSuchAlgorithmException
   *                                  if the DSA algorithm is not available.
   */
  private PrivateKey parsePrivateDSA(StringTokenizer lines)
      throws NoSuchAlgorithmException {
    BigInteger p = null;
    BigInteger q = null;
    BigInteger g = null;
    BigInteger x = null;

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Prime(p): ")) {
        p = new BigInteger(1, data);
      } else if (line.startsWith("Subprime(q): ")) {
        q = new BigInteger(1, data);
      } else if (line.startsWith("Base(g): ")) {
        g = new BigInteger(1, data);
      } else if (line.startsWith("Private_value(x): ")) {
        x = new BigInteger(1, data);
      }
    }

    try {
      KeySpec spec = new DSAPrivateKeySpec(x, p, q, g);
      if (mDSAKeyFactory == null) {
        mDSAKeyFactory = KeyFactory.getInstance("DSA");
      }
      return mDSAKeyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9-style ECDSA private key, parse the key
   * info and translate it into a JCA private key object.
   * 
   * @param lines The remaining lines in a private key file (after
   * @throws NoSuchAlgorithmException
   *                                  If elliptic curve is not available.
   */
  private PrivateKey parsePrivateECDSA(StringTokenizer lines, int algorithm)
      throws NoSuchAlgorithmException {
    BigInteger s = null;

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("PrivateKey: ")) {
        s = new BigInteger(1, data);
      }
    }

    if (mECKeyFactory == null) {
      mECKeyFactory = KeyFactory.getInstance("EC");
    }
    ECParameterSpec ecSpec = mAlgorithms.getEllipticCurveParams(algorithm);
    if (ecSpec == null) {
      throw new NoSuchAlgorithmException("DNSSEC algorithm " + algorithm +
          " is not a recognized Elliptic Curve algorithm");
    }

    KeySpec spec = new ECPrivateKeySpec(s, ecSpec);

    try {
      return mECKeyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9-style ECDSA private key, parse the key
   * info and translate it into a JCA private key object.
   * 
   * @param lines The remaining lines in a private key file (after
   * @throws NoSuchAlgorithmException
   *                                  If elliptic curve is not available.
   */
  private PrivateKey parsePrivateEdDSA(StringTokenizer lines, int algorithm)
      throws NoSuchAlgorithmException {
    byte[] seed = null;

    while (lines.hasMoreTokens()) {
      String line = lines.nextToken();
      if (line == null)
        continue;

      if (line.startsWith("#"))
        continue;

      String val = value(line);
      if (val == null)
        continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("PrivateKey: ")) {
        seed = data;
      }
    }

    if (mEdKeyFactory == null) {
      mEdKeyFactory = KeyFactory.getInstance("EdDSA");
    }
    NamedParameterSpec namedSpec = mAlgorithms.getEdwardsCurveSpec(algorithm);
    if (namedSpec == null) {
      throw new NoSuchAlgorithmException("DNSSEC algorithm " + algorithm +
          " is not a recognized Edwards Curve algorithm");
    }

    EdECPrivateKeySpec spec = new EdECPrivateKeySpec(namedSpec, seed);

    try {
      return mEdKeyFactory.generatePrivate(spec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given a private key and public key, generate the BIND9 style private key
   * format.
   */
  public String generatePrivateKeyString(PrivateKey priv, PublicKey pub, int alg) {
    if (priv instanceof RSAPrivateCrtKey) {
      return generatePrivateRSA((RSAPrivateCrtKey) priv, alg);
    } else if (priv instanceof DSAPrivateKey && pub instanceof DSAPublicKey) {
      return generatePrivateDSA((DSAPrivateKey) priv, (DSAPublicKey) pub, alg);
    } else if (priv instanceof DHPrivateKey && pub instanceof DHPublicKey) {
      return generatePrivateDH((DHPrivateKey) priv, (DHPublicKey) pub, alg);
    } else if (priv instanceof ECPrivateKey && pub instanceof ECPublicKey) {
      return generatePrivateEC((ECPrivateKey) priv, (ECPublicKey) pub, alg);
    } else if (priv instanceof EdECPrivateKey && pub instanceof EdECPublicKey) {
      return generatePrivateED((EdECPrivateKey) priv, (EdECPublicKey) pub, alg);
    }

    return null;
  }

  /**
   * Convert from 'unsigned' big integer to original 'signed format' in Base64
   */
  private static String b64BigInt(BigInteger i) {
    byte[] origBytes = i.toByteArray();

    if (origBytes[0] != 0 || origBytes.length == 1) {
      return base64.toString(origBytes);
    }

    byte[] signedBytes = new byte[origBytes.length - 1];
    System.arraycopy(origBytes, 1, signedBytes, 0, signedBytes.length);

    return base64.toString(signedBytes);
  }

  /**
   * Given a RSA private key (in Crt format), return the BIND9-style text
   * encoding.
   */
  private String generatePrivateRSA(RSAPrivateCrtKey key, int algorithm) {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: " + algorithm + " (" + mAlgorithms.algToString(algorithm)
        + ")");
    out.print("Modulus: ");
    out.println(b64BigInt(key.getModulus()));
    out.print("PublicExponent: ");
    out.println(b64BigInt(key.getPublicExponent()));
    out.print("PrivateExponent: ");
    out.println(b64BigInt(key.getPrivateExponent()));
    out.print("Prime1: ");
    out.println(b64BigInt(key.getPrimeP()));
    out.print("Prime2: ");
    out.println(b64BigInt(key.getPrimeQ()));
    out.print("Exponent1: ");
    out.println(b64BigInt(key.getPrimeExponentP()));
    out.print("Exponent2: ");
    out.println(b64BigInt(key.getPrimeExponentQ()));
    out.print("Coefficient: ");
    out.println(b64BigInt(key.getCrtCoefficient()));

    return sw.toString();
  }

  /** Given a DH key pair, return the BIND9-style text encoding */
  private String generatePrivateDH(DHPrivateKey key, DHPublicKey pub,
      int algorithm) {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    DHParameterSpec p = key.getParams();

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: " + algorithm + " (" + mAlgorithms.algToString(algorithm)
        + ")");
    out.print("Prime(p): ");
    out.println(b64BigInt(p.getP()));
    out.print("Generator(g): ");
    out.println(b64BigInt(p.getG()));
    out.print("Private_value(x): ");
    out.println(b64BigInt(key.getX()));
    out.print("Public_value(y): ");
    out.println(b64BigInt(pub.getY()));

    return sw.toString();
  }

  /** Given a DSA key pair, return the BIND9-style text encoding */
  private String generatePrivateDSA(DSAPrivateKey key, DSAPublicKey pub,
      int algorithm) {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    DSAParams p = key.getParams();

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: " + algorithm + " (" + mAlgorithms.algToString(algorithm)
        + ")");
    out.print("Prime(p): ");
    out.println(b64BigInt(p.getP()));
    out.print("Subprime(q): ");
    out.println(b64BigInt(p.getQ()));
    out.print("Base(g): ");
    out.println(b64BigInt(p.getG()));
    out.print("Private_value(x): ");
    out.println(b64BigInt(key.getX()));
    out.print("Public_value(y): ");
    out.println(b64BigInt(pub.getY()));

    return sw.toString();
  }

  /**
   * Given an elliptic curve key pair, and the actual algorithm (which will
   * describe the curve used), return the BIND9-style text encoding.
   */
  private String generatePrivateEC(ECPrivateKey priv, ECPublicKey pub, int alg) {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: " + alg + " (" + mAlgorithms.algToString(alg)
        + ")");
    out.print("PrivateKey: ");
    out.println(b64BigInt(priv.getS()));

    return sw.toString();
  }

  /**
   * Given an edwards curve key pair, and the actual algorithm (which will
   * describe the curve used), return the BIND9-style text encoding.
   */
  private String generatePrivateED(EdECPrivateKey priv, EdECPublicKey pub, int alg) {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: " + alg + " (" + mAlgorithms.algToString(alg)
        + ")");
    out.print("PrivateKey: ");
    byte[] keyBytes = priv.getBytes().orElse("null".getBytes());
    out.println(base64.toString(keyBytes));

    return sw.toString();
  }

}
