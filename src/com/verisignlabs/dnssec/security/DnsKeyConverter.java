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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.StringTokenizer;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.KEYRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.security.KEYConverter;
import org.xbill.DNS.utils.base64;

/**
 * This class handles conversions between JCA key formats and DNSSEC and BIND9
 * key formats.
 * 
 * @author David Blacka (original)
 * @author $Author$ (latest)
 * @version $Revision$
 */
public class DnsKeyConverter
{
  private KeyFactory mRSAKeyFactory;
  private KeyFactory mDSAKeyFactory;
  private KeyFactory mDHKeyFactory;

  public DnsKeyConverter()
  {
  }

  /** Given a DNS KEY record, return the JCA public key */
  public PublicKey parseDNSKEYRecord(DNSKEYRecord pKeyRecord)
  {
    if (pKeyRecord.getKey() == null) return null;

    return KEYConverter.parseRecord(pKeyRecord);
  }

  /**
   * Given a JCA public key and the ancillary data, generate a DNSKEY record.
   */
  public DNSKEYRecord generateDNSKEYRecord(Name name, int dclass, long ttl,
      int flags, int alg, PublicKey key)
  {
    // FIXME: currenty org.xbill.DNS.security.KEYConverter will only
    // convert to KEYRecords, and even then, assume that an RSA
    // PublicKey means alg 1.
    KEYRecord kr = KEYConverter.buildRecord(name,
        dclass,
        ttl,
        flags,
        KEYRecord.PROTOCOL_DNSSEC,
        key);

    return new DNSKEYRecord(name, dclass, ttl, flags,
        DNSKEYRecord.Protocol.DNSSEC, alg, kr.getKey());
  }

  // Private Key Specific Parsing routines

  /**
   * Convert a PKCS#8 encoded private key into a PrivateKey object.
   */
  public PrivateKey convertEncodedPrivateKey(byte[] key, int algorithm)
  {
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);

    try
    {
      switch (algorithm)
      {
        case DNSSEC.RSAMD5 :
        case DNSSEC.RSASHA1 :
          return mRSAKeyFactory.generatePrivate(spec);
        case DNSSEC.DSA :
          return mDSAKeyFactory.generatePrivate(spec);
      }
    }
    catch (GeneralSecurityException e)
    {}

    return null;
  }

  /**
   * @return a JCA private key, given a BIND9-style textual encoding
   */
  public PrivateKey parsePrivateKeyString(String key) throws IOException,
      NoSuchAlgorithmException
  {
    StringTokenizer lines = new StringTokenizer(key, "\n");

    while (lines.hasMoreTokens())
    {
      String line = lines.nextToken();
      if (line == null) continue;

      if (line.startsWith("#")) continue;

      String val = value(line);
      if (val == null) continue;

      if (line.startsWith("Private-key-format: "))
      {
        if (!val.equals("v1.2"))
        {
          throw new IOException("unsupported private key format: " + val);
        }
      }
      else if (line.startsWith("Algorithm: "))
      {
        if (val.startsWith("1 ")) return parsePrivateRSA(lines);
        if (val.startsWith("5 ")) return parsePrivateRSA(lines);
        if (val.startsWith("2 ")) return parsePrivateDH(lines);
        if (val.startsWith("3 ")) return parsePrivateDSA(lines);
        throw new IOException("unsupported private key algorithm: " + val);
      }
    }
    return null;
  }

  /**
   * @return the value part of an "attribute:value" pair. The value is
   *         trimmed.
   */
  private String value(String av)
  {
    if (av == null) return null;

    int pos = av.indexOf(':');
    if (pos < 0) return av;

    if (pos >= av.length()) return null;

    return av.substring(pos + 1).trim();
  }

  /**
   * Given the rest of the RSA BIND9 string format private key, parse and
   * translate into a JCA private key
   * 
   * @throws NoSuchAlgorithmException if the RSA algorithm is not available.
   */
  private PrivateKey parsePrivateRSA(StringTokenizer lines)
      throws NoSuchAlgorithmException
  {
    BigInteger modulus = null;
    BigInteger public_exponent = null;
    BigInteger private_exponent = null;
    BigInteger prime_p = null;
    BigInteger prime_q = null;
    BigInteger prime_p_exponent = null;
    BigInteger prime_q_exponent = null;
    BigInteger coefficient = null;

    while (lines.hasMoreTokens())
    {
      String line = lines.nextToken();
      if (line == null) continue;

      if (line.startsWith("#")) continue;

      String val = value(line);
      if (val == null) continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Modulus: "))
      {
        modulus = new BigInteger(1, data);
        // printBigIntCompare(data, modulus);
      }
      else if (line.startsWith("PublicExponent: "))
      {
        public_exponent = new BigInteger(1, data);
        // printBigIntCompare(data, public_exponent);
      }
      else if (line.startsWith("PrivateExponent: "))
      {
        private_exponent = new BigInteger(1, data);
        // printBigIntCompare(data, private_exponent);
      }
      else if (line.startsWith("Prime1: "))
      {
        prime_p = new BigInteger(1, data);
        // printBigIntCompare(data, prime_p);
      }
      else if (line.startsWith("Prime2: "))
      {
        prime_q = new BigInteger(1, data);
        // printBigIntCompare(data, prime_q);
      }
      else if (line.startsWith("Exponent1: "))
      {
        prime_p_exponent = new BigInteger(1, data);
      }
      else if (line.startsWith("Exponent2: "))
      {
        prime_q_exponent = new BigInteger(1, data);
      }
      else if (line.startsWith("Coefficient: "))
      {
        coefficient = new BigInteger(1, data);
      }
    }

    try
    {
      KeySpec spec = new RSAPrivateCrtKeySpec(modulus, public_exponent,
          private_exponent, prime_p, prime_q, prime_p_exponent,
          prime_q_exponent, coefficient);
      if (mRSAKeyFactory == null)
      {
        mRSAKeyFactory = KeyFactory.getInstance("RSA");
      }
      return mRSAKeyFactory.generatePrivate(spec);
    }
    catch (InvalidKeySpecException e)
    {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9 style DH private key, parse the key
   * info and translate it into a JCA private key.
   * 
   * @throws NoSuchAlgorithmException if the DH algorithm is not available.
   */
  private PrivateKey parsePrivateDH(StringTokenizer lines)
      throws NoSuchAlgorithmException
  {
    BigInteger p = null;
    BigInteger x = null;
    BigInteger g = null;

    while (lines.hasMoreTokens())
    {
      String line = lines.nextToken();
      if (line == null) continue;

      if (line.startsWith("#")) continue;

      String val = value(line);
      if (val == null) continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Prime(p): "))
      {
        p = new BigInteger(1, data);
      }
      else if (line.startsWith("Generator(g): "))
      {
        g = new BigInteger(1, data);
      }
      else if (line.startsWith("Private_value(x): "))
      {
        x = new BigInteger(1, data);
      }
    }

    try
    {
      KeySpec spec = new DHPrivateKeySpec(x, p, g);
      if (mDHKeyFactory == null)
      {
        mDHKeyFactory = KeyFactory.getInstance("DH");
      }
      return mDHKeyFactory.generatePrivate(spec);
    }
    catch (InvalidKeySpecException e)
    {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given the remaining lines in a BIND9 style DSA private key, parse the key
   * info and translate it into a JCA private key.
   * 
   * @throws NoSuchAlgorithmException if the DSA algorithm is not available.
   */
  private PrivateKey parsePrivateDSA(StringTokenizer lines)
      throws NoSuchAlgorithmException
  {
    BigInteger p = null;
    BigInteger q = null;
    BigInteger g = null;
    BigInteger x = null;

    while (lines.hasMoreTokens())
    {
      String line = lines.nextToken();
      if (line == null) continue;

      if (line.startsWith("#")) continue;

      String val = value(line);
      if (val == null) continue;

      byte[] data = base64.fromString(val);

      if (line.startsWith("Prime(p): "))
      {
        p = new BigInteger(1, data);
      }
      else if (line.startsWith("Subprime(q): "))
      {
        q = new BigInteger(1, data);
      }
      else if (line.startsWith("Base(g): "))
      {
        g = new BigInteger(1, data);
      }
      else if (line.startsWith("Private_value(x): "))
      {
        x = new BigInteger(1, data);
      }
    }

    try
    {
      KeySpec spec = new DSAPrivateKeySpec(x, p, q, g);
      if (mDSAKeyFactory == null)
      {
        mDSAKeyFactory = KeyFactory.getInstance("DSA");
      }
      return mDSAKeyFactory.generatePrivate(spec);
    }
    catch (InvalidKeySpecException e)
    {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * Given a private key and public key, generate the BIND9 style private key
   * format.
   */
  public String generatePrivateKeyString(PrivateKey priv, PublicKey pub,
      int alg)
  {
    if (priv instanceof RSAPrivateCrtKey)
    {
      return generatePrivateRSA((RSAPrivateCrtKey) priv, alg);
    }
    else if (priv instanceof DSAPrivateKey && pub instanceof DSAPublicKey)
    {
      return generatePrivateDSA((DSAPrivateKey) priv, (DSAPublicKey) pub);
    }
    else if (priv instanceof DHPrivateKey && pub instanceof DHPublicKey)
    {
      return generatePrivateDH((DHPrivateKey) priv, (DHPublicKey) pub);
    }

    return null;
  }

  /**
   * Convert from 'unsigned' big integer to original 'signed format' in Base64
   */
  private String b64BigInt(BigInteger i)
  {
    byte[] orig_bytes = i.toByteArray();

    if (orig_bytes[0] != 0 || orig_bytes.length == 1)
    {
      return base64.toString(orig_bytes);
    }

    byte[] signed_bytes = new byte[orig_bytes.length - 1];
    System.arraycopy(orig_bytes, 1, signed_bytes, 0, signed_bytes.length);

    return base64.toString(signed_bytes);
  }

  /**
   * Given a RSA private key (in Crt format), return the BIND9-style text
   * encoding.
   */
  private String generatePrivateRSA(RSAPrivateCrtKey key, int algorithm)
  {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    out.println("Private-key-format: v1.2");
    if (algorithm == DNSSEC.RSAMD5)
    {
      out.println("Algorithm: 1 (RSAMD5)");
    }
    else
    {
      out.println("Algorithm: 5 (RSASHA1)");
    }
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
  private String generatePrivateDH(DHPrivateKey key, DHPublicKey pub)
  {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    DHParameterSpec p = key.getParams();

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: 2 (DH)");
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
  private String generatePrivateDSA(DSAPrivateKey key, DSAPublicKey pub)
  {
    StringWriter sw = new StringWriter();
    PrintWriter out = new PrintWriter(sw);

    DSAParams p = key.getParams();

    out.println("Private-key-format: v1.2");
    out.println("Algorithm: 3 (DSA)");
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
}
