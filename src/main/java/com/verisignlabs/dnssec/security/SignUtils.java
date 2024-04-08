// Copyright (C) 2001-2003, 2022 Verisign, Inc.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.logging.Logger;

import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSOutput;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base64;

/**
 * This class contains a bunch of utility methods that are generally useful in
 * signing zones.
 * 
 * @author David Blacka
 */

public class SignUtils {
  private static final int ASN1_INT = 0x02;
  private static final int ASN1_SEQ = 0x30;

  public static final int RR_NORMAL = 0;
  public static final int RR_DELEGATION = 1;
  public static final int RR_GLUE = 2;
  public static final int RR_INVALID = 3;
  public static final int RR_DNAME = 4;

  private static Logger log;

  static {
    log = Logger.getLogger(SignUtils.class.toString());
  }

  public static void setLog(Logger v) {
    log = v;
  }

  private SignUtils() {
  }

  /**
   * Generate from some basic information a prototype RRSIG RR containing
   * everything but the actual signature itself.
   *
   * @param rrset  the RRset being signed.
   * @param key    the public DNSKEY RR counterpart to the key being used to sign
   *               the RRset
   * @param start  the RRSIG inception time.
   * @param expire the RRSIG expiration time.
   * @param sigTTL the TTL of the resulting RRSIG record.
   *
   * @return a prototype signature based on the RRset and key information.
   */
  public static RRSIGRecord generatePreRRSIG(RRset rrset, DNSKEYRecord key, Instant start,
      Instant expire, long sigTTL) {
    return new RRSIGRecord(rrset.getName(), rrset.getDClass(), sigTTL, rrset.getType(),
        key.getAlgorithm(), (int) rrset.getTTL(), expire, start,
        key.getFootprint(), key.getName(), null);
  }

  /**
   * Generate from some basic information a prototype RRSIG RR containing
   * everything but the actual signature itself.
   *
   * @param rec    the DNS record being signed (forming an entire RRset).
   * @param key    the public DNSKEY RR counterpart to the key signing the record.
   * @param start  the RRSIG inception time.
   * @param expire the RRSIG expiration time.
   * @param sigTTL the TTL of the result RRSIG record.
   *
   * @return a prototype signature based on the Record and key information.
   */
  public static RRSIGRecord generatePreRRSIG(Record rec, DNSKEYRecord key, Instant start,
      Instant expire, long sigTTL) {
    return new RRSIGRecord(rec.getName(), rec.getDClass(), sigTTL, rec.getType(),
        key.getAlgorithm(), rec.getTTL(), expire, start,
        key.getFootprint(), key.getName(), null);
  }

  /**
   * Generate the binary image of the prototype RRSIG RR.
   *
   * @param presig the RRSIG RR prototype.
   * @return the RDATA portion of the prototype RRSIG record. This forms the
   *         first part of the data to be signed.
   */
  private static byte[] generatePreSigRdata(RRSIGRecord presig) {
    // Generate the binary image
    DNSOutput image = new DNSOutput();

    // precalc some things
    long startTime = presig.getTimeSigned().getEpochSecond();
    long expireTime = presig.getExpire().getEpochSecond();
    Name signer = presig.getSigner();

    // first write out the partial SIG record (this is the SIG RDATA
    // minus the actual signature.
    image.writeU16(presig.getTypeCovered());
    image.writeU8(presig.getAlgorithm());
    image.writeU8(presig.getLabels());
    image.writeU32((int) presig.getOrigTTL());
    image.writeU32(expireTime);
    image.writeU32(startTime);
    image.writeU16(presig.getFootprint());
    image.writeByteArray(signer.toWireCanonical());

    return image.toByteArray();
  }

  /**
   * Calculate the canonical wire line format of the RRset.
   *
   * @param rrset  the RRset to convert.
   * @param ttl    the TTL to use when canonicalizing -- this is generally the TTL
   *               of the signature if there is a pre-existing signature. If not
   *               it is just the ttl of the rrset itself.
   * @param labels the labels field of the signature, or 0.
   * @return the canonical wire line format of the rrset. This is the second
   *         part of data to be signed.
   */
  public static byte[] generateCanonicalRRsetData(RRset rrset, long ttl, int labels) {
    DNSOutput image = new DNSOutput();

    if (ttl == 0) {
      ttl = rrset.getTTL();
    }

    Name n = rrset.getName();
    if (labels == 0) {
      labels = n.labels();
    } else {
      // correct for Name()'s conception of label count.
      labels++;
    }
    boolean wildcardName = false;
    if (n.labels() != labels) {
      n = n.wild(n.labels() - labels);
      wildcardName = true;
      log.finer("Detected wildcard expansion: " + rrset.getName() + " changed to " + n);
    }

    // now convert the wire format records in the RRset into a
    // list of byte arrays.
    ArrayList<byte[]> canonicalRRs = new ArrayList<>();
    for (Record r : rrset.rrs()) {
      if (r.getTTL() != ttl || wildcardName) {
        // If necessary, we need to create a new record with a new ttl
        // or ownername.
        // In the TTL case, this avoids changing the ttl in the
        // response.
        r = Record.newRecord(n, r.getType(), r.getDClass(), ttl, r.rdataToWireCanonical());
      }
      byte[] wireFmt = r.toWireCanonical();
      canonicalRRs.add(wireFmt);
    }

    // put the records into the correct ordering.
    // Calculate the offset where the RDATA begins (we have to skip
    // past the length byte)

    int offset = rrset.getName().toWireCanonical().length + 10;
    ByteArrayComparator bac = new ByteArrayComparator(offset, false);

    Collections.sort(canonicalRRs, bac);

    for (byte[] wire_fmt_rec : canonicalRRs) {
      image.writeByteArray(wire_fmt_rec);
    }

    return image.toByteArray();
  }

  /**
   * Given an RRset and the prototype signature, generate the canonical data
   * that is to be signed.
   *
   * @param rrset  the RRset to be signed.
   * @param presig a prototype SIG RR created using the same RRset.
   * @return a block of data ready to be signed.
   */
  public static byte[] generateSigData(RRset rrset, RRSIGRecord presig)
      throws IOException {
    byte[] rrsetData = generateCanonicalRRsetData(rrset, presig.getOrigTTL(),
        presig.getLabels());

    return generateSigData(rrsetData, presig);
  }

  /**
   * Given an RRset and the prototype signature, generate the canonical data
   * that is to be signed.
   *
   * @param rrsetData the RRset converted into canonical wire line format (as
   *                  per the canonicalization rules in RFC 2535).
   * @param presig    the prototype signature based on the same RRset represented
   *                  in <code>rrset_data</code>.
   * @return a block of data ready to be signed.
   */
  public static byte[] generateSigData(byte[] rrsetData, RRSIGRecord presig)
      throws IOException {
    byte[] sigRdata = generatePreSigRdata(presig);

    ByteArrayOutputStream image = new ByteArrayOutputStream(sigRdata.length
        + rrsetData.length);

    image.write(sigRdata);
    image.write(rrsetData);

    return image.toByteArray();
  }

  /**
   * Given the actual signature and the prototype signature, combine them and
   * return the fully formed RRSIGRecord.
   *
   * @param signature the cryptographic signature, in DNSSEC format.
   * @param presig    the prototype RRSIG RR to add the signature to.
   * @return the fully formed RRSIG RR.
   */
  public static RRSIGRecord generateRRSIG(byte[] signature, RRSIGRecord presig) {
    return new RRSIGRecord(presig.getName(), presig.getDClass(), presig.getTTL(),
        presig.getTypeCovered(), presig.getAlgorithm(),
        presig.getOrigTTL(), presig.getExpire(),
        presig.getTimeSigned(), presig.getFootprint(),
        presig.getSigner(), signature);
  }

  /**
   * Converts from a RFC 2536 formatted DSA signature to a JCE (ASN.1) formatted
   * signature.
   *
   * <p>
   * ASN.1 format = ASN1_SEQ . seq_length . ASN1_INT . Rlength . R . ANS1_INT .
   * Slength . S
   * </p>
   *
   * The integers R and S may have a leading null byte to force the integer
   * positive.
   *
   * @param signature the RFC 2536 formatted DSA signature.
   * @return The ASN.1 formatted DSA signature.
   * @throws SignatureException if there was something wrong with the RFC 2536
   *                            formatted signature.
   */
  public static byte[] convertDSASignature(byte[] signature) throws SignatureException {
    if (signature.length != 41)
      throw new SignatureException("RFC 2536 signature not expected length.");

    byte rPad = 0;
    byte sPad = 0;

    // handle initial null byte padding.
    if (signature[1] < 0)
      rPad++;
    if (signature[21] < 0)
      sPad++;

    // ASN.1 length = R length + S length + (2 + 2 + 2), where each 2
    // is for a ASN.1 type-length byte pair of which there are three
    // (SEQ, INT, INT).
    byte sigLength = (byte) (40 + rPad + sPad + 6);

    byte[] sig = new byte[sigLength];
    byte pos = 0;

    sig[pos++] = ASN1_SEQ;
    sig[pos++] = (byte) (sigLength - 2); // all but the SEQ type+length.
    sig[pos++] = ASN1_INT;
    sig[pos++] = (byte) (20 + rPad);

    // copy the value of R, leaving a null byte if necessary
    if (rPad == 1)
      sig[pos++] = 0;

    System.arraycopy(signature, 1, sig, pos, 20);
    pos += 20;

    sig[pos++] = ASN1_INT;
    sig[pos++] = (byte) (20 + sPad);

    // copy the value of S, leaving a null byte if necessary
    if (sPad == 1)
      sig[pos++] = 0;

    System.arraycopy(signature, 21, sig, pos, 20);

    return sig;
  }

  /**
   * Converts from a JCE (ASN.1) formatted DSA signature to a RFC 2536 compliant
   * signature.
   *
   * <p>
   * rfc2536 format = T . R . S
   * </p>
   *
   * where T is a number between 0 and 8, which is based on the DSA key length,
   * and R & S are formatted to be exactly 20 bytes each (no leading null
   * bytes).
   *
   * @param params    the DSA parameters associated with the DSA key used to
   *                  generate the signature.
   * @param signature the ASN.1 formatted DSA signature.
   * @return a RFC 2536 formatted DSA signature.
   * @throws SignatureException if something is wrong with the ASN.1 format.
   */
  public static byte[] convertDSASignature(DSAParams params, byte[] signature)
      throws SignatureException {
    if (signature[0] != ASN1_SEQ || signature[2] != ASN1_INT) {
      throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT");
    }

    byte rPad = (byte) (signature[3] - 20);

    if (signature[24 + rPad] != ASN1_INT) {
      throw new SignatureException(
          "Invalid ASN.1 signature format: expected SEQ, INT, INT");
    }

    log.finer("(start) ASN.1 DSA Sig:\n" + base64.toString(signature));

    byte sPad = (byte) (signature[25 + rPad] - 20);

    byte[] sig = new byte[41]; // all rfc2536 signatures are 41 bytes.

    // Calculate T:
    sig[0] = (byte) ((params.getP().bitLength() - 512) / 64);

    // copy R value
    if (rPad >= 0) {
      System.arraycopy(signature, 4 + rPad, sig, 1, 20);
    } else {
      // R is shorter than 20 bytes, so right justify the number
      // (r_pad is negative here, remember?).
      Arrays.fill(sig, 1, 1 - rPad, (byte) 0);
      System.arraycopy(signature, 4, sig, 1 - rPad, 20 + rPad);
    }

    // copy S value
    if (sPad >= 0) {
      System.arraycopy(signature, 26 + rPad + sPad, sig, 21, 20);
    } else {
      // S is shorter than 20 bytes, so right justify the number
      // (s_pad is negative here).
      Arrays.fill(sig, 21, 21 - sPad, (byte) 0);
      System.arraycopy(signature, 26 + rPad, sig, 21 - sPad, 20 + sPad);
    }

    if (rPad < 0 || sPad < 0) {
      log.finer("(finish ***) RFC 2536 DSA Sig:\n" + base64.toString(sig));

    } else {
      log.finer("(finish) RFC 2536 DSA Sig:\n" + base64.toString(sig));
    }

    return sig;
  }

  // Given one of the ECDSA algorithms determine the "length", which is the
  // length, in bytes, of both 'r' and 's' in the ECDSA signature.
  private static int ecdsaLength(int algorithm) throws SignatureException {
    switch (algorithm) {
      case DNSSEC.Algorithm.ECDSAP256SHA256:
        return 32;
      case DNSSEC.Algorithm.ECDSAP384SHA384:
        return 48;
      default:
        throw new SignatureException("Algorithm " + algorithm +
            " is not a supported ECDSA signature algorithm.");
    }
  }

  /**
   * Convert a JCE standard ECDSA signature (which is a ASN.1 encoding) into a
   * standard DNS signature.
   *
   * The format of the ASN.1 signature is
   *
   * ASN1_SEQ . seq_length . ASN1_INT . r_length . R . ANS1_INT . s_length . S
   *
   * where R and S may have a leading zero byte if without it the values would
   * be negative.
   *
   * The format of the DNSSEC signature is just R . S where R and S are both
   * exactly "length" bytes.
   *
   * @param signature The output of a ECDSA signature object.
   * @return signature data formatted for use in DNSSEC.
   * @throws SignatureException if the ASN.1 encoding appears to be corrupt.
   */
  public static byte[] convertECDSASignature(int algorithm, byte[] signature)
      throws SignatureException {
    int expLength = ecdsaLength(algorithm);
    byte[] sig = new byte[expLength * 2];

    if (signature[0] != ASN1_SEQ || signature[2] != ASN1_INT) {
      throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT");
    }
    int rLen = signature[3];
    int rPos = 4;

    if (signature[rPos + rLen] != ASN1_INT) {
      throw new SignatureException("Invalid ASN.1 signature format: expected SEQ, INT, INT");
    }
    int sPos = rPos + rLen + 2;
    int sLen = signature[rPos + rLen + 1];

    // Adjust for leading zeros on both R and S
    if (signature[rPos] == 0) {
      rPos++;
      rLen--;
    }
    if (signature[sPos] == 0) {
      sPos++;
      sLen--;
    }

    System.arraycopy(signature, rPos, sig, 0 + (expLength - rLen), rLen);
    System.arraycopy(signature, sPos, sig, expLength + (expLength - sLen), sLen);

    return sig;
  }

  /**
   * Convert a DNS standard ECDSA signature (defined in RFC 6605) into a JCE
   * standard ECDSA signature, which is encoded in ASN.1.
   *
   * The format of the ASN.1 signature is
   *
   * ASN1_SEQ . seq_length . ASN1_INT . r_length . R . ANS1_INT . s_length . S
   *
   * where R and S may have a leading zero byte if without it the values would
   * be negative.
   *
   * The format of the DNSSEC signature is just R . S where R and S are both
   * exactly "length" bytes.
   *
   * @param signature The binary signature data from an RRSIG record.
   * @return signature data that may be used in a JCE Signature object for
   *         verification purposes.
   */
  public static byte[] convertECDSASignature(byte[] signature) {
    byte rSrcPos;
    byte rSrcLen;
    byte rPad;
    byte sSrcPos;
    byte sSrcLen;
    byte sPad;
    byte len;

    rSrcLen = sSrcLen = (byte) (signature.length / 2);
    rSrcPos = 0;
    rPad = 0;
    sSrcPos = (byte) (rSrcPos + rSrcLen);
    sPad = 0;
    len = (byte) (6 + rSrcLen + sSrcLen);

    // leading zeroes are forbidden
    while (signature[rSrcPos] == 0 && rSrcLen > 0) {
      rSrcPos++;
      rSrcLen--;
      len--;
    }
    while (signature[sSrcPos] == 0 && sSrcLen > 0) {
      sSrcPos++;
      sSrcLen--;
      len--;
    }

    // except when they are mandatory
    if (rSrcLen > 0 && signature[rSrcPos] < 0) {
      rPad = 1;
      len++;
    }
    if (sSrcLen > 0 && signature[sSrcPos] < 0) {
      sPad = 1;
      len++;
    }
    byte[] sig = new byte[len];
    byte pos = 0;

    sig[pos++] = ASN1_SEQ;
    sig[pos++] = (byte) (len - 2);
    sig[pos++] = ASN1_INT;
    sig[pos++] = (byte) (rSrcLen + rPad);
    pos += rPad;
    System.arraycopy(signature, rSrcPos, sig, pos, rSrcLen);
    pos += rSrcLen;

    sig[pos++] = ASN1_INT;
    sig[pos++] = (byte) (sSrcLen + sPad);
    pos += sPad;
    System.arraycopy(signature, sSrcPos, sig, pos, sSrcLen);

    return sig;
  }

  /**
   * This is a convenience routine to help us classify records/RRsets.
   *
   * It characterizes a record/RRset as one of the following classes:<br/>
   * <dl>
   *
   * <dt>NORMAL</dt>
   * <dd>This record/set is properly within the zone an subject to all NXT and
   * SIG processing.</dd>
   *
   * <dt>DELEGATION</dt>
   * <dd>This is a zone delegation point (or cut). It is used in NXT processing
   * but is not signed.</dd>
   *
   * <dt>GLUE</dt>
   * <dd>This is a glue record and therefore not properly within the zone. It is
   * not included in NXT or SIG processing. Normally glue records are A records,
   * but this routine calls anything that is below a zone delegation glue.</dd>
   *
   * <dt>INVALID</dt>
   * <dd>This record doesn't even belong in the zone.</dd>
   *
   * </dl>
   * <br/>
   *
   * This method must be called successively on records in the canonical name
   * ordering, and the caller must maintain the last_cut parameter.
   *
   * @param zonename the name of the zone that is being processed.
   * @param name     the name of the record/set under consideration.
   * @param type     the type of the record/set under consideration.
   * @param lastCut  the name of the last DELEGATION record/set that was
   *                 encountered while iterating over the zone in canonical
   *                 order.
   */
  public static int recordSecType(Name zonename, Name name, int type, Name lastCut,
      Name lastDname) {
    // records not even in the zone itself are invalid.
    if (!name.subdomain(zonename))
      return RR_INVALID;

    // all records a the zone apex are normal, by definition.
    if (name.equals(zonename))
      return RR_NORMAL;

    if (lastCut != null && name.subdomain(lastCut)) {
      // if we are at the same level as a delegation point, but not one of a set of
      // types allowed at
      // a delegation point (NS, DS, NSEC), this is glue.
      if (name.equals(lastCut)) {
        if (type != Type.NS && type != Type.DS && type != Type.NXT && type != Type.NSEC) {
          return RR_GLUE;
        }
      }
      // if we are below the delegation point, this is glue.
      else {
        return RR_GLUE;
      }

    }

    // if we are below a DNAME, then the RR is invalid.
    if (lastDname != null && name.subdomain(lastDname)
        && name.labels() > lastDname.labels()) {
      return RR_INVALID;
    }

    // since we are not at zone level, any NS records are delegations
    if (type == Type.NS)
      return RR_DELEGATION;

    // and everything else is normal
    return RR_NORMAL;
  }

  /**
   * Given a canonical ordered list of records from a single zone, order the raw
   * records into a list of RRsets.
   * 
   * @param records
   *                a list of {@link org.xbill.DNS.Record} objects, in DNSSEC
   *                canonical order.
   * @return a List of {@link org.xbill.DNS.RRset} objects.
   */
  public static List<RRset> assembleIntoRRsets(List<Record> records) {
    RRset rrset = new RRset();
    ArrayList<RRset> rrsets = new ArrayList<>();

    for (Record r : records) {
      // First record
      if (rrset.size() == 0) {
        rrset.addRR(r);
        continue;
      }

      // Current record is part of the current RRset.
      if (rrset.getName().equals(r.getName())
          && rrset.getDClass() == r.getDClass()
          && ((r.getType() == Type.RRSIG && rrset.getType() == ((RRSIGRecord) r).getTypeCovered())
              || rrset.getType() == r.getType())) {
        rrset.addRR(r);
        continue;
      }

      // otherwise, we have completed the RRset
      rrsets.add(rrset);

      // set up for the next set.
      rrset = new RRset();
      rrset.addRR(r);
    }

    // add the last rrset.
    rrsets.add(rrset);

    return rrsets;
  }

  /**
   * A little private class to hold information about a given node.
   */
  private static class NodeInfo {
    public Name name;
    public int type;
    public long ttl;
    public int dclass;
    public Set<Integer> typemap;
    public boolean isSecureNode; // opt-in support.
    public boolean hasOptInSpan; // opt-in support.
    public int nsecIndex;

    public NodeInfo(Record r, int nodeType) {
      this.name = r.getName();
      this.type = nodeType;
      this.ttl = r.getTTL();
      this.dclass = r.getDClass();
      this.typemap = new HashSet<>();
      this.isSecureNode = false;
      this.hasOptInSpan = false;
      addType(r.getType());
    }

    public void addType(int type) {
      this.typemap.add(Integer.valueOf(type));

      // Opt-In support.
      if (type != Type.NS && type != Type.NSEC && type != Type.RRSIG
          && type != Type.NSEC3) {
        isSecureNode = true;
      }
    }

    public boolean hasType(int type) {
      return this.typemap.contains(type);
    }

    public String toString() {
      StringBuilder sb = new StringBuilder(name.toString());
      if (isSecureNode)
        sb.append("(S)");
      if (hasOptInSpan)
        sb.append("(O)");
      return sb.toString();
    }

    public int[] getTypes() {
      Object[] a = typemap.toArray();
      int[] res = new int[a.length];

      for (int i = 0; i < a.length; i++) {
        res[i] = ((Integer) a[i]).intValue();
      }
      return res;
    }
  }

  /**
   * Given a canonical (by name) ordered list of records in a zone, generate the
   * NSEC records in place.
   *
   * Note that the list that the records are stored in must support the
   * listIterator.add() operation.
   *
   * @param zonename the name of the zone (used to distinguish between zone apex
   *                 NS RRsets and delegations).
   * @param records  a list of {@link org.xbill.DNS.Record} objects in DNSSEC
   *                 canonical order.
   */
  public static void generateNSECRecords(Name zonename, List<Record> records) {
    // This works by iterating over a known sorted list of records.

    NodeInfo lastNode = null;
    NodeInfo currentNode = null;

    Name lastCut = null;
    Name lastDname = null;
    int backup;
    long nsecTTL = 0;

    // First find the SOA record -- it should be near the beginning -- and get
    // the soa minimum
    for (Record r : records) {
      if (r.getType() == Type.SOA) {
        SOARecord soa = (SOARecord) r;
        nsecTTL = Math.min(soa.getMinimum(), soa.getTTL());
        break;
      }
    }

    if (nsecTTL == 0) {
      throw new IllegalArgumentException("Zone did not contain a SOA record");
    }

    for (ListIterator<Record> i = records.listIterator(); i.hasNext();) {
      Record r = i.next();
      Name rName = r.getName();
      int rType = r.getType();
      int rSecType = recordSecType(zonename, rName, rType, lastCut, lastDname);

      // skip irrelevant records
      if (rSecType == RR_INVALID || rSecType == RR_GLUE)
        continue;

      // note our last delegation point so we can recognize glue.
      if (rSecType == RR_DELEGATION)
        lastCut = rName;

      // if this is a DNAME, note it so we can recognize junk
      if (rType == Type.DNAME)
        lastDname = rName;

      // first node -- initialize
      if (currentNode == null) {
        currentNode = new NodeInfo(r, rSecType);
        currentNode.addType(Type.RRSIG);
        currentNode.addType(Type.NSEC);
        continue;
      }

      // record name hasn't changed, so we are still on the same node.
      if (rName.equals(currentNode.name)) {
        currentNode.addType(rType);
        continue;
      }

      if (lastNode != null) {
        NSECRecord nsec = new NSECRecord(lastNode.name, lastNode.dclass, nsecTTL,
            currentNode.name, lastNode.getTypes());
        // Note: we have to add this through the iterator, otherwise
        // the next access via the iterator will generate a
        // ConcurrencyModificationException.
        backup = i.nextIndex() - lastNode.nsecIndex;
        for (int j = 0; j < backup; j++)
          i.previous();
        i.add(nsec);
        for (int j = 0; j < backup; j++)
          i.next();

        log.finer("Generated: " + nsec);
      }

      lastNode = currentNode;

      currentNode.nsecIndex = i.previousIndex();
      currentNode = new NodeInfo(r, rSecType);
      currentNode.addType(Type.RRSIG);
      currentNode.addType(Type.NSEC);
    }

    // Generate next to last NSEC
    if (lastNode != null) {
      NSECRecord nsec = new NSECRecord(lastNode.name, lastNode.dclass, nsecTTL,
          currentNode.name, lastNode.getTypes());
      records.add(lastNode.nsecIndex - 1, nsec);
      log.finer("Generated: " + nsec);
    }

    // Generate last NSEC
    NSECRecord nsec = new NSECRecord(currentNode.name, currentNode.dclass, nsecTTL,
        zonename, currentNode.getTypes());
    records.add(nsec);

    log.finer("Generated: " + nsec);
  }

  /**
   * Given a canonical (by name) ordered list of records in a zone, generate the
   * NSEC3 records in place.
   *
   * Note that the list that the records are stored in must support the
   * listIterator.add() operation.
   *
   * @param zonename      the name of the zone (used to distinguish between zone
   *                      apex NS RRsets and delegations).
   * @param records       a list of {@link org.xbill.DNS.Record} objects in
   *                      DNSSEC canonical order.
   * @param salt          The NSEC3 salt to use (may be null or empty for no
   *                      salt).
   * @param iterations    The number of hash iterations to use.
   * @param nsec3paramTTL The TTL to use for the generated NSEC3PARAM records
   *                      (NSEC3 records will use the SOA minimum)
   * @throws NoSuchAlgorithmException
   */
  public static void generateNSEC3Records(Name zonename, List<Record> records,
      byte[] salt, int iterations, long nsec3paramTTL)
      throws NoSuchAlgorithmException {
    List<ProtoNSEC3> protoNSEC3s = new ArrayList<>();
    NodeInfo currentNode = null;
    NodeInfo lastNode = null;
    // For detecting glue.
    Name lastCut = null;
    // For detecting junk below a DNAME
    Name lastDname = null;

    long nsec3TTL = 0;

    for (Record r : records) {
      Name rName = r.getName();
      int rType = r.getType();

      // Classify this record so we know if we can skip it.
      int rSecType = recordSecType(zonename, rName, rType, lastCut, lastDname);

      // skip irrelevant records
      if (rSecType == RR_INVALID || rSecType == RR_GLUE)
        continue;

      // note our last delegation point so we can recognize glue.
      if (rSecType == RR_DELEGATION)
        lastCut = rName;

      // note our last DNAME point, so we can recognize junk.
      if (rType == Type.DNAME)
        lastDname = rName;

      if (rType == Type.SOA) {
        SOARecord soa = (SOARecord) r;
        nsec3TTL = Math.min(soa.getMinimum(), soa.getTTL());
        if (nsec3paramTTL < 0) {
          nsec3paramTTL = nsec3TTL;
        }
      }

      // For the first iteration, we create our current node.
      if (currentNode == null) {
        currentNode = new NodeInfo(r, rSecType);
        continue;
      }

      // If we are at the same name, we are on the same node.
      if (rName.equals(currentNode.name)) {
        currentNode.addType(rType);
        continue;
      }

      // At this point, r represents the start of a new node.
      // So we move current_node to last_node and generate a new current node.
      // But first, we need to do something with the last node.
      generateNSEC3ForNode(lastNode, zonename, salt, iterations, false, protoNSEC3s);

      lastNode = currentNode;
      currentNode = new NodeInfo(r, rSecType);
    }

    // process last two nodes.
    generateNSEC3ForNode(lastNode, zonename, salt, iterations, false, protoNSEC3s);
    generateNSEC3ForNode(currentNode, zonename, salt, iterations, false, protoNSEC3s);

    List<NSEC3Record> nsec3s = finishNSEC3s(protoNSEC3s, nsec3TTL);

    records.addAll(nsec3s);

    NSEC3PARAMRecord nsec3param = new NSEC3PARAMRecord(zonename, DClass.IN,
        nsec3paramTTL,
        NSEC3Record.SHA1_DIGEST_ID,
        (byte) 0, iterations, salt);
    records.add(nsec3param);

  }

  /**
   * Given a canonical (by name) ordered list of records in a zone, generate the
   * NSEC3 records in place using Opt-Out NSEC3 records. This means that
   * non-apex NS RRs (and glue below those delegations) will, by default, not be
   * included in the NSEC3 chain.
   *
   * Note that the list that the records are stored in must support the
   * listIterator.add() operation.
   *
   * @param zonename      the name of the zone (used to distinguish between zone
   *                      apex NS RRsets and delegations).
   * @param records       a list of {@link org.xbill.DNS.Record} objects in
   *                      DNSSEC canonical order.
   * @param includedNames A list of {@link org.xbill.DNS.Name} objects. These
   *                      names will be included in the NSEC3 chain (if they
   *                      exist in the zone) regardless.
   * @param salt          The NSEC3 salt to use (may be null or empty for no
   *                      salt).
   * @param iterations    The number of hash iterations to use.
   * @param nsec3paramTTL The TTL to use for the generated NSEC3PARAM records
   *                      (NSEC3 records will use the SOA minimum)
   * @throws NoSuchAlgorithmException
   */
  public static void generateOptOutNSEC3Records(Name zonename, List<Record> records,
      List<Name> includedNames, byte[] salt,
      int iterations, long nsec3paramTTL)
      throws NoSuchAlgorithmException {
    List<ProtoNSEC3> protoNSEC3s = new ArrayList<>();
    NodeInfo currentNode = null;
    NodeInfo lastNode = null;
    // For detecting glue.
    Name lastCut = null;
    // For detecting out-of-zone records below a DNAME
    Name lastDname = null;

    long nsec3TTL = 0;

    HashSet<Name> includeSet = null;
    if (includedNames != null) {
      includeSet = new HashSet<>(includedNames);
    }

    for (Record r : records) {
      Name rName = r.getName();
      int rType = r.getType();

      // Classify this record so we know if we can skip it.
      int rSecType = recordSecType(zonename, rName, rType, lastCut, lastDname);

      // skip irrelevant records
      if (rSecType == RR_INVALID || rSecType == RR_GLUE)
        continue;

      // note our last delegation point so we can recognize glue.
      if (rSecType == RR_DELEGATION)
        lastCut = rName;

      if (rType == Type.DNAME)
        lastDname = rName;

      if (rType == Type.SOA) {
        SOARecord soa = (SOARecord) r;
        nsec3TTL = Math.min(soa.getMinimum(), soa.getTTL());
        if (nsec3paramTTL < 0) {
          nsec3paramTTL = nsec3TTL;
        }
      }

      // For the first iteration, we create our current node.
      if (currentNode == null) {
        currentNode = new NodeInfo(r, rSecType);
        continue;
      }

      // If we are at the same name, we are on the same node.
      if (rName.equals(currentNode.name)) {
        currentNode.addType(rType);
        continue;
      }

      if (includeSet != null && includeSet.contains(currentNode.name)) {
        currentNode.isSecureNode = true;
      }

      // At this point, r represents the start of a new node.
      // So we move current_node to last_node and generate a new current node.
      // But first, we need to do something with the last node.
      generateNSEC3ForNode(lastNode, zonename, salt, iterations, true, protoNSEC3s);

      if (currentNode.isSecureNode) {
        lastNode = currentNode;
      } else {
        lastNode.hasOptInSpan = true;
      }

      currentNode = new NodeInfo(r, rSecType);
    }

    // process last two nodes.
    generateNSEC3ForNode(lastNode, zonename, salt, iterations, true, protoNSEC3s);
    generateNSEC3ForNode(currentNode, zonename, salt, iterations, true, protoNSEC3s);

    List<NSEC3Record> nsec3s = finishNSEC3s(protoNSEC3s, nsec3TTL);
    records.addAll(nsec3s);

    NSEC3PARAMRecord nsec3param = new NSEC3PARAMRecord(zonename, DClass.IN,
        nsec3paramTTL,
        NSEC3Record.SHA1_DIGEST_ID,
        (byte) 0, iterations, salt);
    records.add(nsec3param);
  }

  /**
   * For a given node (representing all of the RRsets at a given name), generate
   * all of the necessary NSEC3 records for it. That is, generate the NSEC3 for
   * the node itself, and for any potential empty non-terminals.
   *
   * @param node       The node in question.
   * @param zonename   The zonename.
   * @param salt       The salt to use for the NSEC3 RRs
   * @param iterations The iterations to use for the NSEC3 RRs.
   * @param optIn      If true, the NSEC3 will have the Opt-Out flag set.
   * @param nsec3s     The current list of NSEC3s -- this will be updated.
   * @throws NoSuchAlgorithmException
   */
  private static void generateNSEC3ForNode(NodeInfo node, Name zonename, byte[] salt,
      int iterations, boolean optIn, List<ProtoNSEC3> nsec3s)
      throws NoSuchAlgorithmException {
    if (node == null)
      return;
    if (optIn && !node.isSecureNode)
      return;

    // Add our default types.
    if (node.type == RR_NORMAL || (node.type == RR_DELEGATION && node.hasType(Type.DS))) {
      node.addType(Type.RRSIG);
    }
    if (node.name.equals(zonename))
      node.addType(Type.NSEC3PARAM);

    // Check for ENTs -- note this will generate duplicate ENTs because it
    // doesn't use any context.
    int ldiff = node.name.labels() - zonename.labels();
    for (int i = 1; i < ldiff; i++) {
      Name n = new Name(node.name, i);
      log.finer("Generating ENT NSEC3 for " + n);
      ProtoNSEC3 nsec3 = generateNSEC3(n, zonename, node.ttl, salt, iterations, optIn,
          null);
      nsec3s.add(nsec3);
    }

    ProtoNSEC3 nsec3 = generateNSEC3(node.name, zonename, node.ttl, salt, iterations,
        optIn, node.getTypes());
    nsec3s.add(nsec3);
  }

  /**
   * Create a "prototype" NSEC3 record. Basically, a mutable NSEC3 record.
   *
   * @param name       The original ownername to use.
   * @param zonename   The zonename to use.
   * @param ttl        The TTL to use.
   * @param salt       The salt to use.
   * @param iterations The number of hash iterations to use.
   * @param optIn      The value of the Opt-Out flag.
   * @param types      The typecodes present at this name.
   * @return A mutable NSEC3 record.
   *
   * @throws NoSuchAlgorithmException
   */
  private static ProtoNSEC3 generateNSEC3(Name name, Name zonename, long ttl,
      byte[] salt, int iterations, boolean optIn,
      int[] types) throws NoSuchAlgorithmException {
    byte[] hash = nsec3hash(name, NSEC3Record.SHA1_DIGEST_ID, iterations, salt);
    byte flags = (byte) (optIn ? 0x01 : 0x00);

    ProtoNSEC3 r = new ProtoNSEC3(hash, name, zonename, DClass.IN, ttl,
        NSEC3Record.SHA1_DIGEST_ID, flags, iterations, salt,
        null, types);

    log.finer("Generated: " + r);
    return r;
  }

  /**
   * Given a list of {@link ProtoNSEC3} object (mutable NSEC3 RRs), convert the
   * list into the set of actual {@link org.xbill.DNS.NSEC3Record} objects. This
   * will remove duplicates and finalize the records.
   *
   * @param nsec3s The list of ProtoNSEC3 objects
   * @param ttl    The TTL to assign to the finished NSEC3 records. In general,
   *               this should match the SOA minimum value for the zone.
   * @return The list of {@link org.xbill.DNS.NSEC3Record} objects.
   */
  private static List<NSEC3Record> finishNSEC3s(List<ProtoNSEC3> nsec3s, long ttl) {
    if (nsec3s == null)
      return new ArrayList<>();
    Collections.sort(nsec3s, new ProtoNSEC3.Comparator());

    ProtoNSEC3 prevNSEC3 = null;
    ProtoNSEC3 curNSEC3 = null;
    byte[] firstNSEC3Hash = null;

    for (ListIterator<ProtoNSEC3> i = nsec3s.listIterator(); i.hasNext();) {
      curNSEC3 = i.next();

      // check to see if cur is a duplicate (by name)
      if (prevNSEC3 != null
          && Arrays.equals(prevNSEC3.getOwner(), curNSEC3.getOwner())) {
        log.finer("found duplicate NSEC3 (by name) -- merging type maps: "
            + prevNSEC3.getTypemap() + " and " + curNSEC3.getTypemap());
        i.remove();
        prevNSEC3.mergeTypes(curNSEC3.getTypemap());
        log.finer("merged type map: " + prevNSEC3.getTypemap());
        continue;
      }

      byte[] next = curNSEC3.getOwner();

      if (prevNSEC3 == null) {
        prevNSEC3 = curNSEC3;
        firstNSEC3Hash = next;
        continue;
      }

      prevNSEC3.setNext(next);
      prevNSEC3 = curNSEC3;
    }

    // Handle last NSEC3.
    if (prevNSEC3.getNext() == null) {
      // if prev_nsec3's next field hasn't been set, then it is the last
      // record (i.e., all remaining records were duplicates.)
      prevNSEC3.setNext(firstNSEC3Hash);
    } else {
      // otherwise, cur_nsec3 is the last record.
      curNSEC3.setNext(firstNSEC3Hash);
    }

    // Convert our ProtoNSEC3s to actual (immutable) NSEC3Record objects.
    List<NSEC3Record> res = new ArrayList<>(nsec3s.size());
    for (ProtoNSEC3 p : nsec3s) {
      p.setTTL(ttl);
      res.add(p.getNSEC3Record());
    }

    return res;
  }

  /**
   * Given a canonical (by name) ordered list of records in a zone, generate the
   * NSEC records in place.
   *
   * Note that the list that the records are stored in must support the
   * <code>listIterator.add</code> operation.
   *
   * @param zonename       the name of the zone apex, used to distinguish
   *                       between authoritative and delegation NS RRsets.
   * @param records        a list of {@link org.xbill.DNS.Record}s in DNSSEC
   *                       canonical order.
   * @param includeNames   a list of names that should be in the NXT chain
   *                       regardless. This may be null.
   * @param beConservative if true, then Opt-In NXTs will only be generated
   *                       where there is actually a span of insecure
   *                       delegations.
   */
  public static void generateOptInNSECRecords(Name zonename, List<Record> records,
      List<Name> includeNames,
      boolean beConservative) {
    // This works by iterating over a known sorted list of records.

    NodeInfo lastNode = null;
    NodeInfo currentNode = null;

    Name lastCut = null;
    Name lastDname = null;

    int backup;
    HashSet<Name> includeSet = null;

    if (includeNames != null) {
      includeSet = new HashSet<>(includeNames);
    }

    for (ListIterator<Record> i = records.listIterator(); i.hasNext();) {
      Record r = i.next();
      Name rName = r.getName();
      int rType = r.getType();
      int rSecType = recordSecType(zonename, rName, rType, lastCut, lastDname);

      // skip irrelevant records
      if (rSecType == RR_INVALID || rSecType == RR_GLUE)
        continue;

      // note our last delegation point so we can recognize glue.
      if (rSecType == RR_DELEGATION)
        lastCut = rName;

      if (rType == Type.DNAME)
        lastDname = rName;

      // first node -- initialize
      if (currentNode == null) {
        currentNode = new NodeInfo(r, rSecType);
        currentNode.addType(Type.RRSIG);
        continue;
      }

      // record name hasn't changed, so we are still on the same node.
      if (rName.equals(currentNode.name)) {
        currentNode.addType(rType);
        continue;
      }

      // If the name is in the set of included names, mark it as
      // secure.
      if (includeSet != null && includeSet.contains(currentNode.name)) {
        currentNode.isSecureNode = true;
      }

      if (lastNode != null && currentNode.isSecureNode) {
        // generate a NSEC record.
        if (beConservative && !lastNode.hasOptInSpan) {
          lastNode.addType(Type.NSEC);
        }
        NSECRecord nsec = new NSECRecord(lastNode.name, lastNode.dclass, lastNode.ttl,
            currentNode.name, lastNode.getTypes());
        // Note: we have to add this through the iterator, otherwise
        // the next access via the iterator will generate a
        // ConcurrencyModificationException.
        backup = i.nextIndex() - lastNode.nsecIndex;
        for (int j = 0; j < backup; j++)
          i.previous();
        i.add(nsec);
        for (int j = 0; j < backup; j++)
          i.next();

        log.finer("Generated: " + nsec);
      }

      if (currentNode.isSecureNode) {
        lastNode = currentNode;
      } else if (lastNode != null) {
        // last_node does not change -- last_node is essentially the
        // last *secure* node, and current_node is not secure.
        // However, we need to note the passing of the insecure node.
        lastNode.hasOptInSpan = true;
      }

      currentNode.nsecIndex = i.previousIndex();
      currentNode = new NodeInfo(r, rSecType);
      currentNode.addType(Type.RRSIG);
    }

    // Generate next to last NSEC
    if (lastNode != null && currentNode.isSecureNode) {
      // generate a NSEC record.
      if (beConservative && !lastNode.hasOptInSpan) {
        lastNode.addType(Type.NSEC);
      }
      NSECRecord nsec = new NSECRecord(lastNode.name, lastNode.dclass, lastNode.ttl,
          currentNode.name, lastNode.getTypes());
      records.add(lastNode.nsecIndex - 1, nsec);
      log.finer("Generated: " + nsec);
    }

    // Generate last NSEC
    NSECRecord nsec;
    if (currentNode.isSecureNode) {
      if (beConservative) {
        currentNode.addType(Type.NSEC);
      }
      nsec = new NSECRecord(currentNode.name, currentNode.dclass, currentNode.ttl,
          zonename, currentNode.getTypes());
      // we can just tack this on the end as we are working on the
      // last node.
      records.add(nsec);
    } else {
      nsec = new NSECRecord(lastNode.name, lastNode.dclass, lastNode.ttl, zonename,
          lastNode.getTypes());
      // We need to tack this on after the last secure node, not the
      // end of the whole list.
      records.add(lastNode.nsecIndex, nsec);
    }

    log.finer("Generated: " + nsec);
  }

  /**
   * Given a zone with DNSKEY records at delegation points, convert those KEY
   * records into their corresponding DS records in place.
   *
   * @param zonename  the name of the zone, used to reliably distinguish the
   *                  zone apex from other records.
   * @param records   a list of {@link org.xbill.DNS.Record} objects.
   * @param digestAlg The digest algorithm to use.
   */
  public static void generateDSRecords(Name zonename, List<Record> records, int digestAlg) {

    for (ListIterator<Record> i = records.listIterator(); i.hasNext();) {
      Record r = i.next();
      if (r == null)
        continue; // this should never be true.

      Name rName = r.getName();
      if (rName == null)
        continue; // this should never be true.

      // Convert non-zone level KEY records into DS records.
      if (r.getType() == Type.DNSKEY && !rName.equals(zonename)) {
        DSRecord ds = calculateDSRecord((DNSKEYRecord) r, digestAlg, r.getTTL());

        i.set(ds);
      }
    }
  }

  /**
   * Given a zone, remove all records that are generated.
   *
   * @param zonename the name of the zone.
   * @param records  a list of {@link org.xbill.DNS.Record} objects.
   */
  public static void removeGeneratedRecords(Name zonename, List<Record> records) {
    for (Iterator<Record> i = records.iterator(); i.hasNext();) {
      Record r = i.next();

      if (r.getType() == Type.RRSIG || r.getType() == Type.NSEC
          || r.getType() == Type.NSEC3 || r.getType() == Type.NSEC3PARAM) {
        i.remove();
      }
    }
  }

  /**
   * Remove duplicate records from a list of records. This routine presumes the
   * list of records is in a canonical sorted order, at least on name and RR
   * type.
   *
   * @param records a list of {@link org.xbill.DNS.Record} object, in sorted
   *                order.
   */
  public static void removeDuplicateRecords(List<Record> records) {
    Record lastrec = null;
    for (Iterator<Record> i = records.iterator(); i.hasNext();) {
      Record r = i.next();
      if (lastrec == null) {
        lastrec = r;
        continue;
      }
      if (lastrec.equals(r)) {
        i.remove();
        continue;
      }
      lastrec = r;
    }
  }

  /**
   * Given a DNSKEY record, generate the DS record from it.
   *
   * @param keyrec    the KEY record in question.
   * @param digestAlg The digest algorithm (SHA-1, SHA-256, etc.).
   * @param ttl       the desired TTL for the generated DS record. If zero, or
   *                  negative, the original KEY RR's TTL will be used.
   * @return the corresponding {@link org.xbill.DNS.DSRecord}
   */
  public static DSRecord calculateDSRecord(DNSKEYRecord keyrec, int digestAlg, long ttl) {
    if (keyrec == null)
      return null;

    if (ttl <= 0)
      ttl = keyrec.getTTL();

    DNSOutput os = new DNSOutput();

    os.writeByteArray(keyrec.getName().toWireCanonical());
    os.writeByteArray(keyrec.rdataToWireCanonical());

    try {
      byte[] digest;
      MessageDigest md;

      switch (digestAlg) {
        case DNSSEC.Digest.SHA1:
          md = MessageDigest.getInstance("SHA");
          digest = md.digest(os.toByteArray());
          break;
        case DNSSEC.Digest.SHA256:
          md = MessageDigest.getInstance("SHA-256");
          digest = md.digest(os.toByteArray());
          break;
        default:
          throw new IllegalArgumentException("Unknown digest id: " + digestAlg);
      }

      return new DSRecord(keyrec.getName(), keyrec.getDClass(), ttl,
          keyrec.getFootprint(), keyrec.getAlgorithm(), digestAlg,
          digest);

    } catch (NoSuchAlgorithmException e) {
      log.severe(e.toString());
      return null;
    }
  }

  /**
   * Calculate an NSEC3 hash based on a DNS name and NSEC3 hash parameters.
   *
   * @param n             The name to hash.
   * @param hashAlgorithm The hash algorithm to use.
   * @param iterations    The number of iterations to do.
   * @param salt          The salt to use.
   * @return The calculated hash as a byte array.
   * @throws NoSuchAlgorithmException If the hash algorithm is unrecognized.
   */
  public static byte[] nsec3hash(Name n, int hashAlgorithm, int iterations, byte[] salt)
      throws NoSuchAlgorithmException {
    MessageDigest md;

    if (hashAlgorithm != NSEC3Record.SHA1_DIGEST_ID) {
      throw new NoSuchAlgorithmException("Unknown NSEC3 algorithm identifier: " + hashAlgorithm);
    }
    md = MessageDigest.getInstance("SHA1");

    // Construct our wire form.
    byte[] wireName = n.toWireCanonical();
    byte[] res = wireName; // for the first iteration.
    for (int i = 0; i <= iterations; i++) {
      // Concatenate the salt, if it exists.
      if (salt != null) {
        byte[] concat = new byte[res.length + salt.length];
        System.arraycopy(res, 0, concat, 0, res.length);
        System.arraycopy(salt, 0, concat, res.length, salt.length);
        res = concat;
      }
      res = md.digest(res);
    }

    return res;
  }

}
