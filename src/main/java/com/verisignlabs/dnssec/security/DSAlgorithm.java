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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Logger;

import org.xbill.DNS.CDSRecord;
import org.xbill.DNS.DLVRecord;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSOutput;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;

/**
 * This class handles the implementation behind converting DNSKEYs into
 * DSRecords. It primarily exists to bootstrap whatever crypto libraries we
 * might need to do so.
 *
 * @author David Blacka
 */
public class DSAlgorithm {

    private Logger log = Logger.getLogger(this.getClass().toString());

    HashSet<Integer> mSupportedAlgorithms = null;

    private static DSAlgorithm mInstance = null;

    public DSAlgorithm() {
        mSupportedAlgorithms = new HashSet<>();
        mSupportedAlgorithms.add(DNSSEC.Digest.SHA1);
        mSupportedAlgorithms.add(DNSSEC.Digest.SHA256);
        mSupportedAlgorithms.add(DNSSEC.Digest.SHA384);
        // Attempt to add the bouncycastle provider. This is so we can use this
        // provider if it is available, but not require the user to add it as one of
        // the java.security providers.
        try {
            Class<?> bcProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider bcProvider = (Provider) bcProviderClass.getDeclaredConstructor().newInstance();
            Security.addProvider(bcProvider);
            log.fine("bouncycastle crypto provider loaded");
            mSupportedAlgorithms.add(DNSSEC.Digest.GOST3411);
        } catch (ReflectiveOperationException e) {
            // do nothing, this is the normal case
        }

    }

    public String[] supportedAlgorithmMnemonics() {
        ArrayList<String> algs = new ArrayList<>();

        for (int digestId : mSupportedAlgorithms) {
            algs.add(DNSSEC.Digest.string(digestId));
        }

        String[] result = new String[algs.size()];
        return algs.toArray(result);
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
    public DSRecord calculateDSRecord(DNSKEYRecord keyrec, int digestAlg, long ttl) {
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
                case DNSSEC.Digest.GOST3411:
                    // The standard Java crypto providers don't have this, but bouncycastle does
                    if (java.security.Security.getProviders("MessageDigest.GOST3411") != null) {
                        md = MessageDigest.getInstance("GOST3411");
                        digest = md.digest(os.toByteArray());
                    } else {
                        throw new IllegalArgumentException("Unsupported digest id: " + digestAlg);
                    }
                    break;
                case DNSSEC.Digest.SHA384:
                    md = MessageDigest.getInstance("SHA-384");
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

    public DLVRecord dsToDLV(DSRecord ds) {
        return new DLVRecord(ds.getName(), ds.getDClass(), ds.getTTL(), ds.getFootprint(), ds.getAlgorithm(),
                ds.getDigestID(), ds.getDigest());
    }

    public CDSRecord dstoCDS(DSRecord ds) {
        return new CDSRecord(ds.getName(), ds.getDClass(), ds.getTTL(), ds.getFootprint(), ds.getAlgorithm(),
                ds.getDClass(), ds.getDigest());
    }

    public static DSAlgorithm getInstance() {
        if (mInstance == null) {
            mInstance = new DSAlgorithm();
        }
        return mInstance;
    }
}