// Copyright (C) 2001-2003, 2011, 2022 VeriSign, Inc.
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

package com.verisignlabs.dnssec.cl;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.Option;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import com.verisignlabs.dnssec.security.BINDKeyUtils;
import com.verisignlabs.dnssec.security.DnsKeyPair;
import com.verisignlabs.dnssec.security.DnsSecVerifier;
import com.verisignlabs.dnssec.security.JCEDnsSecSigner;
import com.verisignlabs.dnssec.security.SignUtils;
import com.verisignlabs.dnssec.security.ZoneUtils;

/**
 * This class forms the command line implementation of a DNSSEC RRset signer.
 * Instead of being able to sign an entire zone, it will just sign a given
 * RRset. Note that it will sign any RRset with any private key without
 * consideration of whether or not the RRset *should* be signed in the context
 * of a zone.
 *
 * @author David Blacka
 */
public class SignRRset extends CLBase {
  private File keyDirectory = null;
  private String[] keyFiles = null;
  private Instant start = null;
  private Instant expire = null;
  private String inputfile = null;
  private String outputfile = null;
  private boolean verifySigs = false;
  private boolean verboseSigning = false;


  public SignRRset(String name, String usageStr) {
    super(name, usageStr);
  }

 

  /**
   * Set up the command line options.
   */
  protected void setupOptions() {
    // boolean options
    opts.addOption("a", "verify", false, "verify generated signatures>");
    opts.addOption("V", "verbose-signing", false, "Display verbose signing activity.");

    opts.addOption(Option.builder("D").hasArg().argName("dir").longOpt("key-directory")
        .desc("directory to find key files (default '.'").build());
    opts.addOption(Option.builder("s").hasArg().argName("time/offset").longOpt("start-time")
        .desc("signature starting time (default is now - 1 hour)").build());
    opts.addOption(Option.builder("e").hasArg().argName("time/offset").longOpt("expire-time")
        .desc("signature expiration time (default is start-time + 30 days)").build());
    opts.addOption(
        Option.builder("f").hasArg().argName("outfile").desc("file the the signed rrset is written to").build());
  }

  protected void processOptions() {
    String[] verifyOptionKeys = { "verify_signatures", "verify" };
    String[] verboseSigningOptionKeys = { "verbose_signing" };
    String[] keyDirectoryOptionKeys = { "key_directory", "keydir" };
    String[] inceptionOptionKeys = { "inception", "start" };
    String[] expireOptionKeys = { "expire" };

    String optstr = null;

    verifySigs = cliBooleanOption("a", verifyOptionKeys, false);

    verboseSigning = cliBooleanOption("V", verboseSigningOptionKeys, false);

    optstr = cliOption("D", keyDirectoryOptionKeys, null);
    if (optstr != null) {
      keyDirectory = new File(optstr);
      if (!keyDirectory.isDirectory()) {
        fail("key directory " + optstr + " is not a directory");
      }
    }

    try {
      optstr = cliOption("s", inceptionOptionKeys, null);
      if (optstr != null) {
        start = Utils.convertDuration(null, optstr);
      } else {
        // default is now - 1 hour.
        start = Instant.now().minusSeconds(3600);
      }
    } catch (java.text.ParseException e) {
      fail("unable to parse start time specifiction: " + e);
    }

    try {   
      optstr = cliOption("e", expireOptionKeys, null);
      if (optstr != null) {
        expire = Utils.convertDuration(start, optstr);
      } else {
        expire = Utils.convertDuration(start, "+2592000"); // 30 days
      }
    } catch (java.text.ParseException e) {
      fail("Unable to parse expire time specification: " + e);
    }

    outputfile = cli.getOptionValue('f');

    String[] files = cli.getArgs();

    if (files.length < 1) {
      fail("missing zone file and/or key files");
    }

    inputfile = files[0];
    if (files.length > 1) {
      keyFiles = new String[files.length - 1];
      System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
    }
  }


  /**
   * Verify the generated signatures.
   *
   * @param records  a list of {@link org.xbill.DNS.Record}s.
   * @param keypairs a list of keypairs used the sign the zone.
   * @return true if all of the signatures validated.
   */
  private boolean verifySigs(List<Record> records, List<DnsKeyPair> keypairs) {
    boolean secure = true;

    DnsSecVerifier verifier = new DnsSecVerifier();

    for (DnsKeyPair pair : keypairs) {
      verifier.addTrustedKey(pair);
    }

    verifier.setVerifyAllSigs(true);

    List<RRset> rrsets = SignUtils.assembleIntoRRsets(records);

    for (RRset rrset : rrsets) {
      // skip unsigned rrsets.
      if (rrset.sigs().isEmpty()) {
        continue;
      }

      boolean result = verifier.verify(rrset);

      if (!result) {
        log.fine("Signatures did not verify for RRset: " + rrset);
        secure = false;
      }
    }

    return secure;
  }

  /**
   * Load the key pairs from the key files.
   *
   * @param keyfiles    a string array containing the base names or paths of the
   *                    keys to be loaded.
   * @param startIndex  the starting index of keyfiles string array to use. This
   *                    allows us to use the straight command line argument
   *                    array.
   * @param inDirectory the directory to look in (may be null).
   * @return a list of keypair objects.
   */
  private List<DnsKeyPair> getKeys(String[] keyfiles, int startIndex,
      File inDirectory) throws IOException {
    if (keyfiles == null)
      return new ArrayList<>();

    int len = keyfiles.length - startIndex;
    if (len <= 0)
      return new ArrayList<>();

    ArrayList<DnsKeyPair> keys = new ArrayList<>(len);

    for (int i = startIndex; i < keyfiles.length; i++) {
      DnsKeyPair k = BINDKeyUtils.loadKeyPair(keyfiles[i], inDirectory);
      if (k != null)
        keys.add(k);
    }

    return keys;
  }

  public void execute() throws Exception {
    // Read in the zone
    List<Record> records = ZoneUtils.readZoneFile(inputfile, null);
    if (records == null || records.isEmpty()) {
      fail("empty RRset file");
    }
    // Construct the RRset. Complain if the records in the input file
    // consist of more than one RRset.
    RRset rrset = null;

    for (Record r : records) {
      // skip RRSIGs
      if (r.getType() == Type.RRSIG || r.getType() == Type.SIG) {
        continue;
      }

      // Handle the first record.
      if (rrset == null) {
        rrset = new RRset();
        rrset.addRR(r);
        continue;
      }
      // Ensure that the remaining records all belong to the same rrset.
      if (rrset.getName().equals(r.getName()) && rrset.getType() == r.getType()
          && rrset.getDClass() == r.getDClass()) {
        rrset.addRR(r);
      } else {
        fail("records do not all belong to the same RRset");
      }
    }

    if (rrset == null || rrset.size() == 0) {
      fail("no records found in inputfile");
    }

    // Load the key pairs.

    if (keyFiles.length == 0) {
      fail("at least one keyfile must be specified");
    }

    List<DnsKeyPair> keypairs = getKeys(keyFiles, 0, keyDirectory);

    // Make sure that all the keypairs have the same name.
    // This will be used as the zone name, too.

    Name keysetName = null;
    for (DnsKeyPair pair : keypairs) {
      if (keysetName == null) {
        keysetName = pair.getDNSKEYName();
        continue;
      }
      if (!pair.getDNSKEYName().equals(keysetName)) {
        fail("keys do not all have the same name");
      }
    }

    // default the output file, if not set.
    if (outputfile == null && !inputfile.equals("-")) {
      outputfile = inputfile + ".signed";
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner(verboseSigning);

    List<RRSIGRecord> sigs = signer.signRRset(rrset, keypairs, start, expire);
    for (RRSIGRecord s : sigs) {
      rrset.addRR(s);
    }

    // write out the signed RRset
    List<Record> signedRecords = new ArrayList<>();
    for (Record r : rrset.rrs()) {
      signedRecords.add(r);
    }
    for (RRSIGRecord sigrec : rrset.sigs()) {
      signedRecords.add(sigrec);
    }

    // write out the signed zone
    ZoneUtils.writeZoneFile(signedRecords, outputfile);

    if (verifySigs) {
      log.fine("verifying generated signatures");
      boolean res = verifySigs(signedRecords, keypairs);

      if (res) {
        System.out.println("Generated signatures verified");
      } else {
        System.out.println("Generated signatures did not verify.");
      }
    }

  }

  public static void main(String[] args) {
    SignRRset tool = new SignRRset("signrrset", "jdnssec-signrrset [..options..] rrset_file key_file [key_file ...]");

    tool.run(args);
  }
}
