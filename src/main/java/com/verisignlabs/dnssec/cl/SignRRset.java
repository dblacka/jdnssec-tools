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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
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
  private CLIState state;

  /**
   * This is an inner class used to hold all of the command line option state.
   */
  protected static class CLIState extends CLIStateBase {
    private File keyDirectory      = null;
    public  String[] keyFiles      = null;
    public  Instant start          = null;
    public  Instant expire         = null;
    public  String inputfile       = null;
    public  String outputfile      = null;
    public  boolean verifySigs     = false;
    public  boolean verboseSigning = false;

    public CLIState() {
      super("jdnssec-signrrset [..options..] rrset_file key_file [key_file ...]");
    }

    /**
     * Set up the command line options.
     */
    @Override
    protected void setupOptions(Options opts) {
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

    @Override
    protected void processOptions(CommandLine cli) throws org.apache.commons.cli.ParseException {
      String optstr = null;

      if (cli.hasOption('a'))
        verifySigs = true;
      if (cli.hasOption('V'))
        verboseSigning = true;

      if ((optstr = cli.getOptionValue('D')) != null) {
        keyDirectory = new File(optstr);
        if (!keyDirectory.isDirectory()) {
          System.err.println("error: " + optstr + " is not a directory");
          usage();
        }
      }

      if ((optstr = cli.getOptionValue('s')) != null) {
        start = convertDuration(null, optstr);
      } else {
        // default is now - 1 hour.
        start = Instant.now().minusSeconds(3600);
      }

      if ((optstr = cli.getOptionValue('e')) != null) {
        expire = convertDuration(start, optstr);
      } else {
        expire = convertDuration(start, "+2592000"); // 30 days
      }

      outputfile = cli.getOptionValue('f');

      String[] files = cli.getArgs();

      if (files.length < 1) {
        System.err.println("error: missing zone file and/or key files");
        usage();
      }

      inputfile = files[0];
      if (files.length > 1) {
        keyFiles = new String[files.length - 1];
        System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
      }
    }
  }

  /**
   * Verify the generated signatures.
   *
   * @param records
   *                 a list of {@link org.xbill.DNS.Record}s.
   * @param keypairs
   *                 a list of keypairs used the sign the zone.
   * @return true if all of the signatures validated.
   */
  private static boolean verifySigs(List<Record> records, List<DnsKeyPair> keypairs) {
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
        staticLog.fine("Signatures did not verify for RRset: " + rrset);
        secure = false;
      }
    }

    return secure;
  }

  /**
   * Load the key pairs from the key files.
   *
   * @param keyfiles
   *                    a string array containing the base names or paths of the
   *                    keys
   *                    to be loaded.
   * @param startIndex
   *                    the starting index of keyfiles string array to use. This
   *                    allows us to use the straight command line argument array.
   * @param inDirectory
   *                    the directory to look in (may be null).
   * @return a list of keypair objects.
   */
  private static List<DnsKeyPair> getKeys(String[] keyfiles, int startIndex,
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
    List<Record> records = ZoneUtils.readZoneFile(state.inputfile, null);
    if (records == null || records.isEmpty()) {
      System.err.println("error: empty RRset file");
      state.usage();
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
        System.err.println("Records do not all belong to the same RRset.");
        state.usage();
      }
    }

    if (rrset == null || rrset.size() == 0) {
      System.err.println("No records found in inputfile.");
      state.usage();
      return;
    }

    // Load the key pairs.

    if (state.keyFiles.length == 0) {
      System.err.println("error: at least one keyfile must be specified");
      state.usage();
    }

    List<DnsKeyPair> keypairs = getKeys(state.keyFiles, 0, state.keyDirectory);

    // Make sure that all the keypairs have the same name.
    // This will be used as the zone name, too.

    Name keysetName = null;
    for (DnsKeyPair pair : keypairs) {
      if (keysetName == null) {
        keysetName = pair.getDNSKEYName();
        continue;
      }
      if (!pair.getDNSKEYName().equals(keysetName)) {
        System.err.println("Keys do not all have the same name.");
        state.usage();
      }
    }

    // default the output file, if not set.
    if (state.outputfile == null && !state.inputfile.equals("-")) {
      state.outputfile = state.inputfile + ".signed";
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner(state.verboseSigning);

    List<RRSIGRecord> sigs = signer.signRRset(rrset, keypairs, state.start, state.expire);
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
    ZoneUtils.writeZoneFile(signedRecords, state.outputfile);

    if (state.verifySigs) {
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
    SignRRset tool = new SignRRset();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }
}
