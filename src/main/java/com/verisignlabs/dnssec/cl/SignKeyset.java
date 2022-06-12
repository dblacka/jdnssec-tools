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
import java.io.FileFilter;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.OptionBuilder;
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
 * This class forms the command line implementation of a DNSSEC keyset signer.
 * Instead of being able to sign an entire zone, it will just sign a given
 * DNSKEY RRset.
 * 
 * @author David Blacka
 */
public class SignKeyset extends CLBase {
  private CLIState state;

  /**
   * This is an inner class used to hold all of the command line option state.
   */
  protected static class CLIState extends CLIStateBase {
    public File keyDirectory = null;
    public String[] keyFiles = null;
    public Instant start = null;
    public Instant expire = null;
    public String inputfile = null;
    public String outputfile = null;
    public boolean verifySigs = false;

    public CLIState() {
      super("jdnssec-signkeyset [..options..] dnskeyset_file [key_file ...]");
    }

    /**
     * Set up the command line options.
     */
    protected void setupOptions(Options opts) {
      // boolean options
      opts.addOption("a", "verify", false, "verify generated signatures>");

      // Argument options
      OptionBuilder.hasArg();
      OptionBuilder.withArgName("dir");
      OptionBuilder.withLongOpt("key-directory");
      OptionBuilder.withDescription("directory to find key files (default '.').");
      opts.addOption(OptionBuilder.create('D'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("time/offset");
      OptionBuilder.withLongOpt("start-time");
      OptionBuilder.withDescription("signature starting time (default is now - 1 hour)");
      opts.addOption(OptionBuilder.create('s'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("time/offset");
      OptionBuilder.withLongOpt("expire-time");
      OptionBuilder.withDescription("signature expiration time (default is start-time + 30 days).");
      opts.addOption(OptionBuilder.create('e'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("outfile");
      OptionBuilder.withDescription("file the signed keyset is written to.");
      opts.addOption(OptionBuilder.create('f'));
    }

    protected void processOptions(CommandLine cli)
        throws org.apache.commons.cli.ParseException {
      String optstr = null;

      if (cli.hasOption('a'))
        verifySigs = true;

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
   * @param zonename
   *                 the origin name of the zone.
   * @param records
   *                 a list of {@link org.xbill.DNS.Record}s.
   * @param keypairs
   *                 a list of keypairs used the sign the zone.
   * @return true if all of the signatures validated.
   */
  private static boolean verifySigs(Name zonename, List<Record> records,
      List<DnsKeyPair> keypairs) {
    boolean secure = true;

    DnsSecVerifier verifier = new DnsSecVerifier();

    for (DnsKeyPair pair : keypairs) {
      verifier.addTrustedKey(pair);
    }

    verifier.setVerifyAllSigs(true);

    List<RRset> rrsets = SignUtils.assembleIntoRRsets(records);

    for (RRset rrset : rrsets) {
      // skip unsigned rrsets.
      if (rrset.sigs().isEmpty())
        continue;

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
   * @param keyfiles
   *                    a string array containing the base names or paths of the
   *                    keys
   *                    to be loaded.
   * @param start_index
   *                    the starting index of keyfiles string array to use. This
   *                    allows us to use the straight command line argument array.
   * @param inDirectory
   *                    the directory to look in (may be null).
   * @return a list of keypair objects.
   */
  private static List<DnsKeyPair> getKeys(String[] keyfiles, int start_index,
      File inDirectory) throws IOException {
    if (keyfiles == null)
      return null;

    int len = keyfiles.length - start_index;
    if (len <= 0)
      return null;

    ArrayList<DnsKeyPair> keys = new ArrayList<DnsKeyPair>(len);

    for (int i = start_index; i < keyfiles.length; i++) {
      DnsKeyPair k = BINDKeyUtils.loadKeyPair(keyfiles[i], inDirectory);
      if (k != null)
        keys.add(k);
    }

    return keys;
  }

  private static class KeyFileFilter implements FileFilter {
    private String prefix;

    public KeyFileFilter(Name origin) {
      prefix = "K" + origin.toString();
    }

    public boolean accept(File pathname) {
      if (!pathname.isFile())
        return false;
      String name = pathname.getName();
      if (name.startsWith(prefix) && name.endsWith(".private"))
        return true;
      return false;
    }
  }

  private static List<DnsKeyPair> findZoneKeys(File inDirectory, Name zonename)
      throws IOException {
    if (inDirectory == null) {
      inDirectory = new File(".");
    }

    // get the list of "K<zone>.*.private files.
    FileFilter filter = new KeyFileFilter(zonename);
    File[] files = inDirectory.listFiles(filter);

    // read in all of the records
    ArrayList<DnsKeyPair> keys = new ArrayList<DnsKeyPair>();
    for (int i = 0; i < files.length; i++) {
      DnsKeyPair p = BINDKeyUtils.loadKeyPair(files[i].getName(), inDirectory);
      keys.add(p);
    }

    if (keys.size() > 0)
      return keys;
    return null;
  }

  public void execute() throws Exception {
    // Read in the zone
    List<Record> records = ZoneUtils.readZoneFile(state.inputfile, null);
    if (records == null || records.size() == 0) {
      System.err.println("error: empty keyset file");
      state.usage();
    }

    // Make sure that all records are DNSKEYs with the same name.
    Name keysetName = null;
    RRset keyset = new RRset();

    for (Record r : records) {
      if (r.getType() != Type.DNSKEY) {
        System.err.println("error: Non DNSKEY RR found in keyset: " + r);
        continue;
      }
      if (keysetName == null) {
        keysetName = r.getName();
      }
      if (!r.getName().equals(keysetName)) {
        System.err.println("error: DNSKEY with a different name found!");
        state.usage();
      }
      keyset.addRR(r);
    }

    if (keyset.size() == 0) {
      System.err.println("error: No DNSKEYs found in keyset file");
      state.usage();
    }

    // Load the key pairs.
    List<DnsKeyPair> keypairs = getKeys(state.keyFiles, 0, state.keyDirectory);

    // If we *still* don't have any key pairs, look for keys the key
    // directory
    // that match
    if (keypairs == null) {
      keypairs = findZoneKeys(state.keyDirectory, keysetName);
    }

    // If there *still* aren't any ZSKs defined, bail.
    if (keypairs == null || keypairs.size() == 0) {
      System.err.println("error: No signing keys could be determined.");
      state.usage();
    }

    // default the output file, if not set.
    if (state.outputfile == null) {
      if (keysetName.isAbsolute()) {
        state.outputfile = keysetName + "signed_keyset";
      } else {
        state.outputfile = keysetName + ".signed_keyset";
      }
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    List<RRSIGRecord> sigs = signer.signRRset(keyset, keypairs, state.start, state.expire);
    for (RRSIGRecord s : sigs) {
      keyset.addRR(s);
    }

    // write out the signed RRset
    List<Record> signed_records = new ArrayList<Record>();
    for (Record r : keyset.rrs()) {
      signed_records.add(r);
    }
    for (RRSIGRecord s : keyset.sigs()) {
      signed_records.add(s);
    }

    // write out the signed zone
    ZoneUtils.writeZoneFile(signed_records, state.outputfile);

    if (state.verifySigs) {
      log.fine("verifying generated signatures");
      boolean res = verifySigs(keysetName, signed_records, keypairs);

      if (res) {
        System.out.println("Generated signatures verified");
        // log.info("Generated signatures verified");
      } else {
        System.out.println("Generated signatures did not verify.");
        // log.warn("Generated signatures did not verify.");
      }
    }

  }

  public static void main(String[] args) {
    SignKeyset tool = new SignKeyset();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }
}
