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
 * This class forms the command line implementation of a DNSSEC keyset signer.
 * Instead of being able to sign an entire zone, it will just sign a given
 * DNSKEY RRset.
 * 
 * @author David Blacka
 */
public class SignKeyset extends CLBase {
  private File keyDirectory = null;
  private String[] keyFiles = null;
  private Instant start = null;
  private Instant expire = null;
  private String inputfile = null;
  private String outputfile = null;
  private boolean verifySigs = false;

  public SignKeyset(String name, String usageStr) {
    super(name, usageStr);
  }


  /**
   * Set up the command line options.
   */

  protected void setupOptions() {
    // boolean options
    opts.addOption("a", "verify", false, "verify generated signatures>");

    // Argument options
    opts.addOption(Option.builder("D").hasArg().argName("dir").longOpt("key-directory")
        .desc("directory where key files are found (default '.').").build());
    opts.addOption(Option.builder("s").hasArg().argName("time/offset").longOpt("start-time")
        .desc("signature starting time (default is now - 1 hour)").build());
    opts.addOption(Option.builder("e").hasArg().argName("time/offset").longOpt("expire-time")
        .desc("signature expiration time (default is start-time + 30 days)").build());
    opts.addOption(
        Option.builder("f").hasArg().argName("outfile").desc("file the signed keyset is written to").build());
  }


  protected void processOptions() {
      String[] verifyOptionKeys = { "verify_signatures", "verify" };
      String[] keyDirectoryOptionKeys = { "key_directory", "keydir" };
      String[] inceptionOptionKeys = { "inception", "start" };
      String[] expireOptionKeys = { "expire" };

      String optstr = null;

      verifySigs = cliBooleanOption("a", verifyOptionKeys, false);
      
      String keyDirectoryName = cliOption("D", keyDirectoryOptionKeys, null);
      if (keyDirectoryName != null) {
        keyDirectory = new File(optstr);
        if (!keyDirectory.isDirectory()) {
          log.severe("key directory " + optstr + " is not a directory");
          usage(true);
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
        System.err.println("Unable to parse start time specifiction: " + e);
        usage(true);
      }

      try {
        optstr = cliOption("e", expireOptionKeys, null);
        if (optstr != null) {
          expire = Utils.convertDuration(start, optstr);
        } else {
          expire = Utils.convertDuration(start, "+2592000"); // 30 days
        }
      } catch (java.text.ParseException e) {
        System.err.println("Unable to parse expire time specification: " + e);
        usage(true);
      }

      outputfile = cli.getOptionValue('f');

      String[] files = cli.getArgs();

      if (files.length < 1) {
        System.err.println("error: missing zone file and/or key files");
        usage(true);
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
  private boolean verifySigs(List<Record> records,
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

  private static class KeyFileFilter implements FileFilter {
    private String prefix;

    public KeyFileFilter(Name origin) {
      prefix = "K" + origin.toString();
    }

    public boolean accept(File pathname) {
      if (!pathname.isFile())
        return false;
      String name = pathname.getName();
      return (name.startsWith(prefix) && name.endsWith(".private"));
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
    ArrayList<DnsKeyPair> keys = new ArrayList<>();
    for (int i = 0; i < files.length; i++) {
      DnsKeyPair p = BINDKeyUtils.loadKeyPair(files[i].getName(), inDirectory);
      keys.add(p);
    }

    return keys;
  }

  public void execute() throws Exception {
    // Read in the zone
    List<Record> records = ZoneUtils.readZoneFile(inputfile, null);
    if (records == null || records.isEmpty()) {
      System.err.println("error: empty keyset file");
      usage(true);
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
        usage(true);
      }
      keyset.addRR(r);
    }

    if (keyset.size() == 0) {
      System.err.println("error: No DNSKEYs found in keyset file");
      usage(true);
    }

    // Load the key pairs.
    List<DnsKeyPair> keypairs = getKeys(keyFiles, 0, keyDirectory);

    // If we *still* don't have any key pairs, look for keys the key
    // directory
    // that match
    if (keypairs == null) {
      keypairs = findZoneKeys(keyDirectory, keysetName);
    }

    // If there *still* aren't any ZSKs defined, bail.
    if (keypairs == null || keypairs.isEmpty() || keysetName == null) {
      System.err.println("error: No signing keys could be determined.");
      usage(true);
      return;
    }

    // default the output file, if not set.
    if (outputfile == null) {
      if (keysetName.isAbsolute()) {
        outputfile = keysetName + "signed_keyset";
      } else {
        outputfile = keysetName + ".signed_keyset";
      }
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    List<RRSIGRecord> sigs = signer.signRRset(keyset, keypairs, start, expire);
    for (RRSIGRecord s : sigs) {
      keyset.addRR(s);
    }

    // write out the signed RRset
    List<Record> signedRecords = new ArrayList<>();
    for (Record r : keyset.rrs()) {
      signedRecords.add(r);
    }
    for (RRSIGRecord s : keyset.sigs()) {
      signedRecords.add(s);
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
    SignKeyset tool = new SignKeyset("signkeyset", "jdnssec-signkeyset [..options..] dnskeyset_file [key_file ...]");

    tool.run(args);
  }
}
