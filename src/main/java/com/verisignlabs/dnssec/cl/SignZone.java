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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.apache.commons.cli.Option;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base16;

import com.verisignlabs.dnssec.security.BINDKeyUtils;
import com.verisignlabs.dnssec.security.DnsKeyPair;
import com.verisignlabs.dnssec.security.DnsSecVerifier;
import com.verisignlabs.dnssec.security.JCEDnsSecSigner;
import com.verisignlabs.dnssec.security.SignUtils;
import com.verisignlabs.dnssec.security.ZoneUtils;

/**
 * This class forms the command line implementation of a DNSSEC zone signer.
 *
 * @author David Blacka
 */
public class SignZone extends CLBase {
  private File keyDirectory = null;
  private File keysetDirectory = null;
  private String[] kskFiles = null;
  private String[] keyFiles = null;
  private String zonefile = null;
  private Instant start = null;
  private Instant expire = null;
  private String outputfile = null;
  private boolean verifySigs = false;
  private boolean useOptOut = false;
  private boolean fullySignKeyset = false;
  private List<Name> includeNames = null;
  private boolean useNsec3 = false;
  private byte[] salt = null;
  private int iterations = 0;
  private int digestId = DNSSEC.Digest.SHA1;
  private long nsec3paramttl = -1;
  private boolean verboseSigning = false;

  private static final Random rand = new Random();

  public SignZone(String name, String usageStr) {
    super(name, usageStr);
  }

  protected void setupOptions() {
    // boolean options
    opts.addOption("a", "verify", false, "verify generated signatures>");
    opts.addOption("F", "fully-sign-keyset", false,
        "sign the zone apex keyset with all available keys.");
    opts.addOption("V", "verbose-signing", false, "Display verbose signing activity.");

    opts.addOption(Option.builder("d").hasArg().argName("dir").longOpt("keyset-directory")
        .desc("directory to find keyset files (default '.')").build());
    opts.addOption(Option.builder("D").hasArg().argName("dir").longOpt("key-directory")
        .desc("directory to find key files (default '.'").build());
    opts.addOption(Option.builder("s").hasArg().argName("time/offset").longOpt("start-time")
        .desc("signature starting time (default is now - 1 hour)").build());
    opts.addOption(Option.builder("e").hasArg().argName("time/offset").longOpt("expire-time")
        .desc("signature expiration time (default is start-time + 30 days)").build());
    opts.addOption(
        Option.builder("f").hasArg().argName("outfile").desc("file the the signed rrset is written to").build());
    opts.addOption(Option.builder("k").hasArgs().argName("KSK file").longOpt("ksk-file")
        .desc("This key is a Key-Signing Key (may repeat)").build());
    opts.addOption(Option.builder("I").hasArg().argName("file").longOpt("include-file")
        .desc("include names in the file in the NSEC/NSEC3 chain").build());

    // NSEC3 options
    opts.addOption("3", "use-nsec3", false, "use NSEC3 instead of NSEC");
    opts.addOption("O", "use-opt-out", false,
        "generate a fully Opt-Out zone (only valid with NSEC3).");
    opts.addOption(
        Option.builder("S").hasArg().argName("hex value").longOpt("salt").desc("Supply a salt value").build());
    opts.addOption(Option.builder("R").hasArg().argName("length").longOpt("random-salt")
        .desc("Generate a random salt of <length>").build());
    opts.addOption(Option.builder("H").hasArg().argName("count").longOpt("iterations")
        .desc("Use this many addtional iterations in NSEC3 (default 0)").build());
    opts.addOption(Option.builder().hasArg().longOpt("nsec3paramttl").argName("ttl")
        .desc("Use this TTL for the NSEC3PARAM record (default is min(soa.min, soa.ttl))").build());
    opts.addOption(Option.builder().hasArg().argName("id").longOpt("ds-digest")
        .desc("Digest algorithm to use for generated DS records").build());
  }

  protected void processOptions() {
    String[] verifyOptionKeys = { "verify_signatures", "verify" };
    String[] nsec3OptionKeys = { "use_nsec3", "nsec3" };
    String[] optOutOptionKeys = { "use_opt_out", "opt_out" };
    String[] verboseSigningOptionKeys = { "verbose_signing" };
    String[] fullySignKeysetOptionKeys = { "fully_sign_keyset", "fully_sign" };
    String[] keyDirectoryOptionKeys = { "key_directory", "keydir" };
    String[] inceptionOptionKeys = { "inception", "start" };
    String[] expireOptionKeys = { "expire" };
    String[] nsec3SaltOptionKeys = { "nsec3_salt", "salt" };
    String[] randomSaltOptionKeys = { "nsec3_random_salt_length", "nsec3_salt_length", "random_salt_length" };
    String[] nsec3IterationsOptionKeys = { "nsec3_iterations", "iterations" };
    String[] digestAlgOptionKeys = { "digest_algorithm", "digest_id" };
    String[] nsec3paramTTLOptionKeys = { "nsec3param_ttl" };
    String[] incudeNamesOptionKeys = { "include_names_file", "include_names" };

    String optstr = null;

    verifySigs = cliBooleanOption("a", verifyOptionKeys, false);
    useNsec3 = cliBooleanOption("3", nsec3OptionKeys, false);
    useOptOut = cliBooleanOption("O", optOutOptionKeys, false);
    verboseSigning = cliBooleanOption("V", verboseSigningOptionKeys, false);

    if (useOptOut && !useNsec3) {
      System.err.println("Opt-Out not supported without NSEC3 -- ignored.");
      useOptOut = false;
    }

    fullySignKeyset = cliBooleanOption("F", fullySignKeysetOptionKeys, false);

    optstr = cliOption("D", keyDirectoryOptionKeys, null);
    if (optstr != null) {
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
      System.err.println("error: missing zone file and/or key files");
      usage(true);
    }

    outputfile = cli.getOptionValue('f');

    kskFiles = cli.getOptionValues('k');

    optstr = cliOption("S", nsec3SaltOptionKeys, null);
    if (optstr != null) {
      salt = base16.fromString(optstr);
      if (salt == null && !optstr.equals("-")) {
        System.err.println("error: salt is not valid hexidecimal.");
        usage(true);
      }
    }

    optstr = cliOption("R", randomSaltOptionKeys, null);
    if (optstr != null) {
      int length = Utils.parseInt(optstr, 0);
      if (length > 0 && length <= 255) {
        salt = new byte[length];
        rand.nextBytes(salt);
      }
    }

    iterations = cliIntOption("iterations", nsec3IterationsOptionKeys, 0);
    if (iterations > 150) {
      log.warning("NSEC3 iterations value is too high for normal use: " + iterations
          + " is greater than current accepted threshold of 150");
    }

    optstr = cliOption("ds-digest", digestAlgOptionKeys, Integer.toString(digestId));
    digestId = DNSSEC.Digest.value(optstr);

    nsec3paramttl = cliIntOption("nsec3paramttl", nsec3paramTTLOptionKeys, -1);

    optstr = cliOption("I", incudeNamesOptionKeys, null);
    if (optstr != null) {
      File includeNamesFile = new File(optstr);
      try {
        includeNames = getNameList(includeNamesFile);
      } catch (IOException e) {
        System.err.println("Unable to load include-names file: " + e);
        usage(true);
      }
    }

    String[] files = cli.getArgs();

    if (files.length < 1) {
      System.err.println("error: missing zone file and/or key files");
      usage(true);
    }

    zonefile = files[0];
    if (files.length > 1) {
      keyFiles = new String[files.length - 1];
      System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
    }
  }

  /**
   * Load a list of DNS names from a file.
   *
   * @param nameListFile the path of a file containing a bare list of DNS
   *                     names.
   * @return a list of {@link org.xbill.DNS.Name} objects.
   */
  private List<Name> getNameList(File nameListFile) throws IOException {
    try (BufferedReader br = new BufferedReader(new FileReader(nameListFile))) {
      List<Name> res = new ArrayList<>();

      String line = null;
      while ((line = br.readLine()) != null) {
        try {
          Name n = Name.fromString(line);
          // force the name to be absolute.
          if (!n.isAbsolute())
            n = Name.concatenate(n, Name.root);

          res.add(n);
        } catch (TextParseException e) {
          log.severe("DNS Name parsing error:" + e);
        }
      }

      return res;
    }
  }

  /**
   * Verify the generated signatures.
   *
   * @param records  a list of {@link org.xbill.DNS.Record}s.
   * @param keypairs a list of keypairs used the sign the zone.
   * @return true if all of the signatures validated.
   */
  private boolean verifyZoneSigs(List<Record> records,
      List<DnsKeyPair> keypairs, List<DnsKeyPair> kskpairs) {
    boolean secure = true;

    DnsSecVerifier verifier = new DnsSecVerifier();

    for (DnsKeyPair pair : keypairs) {
      verifier.addTrustedKey(pair);
    }
    for (DnsKeyPair pair : kskpairs) {
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
        System.err.println("Signatures did not verify for RRset: " + rrset);
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
      if (k != null) {
        keys.add(k);
      }
    }

    return keys;
  }

  private List<DnsKeyPair> getKeys(List<Record> dnskeyrrs, File inDirectory)
      throws IOException {
    List<DnsKeyPair> res = new ArrayList<>();
    for (Record r : dnskeyrrs) {
      if (r.getType() != Type.DNSKEY)
        continue;

      // Construct a public-key-only DnsKeyPair just so we can calculate the
      // base name.
      DnsKeyPair pub = new DnsKeyPair((DNSKEYRecord) r);
      DnsKeyPair pair = BINDKeyUtils.loadKeyPair(BINDKeyUtils.keyFileBase(pub),
          inDirectory);
      if (pair != null) {
        res.add(pair);
      }
    }
    return res;
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

  private List<DnsKeyPair> findZoneKeys(File inDirectory, Name zonename)
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

  /**
   * This is an implementation of a file filter used for finding BIND 9-style
   * keyset-* files.
   */
  private static class KeysetFileFilter implements FileFilter {
    public boolean accept(File pathname) {
      if (!pathname.isFile())
        return false;
      String name = pathname.getName();
      return (name.startsWith("keyset-"));
    }
  }

  /**
   * Load keysets (which contain delegation point security info).
   *
   * @param inDirectory the directory to look for the keyset files (may be null,
   *                    in which case it defaults to looking in the current
   *                    working directory).
   * @param zonename    the name of the zone we are signing, so we can ignore
   *                    keysets that do not belong in the zone.
   * @return a list of {@link org.xbill.DNS.Record}s found in the keyset files.
   */
  private List<Record> getKeysets(File inDirectory, Name zonename)
      throws IOException {
    if (inDirectory == null) {
      inDirectory = new File(".");
    }

    // get the list of "keyset-" files.
    FileFilter filter = new KeysetFileFilter();
    File[] files = inDirectory.listFiles(filter);

    // read in all of the records
    ArrayList<Record> keysetRecords = new ArrayList<>();
    for (int i = 0; i < files.length; i++) {
      List<Record> l = ZoneUtils.readZoneFile(files[i].getAbsolutePath(), zonename);
      keysetRecords.addAll(l);
    }

    // discard records that do not belong to the zone in question.
    for (Iterator<Record> i = keysetRecords.iterator(); i.hasNext();) {
      Record r = i.next();
      if (!r.getName().subdomain(zonename)) {
        i.remove();
      }
    }

    return keysetRecords;
  }

  /**
   * Determine if the given keypairs can be used to sign the zone.
   *
   * @param zonename the zone origin.
   * @param keypairs a list of {@link DnsKeyPair} objects that will be used to
   *                 sign the zone.
   * @return true if the keypairs valid.
   */
  private static boolean keyPairsValidForZone(Name zonename, List<DnsKeyPair> keypairs) {
    if (keypairs == null)
      return true; // technically true, I guess.

    for (DnsKeyPair kp : keypairs) {
      Name keyname = kp.getDNSKEYRecord().getName();
      if (!keyname.equals(zonename)) {
        return false;
      }
    }

    return true;
  }

  public void execute() throws Exception {
    // Read in the zone
    List<Record> records = ZoneUtils.readZoneFile(zonefile, null);
    if (records == null || records.isEmpty()) {
      System.err.println("error: empty zone file");
      usage(true);
      return;
    }

    // calculate the zone name.
    Name zonename = ZoneUtils.findZoneName(records);
    if (zonename == null) {
      System.err.println("error: invalid zone file - no SOA");
      usage(true);
      return;
    }

    // Load the key pairs. Note that getKeys() always returns an ArrayList,
    // which may be empty.
    List<DnsKeyPair> keypairs = getKeys(keyFiles, 0, keyDirectory);
    List<DnsKeyPair> kskpairs = getKeys(kskFiles, 0, keyDirectory);

    // If we didn't get any keys on the command line, look at the zone apex for
    // any public keys.
    if (keypairs.isEmpty()) {
      List<Record> dnskeys = ZoneUtils.findRRs(records, zonename, Type.DNSKEY);
      keypairs = getKeys(dnskeys, keyDirectory);
    }

    // If we *still* don't have any key pairs, look for keys the key directory
    // that match
    if (keypairs.isEmpty()) {
      keypairs = findZoneKeys(keyDirectory, zonename);
    }

    // If we don't have any KSKs, but we do have more than one zone
    // signing key (presumably), presume that the zone signing keys
    // are just not differentiated and try to figure out which keys
    // are actually KSKs by looking at the SEP flag.
    if (kskpairs.isEmpty() && !keypairs.isEmpty()) {
      for (Iterator<DnsKeyPair> i = keypairs.iterator(); i.hasNext();) {
        DnsKeyPair pair = i.next();
        DNSKEYRecord kr = pair.getDNSKEYRecord();
        if ((kr.getFlags() & DNSKEYRecord.Flags.SEP_KEY) != 0) {
          kskpairs.add(pair);
          i.remove();
        }
      }
    }

    // If we have zero keypairs at all, we are stuck.
    if (keypairs.isEmpty() && kskpairs.isEmpty()) {
      System.err.println("No zone signing keys could be determined.");
      usage(true);
      return;
    }

    // If we only have one type of key (all ZSKs or all KSKs), then these are
    // "CSKs" -- Combined signing keys, so assign one set to the other.
    if (keypairs.isEmpty()) {
      keypairs = kskpairs;
    } else if (kskpairs.isEmpty()) {
      kskpairs = keypairs;
    }

    // Output what keys we are using for what
    if (keypairs == kskpairs) {
      System.out.println("CSKs: ");
      for (DnsKeyPair kp : keypairs) {
        System.out.println("  - " + kp);
      }
    } else {
      System.out.println("KSKs: ");
      for (DnsKeyPair kp : kskpairs) {
        System.out.println("  - " + kp);
      }
      System.out.println("ZSKs: ");
      for (DnsKeyPair kp : keypairs) {
        System.out.println("  - " + kp);
      }
    }

    // default the output file, if not set.
    if (outputfile == null && !zonefile.equals("-")) {
      if (zonename.isAbsolute()) {
        outputfile = zonename + "signed";
      } else {
        outputfile = zonename + ".signed";
      }
    }

    // Verify that the keys can be in the zone.
    if (!keyPairsValidForZone(zonename, keypairs)
        || !keyPairsValidForZone(zonename, kskpairs)) {
      System.err.println("error: specified keypairs are not valid for the zone.");
      usage(true);
    }

    // We force the signing keys to be in the zone by just appending
    // them to the zone here. Currently JCEDnsSecSigner.signZone
    // removes duplicate records.
    if (!kskpairs.isEmpty()) {
      for (DnsKeyPair pair : kskpairs) {
        records.add(pair.getDNSKEYRecord());
      }
    }
    if (!keypairs.isEmpty()) {
      for (DnsKeyPair pair : keypairs) {
        records.add(pair.getDNSKEYRecord());
      }
    }

    // read in the keysets, if any.
    List<Record> keysetrecs = getKeysets(keysetDirectory, zonename);
    if (keysetrecs != null) {
      records.addAll(keysetrecs);
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner(verboseSigning);

    // Sign the zone.
    List<Record> signedRecords;

    if (useNsec3) {
      signedRecords = signer.signZoneNSEC3(zonename, records, kskpairs, keypairs,
          start, expire,
          fullySignKeyset, useOptOut,
          includeNames, salt,
          iterations, digestId,
          nsec3paramttl);
    } else {
      signedRecords = signer.signZone(zonename, records, kskpairs, keypairs,
          start, expire, fullySignKeyset,
          digestId);
    }

    // write out the signed zone
    ZoneUtils.writeZoneFile(signedRecords, outputfile);
    System.out.println("zone signing complete");

    if (verifySigs) {
      log.fine("verifying generated signatures");
      boolean res = verifyZoneSigs(signedRecords, keypairs, kskpairs);

      if (res) {
        System.out.println("Generated signatures verified");
      } else {
        System.out.println("Generated signatures did not verify.");
      }
    }
  }

  public static void main(String[] args) {
    SignZone tool = new SignZone("signzone", "jdnssec-signzone [..options..] zone_file [key_file ...]");

    tool.run(args);
  }
}
