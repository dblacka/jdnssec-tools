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

import org.apache.commons.cli.Option;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.Name;

import com.verisignlabs.dnssec.security.BINDKeyUtils;
import com.verisignlabs.dnssec.security.DnsKeyAlgorithm;
import com.verisignlabs.dnssec.security.DnsKeyPair;
import com.verisignlabs.dnssec.security.JCEDnsSecSigner;

/**
 * This class forms the command line implementation of a DNSSEC key generator
 *
 * @author David Blacka
 */
public class KeyGen extends CLBase {
  private int algorithm = 13;
  private int keylength = 2048;
  private boolean useLargeE = true;
  private String outputfile = null;
  private File keydir = null;
  private boolean zoneKey = true;
  private boolean kskFlag = false;
  private String owner = null;
  private long ttl = 86400;
  private int givenKeyTag = -1;

  public KeyGen(String name, String usageStr) {
    super(name, usageStr);
  }

  /**
   * Set up the command line options.
   */
  protected void setupOptions() {
    // boolean options
    opts.addOption("k", "kskflag", false,
        "Key is a key-signing-key (sets the SEP flag).");
    opts.addOption("e", "large-exponent", false, "Use large RSA exponent (default)");
    opts.addOption("E", "small-exponent", false, "Use small RSA exponent");

    // Argument options
    opts.addOption(
        Option.builder("n").longOpt("nametype").hasArg().argName("type").desc("ZONE | OTHER (default ZONE)").build());

    String[] algStrings = DnsKeyAlgorithm.getInstance().supportedAlgMnemonics();
    String algStringSet = String.join(" | ", algStrings);
    opts.addOption(Option.builder("a").hasArg().argName("algorithm")
        .desc(algStringSet + " | alias, ECDSAP256SHA256 is default.").build());

    opts.addOption(Option.builder("b").hasArg().argName("size").desc(
        "key size, in bits (default 2048). RSA: [512..4096], DSA: [512..1024], DH: [128..4096], ECDSA: ignored, EdDSA: ignored")
        .build());
    opts.addOption(Option.builder("f").hasArg().argName("file").longOpt("output-file")
        .desc("base filename from the public/private key files").build());
    opts.addOption(Option.builder("d").hasArg().argName("dir").longOpt("keydir")
        .desc("generated keyfiles are written to this directory").build());
    opts.addOption(Option.builder("T").hasArg().argName("ttl").longOpt("ttl")
        .desc("use this TTL for the generated DNSKEY records (default: 86400").build());
    opts.addOption(Option.builder().hasArg().argName("tag").longOpt("with-tag")
        .desc("Generate keys until tag is the given value.").build());

  }

  protected void processOptions() {
    String[] useLargeEOptionKeys = { "use_large_exponent", "use_large_e" };
    String[] keyDirectoryOptionKeys = { "key_directory", "keydir" };
    String[] algorithmOptionKeys = { "algorithm", "alg " };
    String[] keyLengthOptionKeys = { "key_length", "keylen" };
    String[] ttlOptionKeys = { "dnskey_ttl", "ttl" };

    if (cli.hasOption('k')) {
      kskFlag = true;
    }
    useLargeE = cli.hasOption('e'); // explicit command line option for the large exponent
    useLargeE = !cli.hasOption('E');  // explicit command line option for the small exponent
    String optstr = cliOption("e", useLargeEOptionKeys, Boolean.toString(useLargeE)); // get any config file properties
    if (optstr != null) {
      useLargeE = Boolean.parseBoolean(optstr);
    }

    outputfile = cli.getOptionValue('f');

    String keydirName = cliOption("d", keyDirectoryOptionKeys, null);
    if (keydirName != null) {
      keydir = new File(keydirName);
    }

    String algString = cliOption("a", algorithmOptionKeys, Integer.toString(algorithm));
    algorithm = Utils.parseAlg(algString);
    if (algorithm < 0) {
      fail("DNSSEC algorithm " + algString + " is not supported");
    }

    keylength = cliIntOption("b", keyLengthOptionKeys, keylength);
    ttl = cliLongOption("ttl", ttlOptionKeys, ttl);
    givenKeyTag = Utils.parseInt(cli.getOptionValue("with-tag"), -1);

    String[] args = cli.getArgs();

    if (args.length < 1) {
      fail("missing key owner name");
    }

    owner = args[0];

    log.fine("keygen options => algorithm: " + algorithm + ", keylength: " + keylength +
        ", useLargeE: " + useLargeE + ", kskFlag: " + kskFlag + ", ttl: " + ttl + ", givenKeyTag: " + givenKeyTag);
  }

  public void execute() throws Exception {
    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    // Minor hack to make the owner name absolute.
    if (!owner.endsWith(".")) {
      owner = owner + ".";
    }

    Name ownerName = Name.fromString(owner);

    // Calculate our flags
    int flags = 0;
    if (zoneKey) {
      flags |= DNSKEYRecord.Flags.ZONE_KEY;
    }
    if (kskFlag) {
      flags |= DNSKEYRecord.Flags.SEP_KEY;
    }
    log.fine("create key pair with (name = " + ownerName + ", ttl = " + ttl
        + ", alg = " + algorithm + ", flags = " + flags + ", length = "
        + keylength + ")");

    DnsKeyPair pair = signer.generateKey(ownerName, ttl, DClass.IN,
        algorithm, flags, keylength,
        useLargeE);

    // If we were asked to generate a duplicate keytag, keep trying until we get one
    // This can take a long time, depending on our key generation speed
    while (givenKeyTag >= 0 && pair.getDNSKEYFootprint() != givenKeyTag) {
      pair = signer.generateKey(ownerName, ttl, DClass.IN, algorithm, flags, keylength,
          useLargeE);
    }

    if (outputfile != null) {
      BINDKeyUtils.writeKeyFiles(outputfile, pair, keydir);
    } else {
      BINDKeyUtils.writeKeyFiles(pair, keydir);
      System.out.println(BINDKeyUtils.keyFileBase(pair));
    }
  }

  public static void main(String[] args) {
    KeyGen tool = new KeyGen("keygen", "jdnssec-keygen [..options..] zonename");

    tool.run(args);
  }
}
