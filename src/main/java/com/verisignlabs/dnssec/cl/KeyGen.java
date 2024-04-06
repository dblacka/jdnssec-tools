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
import org.apache.commons.cli.Options;
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
  private CLIState state;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  protected static class CLIState extends CLIStateBase {
    public int algorithm = 13;
    public int keylength = 2048;
    public boolean useLargeE = true;
    public String outputfile = null;
    public File keydir = null;
    public boolean zoneKey = true;
    public boolean kskFlag = false;
    public String owner = null;
    public long ttl = 86400;
    public int givenKeyTag = -1;

    public CLIState() {
      super("keygen", "jdnssec-keygen [..options..] name");
    }

    /**
     * Set up the command line options.
     */
    @Override
    protected void setupOptions(Options opts) {
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

    @Override
    protected void processOptions() throws org.apache.commons.cli.ParseException {
      String[] useLargeEOptionKeys = { "use_large_exponent", "use_large_e" };
      String[] keyDirectoryOptionKeys = { "key_directory", "keydir" };
      String[] algorithmOptionKeys = { "algorithm", "alg "};
      String[] keyLengthOptionKeys = { "key_length", "keylen" };
      String[] ttlOptionKeys = { "ttl" };

      if (cli.hasOption('k')) {
        kskFlag = true;
      }
      String optstr = cliOption("E", useLargeEOptionKeys, null);
      if (optstr != null) {
        useLargeE = Boolean.parseBoolean(optstr);
      }

      outputfile = cli.getOptionValue('f');

      String keydirName = cliOption("d", keyDirectoryOptionKeys, null);
      if (keydirName != null) {
        keydir = new File(keydirName);
      }

      String algString = cliOption("a", algorithmOptionKeys, Integer.toString(algorithm));
      algorithm = CLIState.parseAlg(algString);
      if (algorithm < 0) {
        System.err.println("DNSSEC algorithm " + algString + " is not supported");
        usage();
      }

      keylength = cliIntOption("b", keyLengthOptionKeys, keylength);
      ttl = cliLongOption("ttl", ttlOptionKeys, ttl);
      givenKeyTag = parseInt(cli.getOptionValue("with-tag"), -1);

      String[] args = cli.getArgs();

      if (args.length < 1) {
        System.err.println("error: missing key owner name");
        usage();
      }

      owner = args[0];

      staticLog.fine("keygen options => algorithm: " + algorithm + " keylength: " + keylength +
          " useLargeE: " + useLargeE + " kskFlag: " + kskFlag + " ttl: " + ttl + " givenKeyTag: " + givenKeyTag);
    }

    private static int parseAlg(String s) {
      DnsKeyAlgorithm algs = DnsKeyAlgorithm.getInstance();

      int alg = parseInt(s, -1);
      if (alg > 0) {
        if (algs.supportedAlgorithm(alg))
          return alg;
        return -1;
      }

      return algs.stringToAlgorithm(s);
    }
  }

  public void execute() throws Exception {
    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    // Minor hack to make the owner name absolute.
    if (!state.owner.endsWith(".")) {
      state.owner = state.owner + ".";
    }

    Name ownerName = Name.fromString(state.owner);

    // Calculate our flags
    int flags = 0;
    if (state.zoneKey) {
      flags |= DNSKEYRecord.Flags.ZONE_KEY;
    }
    if (state.kskFlag) {
      flags |= DNSKEYRecord.Flags.SEP_KEY;
    }
    log.fine("create key pair with (name = " + ownerName + ", ttl = " + state.ttl
        + ", alg = " + state.algorithm + ", flags = " + flags + ", length = "
        + state.keylength + ")");

    DnsKeyPair pair = signer.generateKey(ownerName, state.ttl, DClass.IN,
        state.algorithm, flags, state.keylength,
        state.useLargeE);

    // If we were asked to generate a duplicate keytag, keep trying until we get one
    // This can take a long time, depending on our key generation speed
    while (state.givenKeyTag >= 0 && pair.getDNSKEYFootprint() != state.givenKeyTag) {
      pair = signer.generateKey(ownerName, state.ttl, DClass.IN, state.algorithm, flags, state.keylength,
          state.useLargeE);
    }

    if (state.outputfile != null) {
      BINDKeyUtils.writeKeyFiles(state.outputfile, pair, state.keydir);
    } else {
      BINDKeyUtils.writeKeyFiles(pair, state.keydir);
      System.out.println(BINDKeyUtils.keyFileBase(pair));
    }
  }

  public static void main(String[] args) {
    KeyGen tool = new KeyGen();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }
}
