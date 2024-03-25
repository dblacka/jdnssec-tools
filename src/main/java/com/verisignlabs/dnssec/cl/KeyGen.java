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

import org.apache.commons.cli.CommandLine;
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
    public int algorithm = 8;
    public int keylength = 1024;
    public boolean useLargeE = true;
    public String outputfile = null;
    public File keydir = null;
    public boolean zoneKey = true;
    public boolean kskFlag = false;
    public String owner = null;
    public long ttl = 86400;
    public int givenKeyTag = -1;

    public CLIState() {
      super("jdnssec-keygen [..options..] name");
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
          .desc(algStringSet + " | alias, RSASHA256 is default.").build());

      opts.addOption(Option.builder("b").hasArg().argName("size").desc(
          "key size, in bits (default 1024). RSA: [512..4096], DSA: [512..1024], DH: [128..4096], ECDSA: ignored, EdDSA: ignored")
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
    protected void processOptions(CommandLine cli)
        throws org.apache.commons.cli.ParseException {
      String optstr = null;
      String[] optstrs = null;

      if (cli.hasOption('k'))
        kskFlag = true;
      if (cli.hasOption('e'))
        useLargeE = true;

      outputfile = cli.getOptionValue('f');

      if ((optstr = cli.getOptionValue('d')) != null) {
        keydir = new File(optstr);
      }

      if ((optstr = cli.getOptionValue('n')) != null && !optstr.equalsIgnoreCase("ZONE")) {
        zoneKey = false;
      }

      if ((optstrs = cli.getOptionValues('A')) != null) {
        for (int i = 0; i < optstrs.length; i++) {
          addArgAlias(optstrs[i]);
        }
      }

      if ((optstr = cli.getOptionValue('a')) != null) {
        algorithm = CLIState.parseAlg(optstr);
        if (algorithm < 0) {
          System.err.println("DNSSEC algorithm " + optstr + " is not supported");
          usage();
        }
      }

      if ((optstr = cli.getOptionValue('b')) != null) {
        keylength = parseInt(optstr, 1024);
      }

      if ((optstr = cli.getOptionValue("ttl")) != null) {
        ttl = parseInt(optstr, 86400);
      }

      if ((optstr = cli.getOptionValue("with-tag")) != null) {
        givenKeyTag = parseInt(optstr, -1);
      }

      String[] args = cli.getArgs();

      if (args.length < 1) {
        System.err.println("error: missing key owner name");
        usage();
      }

      owner = args[0];
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
