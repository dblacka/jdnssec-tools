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

import java.io.FileWriter;
import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.xbill.DNS.CDSRecord;
import org.xbill.DNS.DLVRecord;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Record;

import com.verisignlabs.dnssec.security.BINDKeyUtils;
import com.verisignlabs.dnssec.security.DnsKeyPair;
import com.verisignlabs.dnssec.security.SignUtils;

/**
 * This class forms the command line implementation of a DNSSEC DS/DLV generator
 * 
 * @author David Blacka
 */
public class DSTool extends CLBase {
  private CLIState state;

  /** There are several records that are based on DS. */
  protected enum dsType {
    DS, CDS, DLV;
  }

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */

  protected static class CLIState extends CLIStateBase {
    public dsType createType = dsType.DS;
    public String outputfile = null;
    public String keyname = null;
    public int digestId = DNSSEC.Digest.SHA256;

    public CLIState() {
      super("jdnssec-dstool [..options..] keyfile");
    }

    /**
     * Set up the command line options.
     * 
     * @return a set of command line options.
     */
    @Override
    protected void setupOptions(Options opts) {
      opts.addOption(Option.builder("D").longOpt("dlv").desc("Generate a DLV record instead.").build());
      opts.addOption(Option.builder("C").longOpt("cds").desc("Generate a CDS record instead").build());
      opts.addOption(
          Option.builder("d").hasArg().argName("id").longOpt("digest").desc("The digest algorithm to use").build());
      opts.addOption(Option.builder("f").hasArg().argName("file").longOpt("output").desc("output to file").build());
    }

    @Override
    protected void processOptions(CommandLine cli)
        throws org.apache.commons.cli.ParseException {
      outputfile = cli.getOptionValue('f');
      if (cli.hasOption("dlv")) {
        createType = dsType.DLV;
      } else if (cli.hasOption("cds")) {
        createType = dsType.CDS;
      }
      String optstr = cli.getOptionValue('d');
      if (optstr != null)
        digestId = DNSSEC.Digest.value(optstr);

      String[] args = cli.getArgs();

      if (args.length < 1) {
        System.err.println("error: missing key file ");
        usage();
      }

      keyname = args[0];
    }

  }

  public void execute() throws Exception {
    DnsKeyPair key = BINDKeyUtils.loadKey(state.keyname, null);
    DNSKEYRecord dnskey = key.getDNSKEYRecord();

    if ((dnskey.getFlags() & DNSKEYRecord.Flags.SEP_KEY) == 0) {
      log.warning("DNSKEY is not an SEP-flagged key.");
    }

    DSRecord ds = SignUtils.calculateDSRecord(dnskey, state.digestId, dnskey.getTTL());
    Record res = ds;

    if (state.createType == dsType.DLV) {
      log.fine("creating DLV.");
      DLVRecord dlv = new DLVRecord(ds.getName(), ds.getDClass(), ds.getTTL(), ds.getFootprint(), ds.getAlgorithm(),
          ds.getDigestID(), ds.getDigest());
      res = dlv;
    } else if (state.createType == dsType.CDS) {
      log.fine("creating CDS.");
      CDSRecord cds = new CDSRecord(ds.getName(), ds.getDClass(), ds.getTTL(), ds.getFootprint(), ds.getAlgorithm(),
          ds.getDClass(), ds.getDigest());
      res = cds;
    }

    if (state.outputfile != null && !state.outputfile.equals("-")) {
      try (PrintWriter out = new PrintWriter(new FileWriter(state.outputfile))) {
        out.println(res);
      }
    } else {
      System.out.println(res);
    }
  }

  public static void main(String[] args) {
    DSTool tool = new DSTool();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }
}
