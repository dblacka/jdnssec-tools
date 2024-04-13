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
import java.io.IOException;
import java.io.PrintWriter;

import org.apache.commons.cli.Option;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Record;

import com.verisignlabs.dnssec.security.BINDKeyUtils;
import com.verisignlabs.dnssec.security.DSAlgorithm;
import com.verisignlabs.dnssec.security.DnsKeyPair;

/**
 * This class forms the command line implementation of a DNSSEC DS/DLV generator
 * 
 * @author David Blacka
 */
public class DSTool extends CLBase {
  private dsType createType = dsType.DS;
  private String outputfile = null;
  private String[] keynames = null;
  private int digestId = DNSSEC.Digest.SHA256;
  private long dsTTL = -1;

  public DSTool(String name, String usageStr) {
    super(name, usageStr);
  }

  /** There are several records that are based on DS. */
  protected enum dsType {
    DS, CDS, DLV;
  }

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */

  /**
   * Set up the command line options.
   * 
   * @return a set of command line options.
   */
  protected void setupOptions() {
    opts.addOption(Option.builder("D").longOpt("dlv").desc("Generate a DLV record instead.").build());
    opts.addOption(Option.builder("C").longOpt("cds").desc("Generate a CDS record instead").build());
    String[] algStrings = DSAlgorithm.getInstance().supportedAlgorithmMnemonics();
    String algStringSet = String.join(" | ", algStrings);
    opts.addOption(
        Option.builder("d").hasArg().argName("id").longOpt("digest").desc(algStringSet + ": default is SHA256")
            .build());
    opts.addOption(Option.builder("f").hasArg().argName("file").longOpt("output").desc("output to file").build());
    opts.addOption(Option.builder("T").longOpt("ttl").hasArg().desc("TTL to use for generated DS/CDS record").build());
  }

  protected void processOptions() {
    String[] digestAlgOptionKeys = { "digest_algorithm", "digest_id" };
    String[] dsTTLOptionKeys = { "ds_ttl", "ttl" };

    outputfile = cli.getOptionValue('f');
    if (cli.hasOption("dlv")) {
      createType = dsType.DLV;
    } else if (cli.hasOption("cds")) {
      createType = dsType.CDS;
    }
    String digestValue = cliOption("d", digestAlgOptionKeys, Integer.toString(digestId));
    digestId = DNSSEC.Digest.value(digestValue);

    dsTTL = cliLongOption("ttl", dsTTLOptionKeys, dsTTL);

    String[] args = cli.getArgs();

    if (args.length < 1) {
      fail("missing key file");
    }

    keynames = args;
  }

  public void createDS(String keyname) throws IOException {
    DSAlgorithm dsAlgorithm = DSAlgorithm.getInstance();
    DnsKeyPair key = BINDKeyUtils.loadKey(keyname, null);
    DNSKEYRecord dnskey = key.getDNSKEYRecord();

    if ((dnskey.getFlags() & DNSKEYRecord.Flags.SEP_KEY) == 0) {
      log.warning("DNSKEY " + keyname + " is not an SEP-flagged key.");
    }

    long ttl = dsTTL < 0 ? dnskey.getTTL() : dsTTL;
    DSRecord ds = dsAlgorithm.calculateDSRecord(dnskey, digestId, ttl);
    Record res;

    switch (createType) {
      case DLV:
        log.fine("creating DLV.");
        res = dsAlgorithm.dsToDLV(ds);
        break;
      case CDS:
        log.fine("creating CDS.");
        res = dsAlgorithm.dstoCDS(ds);
        break;
      default:
        res = ds;
        break;
    }

    if (outputfile != null && !outputfile.equals("-")) {
      try (PrintWriter out = new PrintWriter(new FileWriter(outputfile))) {
        out.println(res);
      }
    } else {
      System.out.println(res);
    }
  }

  public void execute() throws Exception {
    for (String keyname : keynames) {
      createDS(keyname);
    }
  }

  public static void main(String[] args) {
    DSTool tool = new DSTool("dstool", "jdnssec-dstool [..options..] keyfile [keyfile..]");

    tool.run(args);
  }
}
