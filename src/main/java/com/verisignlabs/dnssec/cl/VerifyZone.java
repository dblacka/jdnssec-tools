// Copyright (C) 2011, 2022 VeriSign, Inc.
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

import java.time.Instant;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;
import org.xbill.DNS.Record;

import com.verisignlabs.dnssec.security.ZoneUtils;
import com.verisignlabs.dnssec.security.ZoneVerifier;

/**
 * This class forms the command line implementation of a DNSSEC zone validator.
 * 
 * @author David Blacka
 */
public class VerifyZone extends CLBase {

  private CLIState state;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  protected static class CLIState extends CLIStateBase {
    public String zonefile = null;
    public String[] keyfiles = null;
    public int startfudge = 0;
    public int expirefudge = 0;
    public boolean ignoreTime = false;
    public boolean ignoreDups = false;
    public Instant currentTime = null;

    public CLIState() {
      super("jdnssec-verifyzone [..options..] zonefile");
    }

    @Override
    protected void setupOptions(Options opts) {
      opts.addOption(Option.builder("S").hasArg().argName("seconds").longOpt("sig-start-fudge")
          .desc("'fudge' RRSIG inception ties by 'seconds'").build());
      opts.addOption(Option.builder("E").hasArg().argName("seconds").longOpt("sig-expire-fudge")
          .desc("'fudge' RRSIG expiration times by 'seconds'").build());
      opts.addOption(Option.builder("t").hasArg().argName("time").longOpt("use-time")
          .desc("Use 'time' as the time for verification purposes.").build());

      opts.addOption(
          Option.builder().longOpt("ignore-time").desc("Ignore RRSIG inception and expiration time errors.").build());
      opts.addOption(Option.builder().longOpt("ignore-duplicate-rrs").desc("Ignore duplicate record errors.").build());
    }

    @Override
    protected void processOptions(CommandLine cli) {
      if (cli.hasOption("ignore-time")) {
        ignoreTime = true;
      }

      if (cli.hasOption("ignore-duplicate-rrs")) {
        ignoreDups = true;
      }

      String optstr = null;
      if ((optstr = cli.getOptionValue('S')) != null) {
        startfudge = parseInt(optstr, 0);
      }

      if ((optstr = cli.getOptionValue('E')) != null) {
        expirefudge = parseInt(optstr, 0);
      }

      if ((optstr = cli.getOptionValue('t')) != null) {
        try {
          currentTime = convertDuration(null, optstr);
        } catch (ParseException e) {
          System.err.println("error: could not parse timespec");
          usage();
        }
      }

      String[] optstrs = null;
      if ((optstrs = cli.getOptionValues('A')) != null) {
        for (int i = 0; i < optstrs.length; i++) {
          addArgAlias(optstrs[i]);
        }
      }

      String[] args = cli.getArgs();

      if (args.length < 1) {
        System.err.println("error: missing zone file");
        usage();
      }

      zonefile = args[0];

      if (args.length >= 2) {
        keyfiles = new String[args.length - 1];
        System.arraycopy(args, 1, keyfiles, 0, keyfiles.length);
      }
    }
  }

  public void execute() throws Exception {
    ZoneVerifier zoneverifier = new ZoneVerifier();
    zoneverifier.getVerifier().setStartFudge(state.startfudge);
    zoneverifier.getVerifier().setExpireFudge(state.expirefudge);
    zoneverifier.getVerifier().setIgnoreTime(state.ignoreTime);
    zoneverifier.getVerifier().setCurrentTime(state.currentTime);
    zoneverifier.setIgnoreDuplicateRRs(state.ignoreDups);

    List<Record> records = ZoneUtils.readZoneFile(state.zonefile, null);

    log.fine("verifying zone...");
    int errors = zoneverifier.verifyZone(records);
    log.fine("completed verification process.");

    if (errors > 0) {
      System.out.println("zone did not verify.");
      System.exit(1);
    } else {
      System.out.println("zone verified.");
      System.exit(0);
    }
  }

  public static void main(String[] args) {
    VerifyZone tool = new VerifyZone();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }
}
