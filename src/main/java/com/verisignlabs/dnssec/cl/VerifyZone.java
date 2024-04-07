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

import org.apache.commons.cli.Option;
import org.xbill.DNS.Record;

import com.verisignlabs.dnssec.security.ZoneUtils;
import com.verisignlabs.dnssec.security.ZoneVerifier;

/**
 * This class forms the command line implementation of a DNSSEC zone validator.
 * 
 * @author David Blacka
 */
public class VerifyZone extends CLBase {
  private String zonefile = null;
  private String[] keyfiles = null;
  private int startfudge = 0;
  private int expirefudge = 0;
  private boolean ignoreTime = false;
  private boolean ignoreDups = false;
  private Instant currentTime = null;

  public VerifyZone(String name, String usageStr) {
    super(name, usageStr);
  }

  protected void setupOptions() {
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

  protected void processOptions() {
    String[] ignoreTimeOptionKeys = { "ignore_time" };
    String[] ignoreDuplicateOptionKeys = { "ingore_duplicate_rrs", "ignore_duplicates" };
    String[] startFudgeOptionKeys = { "start_fudge" };
    String[] expireFudgeOptionKeys = { "expire_fudge" };
    String[] currentTimeOptionKeys = { "current_time" };

    ignoreTime = cliBooleanOption("ignore-time", ignoreTimeOptionKeys, false);
    ignoreDups = cliBooleanOption("ignore-duplicate-rrs", ignoreDuplicateOptionKeys, false);
    startfudge = cliIntOption("S", startFudgeOptionKeys, 0);
    expirefudge = cliIntOption("E", expireFudgeOptionKeys, 0);

    String optstr = cliOption("t", currentTimeOptionKeys, null);
    if (optstr != null) {
      try {
        currentTime = Utils.convertDuration(null, optstr);
      } catch (java.text.ParseException e) {
        System.err.println("error: could not parse timespec");
        usage(true);
      }
    }

    String[] args = cli.getArgs();

    if (args.length < 1) {
      System.err.println("error: missing zone file");
      usage(true);
    }

    zonefile = args[0];

    if (args.length >= 2) {
      keyfiles = new String[args.length - 1];
      System.arraycopy(args, 1, keyfiles, 0, keyfiles.length);
    }
  }

  public void execute() throws Exception {
    ZoneVerifier zoneverifier = new ZoneVerifier();
    zoneverifier.getVerifier().setStartFudge(startfudge);
    zoneverifier.getVerifier().setExpireFudge(expirefudge);
    zoneverifier.getVerifier().setIgnoreTime(ignoreTime);
    zoneverifier.getVerifier().setCurrentTime(currentTime);
    zoneverifier.setIgnoreDuplicateRRs(ignoreDups);

    List<Record> records = ZoneUtils.readZoneFile(zonefile, null);

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
    VerifyZone tool = new VerifyZone("verifyzone", "jdnssec-verifyzone [..options..] zonefile");

    tool.run(args);
  }
}
