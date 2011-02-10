// $Id$
//
// Copyright (C) 2001-2003 VeriSign, Inc.
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

import java.io.PrintWriter;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.AlreadySelectedException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.cli.UnrecognizedOptionException;

import com.verisignlabs.dnssec.security.*;

/**
 * This class forms the command line implementation of a DNSSEC zone validator.
 * 
 * @author David Blacka (original)
 * @author $Author$
 * @version $Revision$
 */
public class VerifyZone
{
  private static Logger log;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  private static class CLIState
  {
    private Options opts;
    public String   zonefile    = null;
    public String[] keyfiles    = null;
    public int      startfudge  = 0;
    public int      expirefudge = 0;
    public boolean  ignoreTime  = false;

    public CLIState()
    {
      setupCLI();
    }

    /**
     * Set up the command line options.
     * 
     * @return a set of command line options.
     */
    private void setupCLI()
    {
      opts = new Options();

      // boolean options
      opts.addOption("h", "help", false, "Print this message.");
      opts.addOption("m", "multiline", false, "log DNS records using 'multiline' format");

      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("verbose");
      OptionBuilder.withArgName("level");
      OptionBuilder.withDescription("verbosity level -- 0 is silence, 3 is info, "
          + "5 is debug information, 6 is trace information. default is level 2 (warning)");
      opts.addOption(OptionBuilder.create('v'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("alias:original:mnemonic");
      OptionBuilder.withLongOpt("alg-alias");
      OptionBuilder.withDescription("Define an alias for an algorithm");
      opts.addOption(OptionBuilder.create('A'));

      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("sig-start-fudge");
      OptionBuilder.withArgName("seconds");
      OptionBuilder.withDescription("'fudge' RRSIG inception times by 'seconds' seconds.");
      opts.addOption(OptionBuilder.create('S'));

      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("sig-expire-fudge");
      OptionBuilder.withArgName("seconds");
      OptionBuilder.withDescription("'fudge' RRSIG expiration times by 'seconds' seconds.");
      opts.addOption(OptionBuilder.create('E'));

      OptionBuilder.withLongOpt("ignore-time");
      OptionBuilder.withDescription("Ignore RRSIG inception and expiration time errors.");
      opts.addOption(OptionBuilder.create());
    }

    public void parseCommandLine(String[] args)
        throws org.apache.commons.cli.ParseException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

      if (cli.hasOption('h')) usage();

      Logger rootLogger = Logger.getLogger("");
      int value = parseInt(cli.getOptionValue('v'), -1);

      switch (value)
      {
        case 0:
          rootLogger.setLevel(Level.OFF);
          break;
        case 1:
          rootLogger.setLevel(Level.SEVERE);
          break;
        case 2:
        default:
          rootLogger.setLevel(Level.WARNING);
          break;
        case 3:
          rootLogger.setLevel(Level.INFO);
          break;
        case 4:
          rootLogger.setLevel(Level.CONFIG);
        case 5:
          rootLogger.setLevel(Level.FINE);
          break;
        case 6:
          rootLogger.setLevel(Level.ALL);
          break;
      }

      // I hate java.util.logging, btw.
      for (Handler h : rootLogger.getHandlers())
      {
        h.setLevel(rootLogger.getLevel());
        h.setFormatter(new BareLogFormatter());
      }

      if (cli.hasOption('m'))
      {
        org.xbill.DNS.Options.set("multiline");
      }

      if (cli.hasOption("ignore-time"))
      {
        ignoreTime = true;
      }

      String optstr = null;
      if ((optstr = cli.getOptionValue('S')) != null)
      {
        startfudge = parseInt(optstr, 0);
      }

      if ((optstr = cli.getOptionValue('E')) != null)
      {
        expirefudge = parseInt(optstr, 0);
      }

      String[] optstrs = null;
      if ((optstrs = cli.getOptionValues('A')) != null)
      {
        for (int i = 0; i < optstrs.length; i++)
        {
          addArgAlias(optstrs[i]);
        }
      }

      String[] cl_args = cli.getArgs();

      if (cl_args.length < 1)
      {
        System.err.println("error: missing zone file");
        usage();
      }

      zonefile = cl_args[0];

      if (cl_args.length >= 2)
      {
        keyfiles = new String[cl_args.length - 1];
        System.arraycopy(cl_args, 1, keyfiles, 0, keyfiles.length);
      }
    }

    private void addArgAlias(String s)
    {
      if (s == null) return;

      DnsKeyAlgorithm algs = DnsKeyAlgorithm.getInstance();

      String[] v = s.split(":");
      if (v.length < 2) return;

      int alias = parseInt(v[0], -1);
      if (alias <= 0) return;
      int orig = parseInt(v[1], -1);
      if (orig <= 0) return;
      String mn = null;
      if (v.length > 2) mn = v[2];

      algs.addAlias(alias, mn, orig);
    }

    /** Print out the usage and help statements, then quit. */
    public void usage()
    {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out, 75, "jdnssec-verifyzone [..options..] zonefile "
                      + "[keyfile [keyfile...]]", null, opts,
                  HelpFormatter.DEFAULT_LEFT_PAD,
                  HelpFormatter.DEFAULT_DESC_PAD, null);

      out.flush();
      System.exit(64);

    }

    /**
     * This is just a convenience method for parsing integers from strings.
     * 
     * @param s
     *          the string to parse.
     * @param def
     *          the default value, if the string doesn't parse.
     * @return the parsed integer, or the default.
     */
    private static int parseInt(String s, int def)
    {
      try
      {
        int v = Integer.parseInt(s);
        return v;
      }
      catch (NumberFormatException e)
      {
        return def;
      }
    }

  }

  public static void execute(CLIState state) throws Exception
  {
    ZoneVerifier zoneverifier = new ZoneVerifier();
    zoneverifier.getVerifier().setStartFudge(state.startfudge);
    zoneverifier.getVerifier().setExpireFudge(state.expirefudge);
    zoneverifier.getVerifier().setIgnoreTime(state.ignoreTime);

    List records = ZoneUtils.readZoneFile(state.zonefile, null);

    log.fine("verifying zone...");
    int errors = zoneverifier.verifyZone(records);
    log.fine("completed verification process.");

    if (errors > 0)
    {
      System.out.println("zone did not verify.");
    }
    else
    {
      System.out.println("zone verified.");
    }

    System.exit(0);
  }

  public static void main(String[] args)
  {
    CLIState state = new CLIState();

    try
    {
      state.parseCommandLine(args);
    }
    catch (UnrecognizedOptionException e)
    {
      System.err.println("error: unknown option encountered: " + e.getMessage());
      state.usage();
    }
    catch (AlreadySelectedException e)
    {
      System.err.println("error: mutually exclusive options have "
          + "been selected:\n     " + e.getMessage());
      state.usage();
    }
    catch (Exception e)
    {
      System.err.println("error: unknown command line parsing exception:");
      e.printStackTrace();
      state.usage();
    }

    log = Logger.getLogger(VerifyZone.class.toString());

    try
    {
      execute(state);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
}
