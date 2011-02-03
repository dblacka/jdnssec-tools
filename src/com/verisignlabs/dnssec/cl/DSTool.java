// $Id: KeyGen.java 1954 2005-08-14 17:05:50Z davidb $
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

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.*;
import org.xbill.DNS.DLVRecord;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Record;

import com.verisignlabs.dnssec.security.*;

/**
 * This class forms the command line implementation of a DNSSEC DS/DLV generator
 * 
 * @author David Blacka (original)
 * @author $Author: davidb $
 * @version $Revision: 1954 $
 */
public class DSTool
{
  private static Logger log;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  private static class CLIState
  {
    private Options opts;
    public boolean  createDLV  = false;
    public String   outputfile = null;
    public String   keyname    = null;
    public int      digest_id  = DSRecord.SHA1_DIGEST_ID;

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

      OptionBuilder.withLongOpt("dlv");
      OptionBuilder.withDescription("Generate a DLV record instead.");
      opts.addOption(OptionBuilder.create());

      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("verbose");
      OptionBuilder.withArgName("level");
      OptionBuilder.withDescription("verbosity level -- 0 is silence, 5 is debug information, 6 is trace information.\n"
          + "default is level 5.");
      // Argument options
      opts.addOption(OptionBuilder.create('v'));

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("digest");
      OptionBuilder.withArgName("id");
      OptionBuilder.withDescription("The Digest ID to use (numerically): either 1 for SHA1 or 2 for SHA256");
      opts.addOption(OptionBuilder.create('d'));
    }

    public void parseCommandLine(String[] args)
        throws org.apache.commons.cli.ParseException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

      if (cli.hasOption('h')) usage();

      Logger rootLogger = Logger.getLogger("");
      if (cli.hasOption('v'))
      {
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
      }
      // I hate java.util.logging, btw.
      for (Handler h : rootLogger.getHandlers())
      {
        h.setLevel(rootLogger.getLevel());
        h.setFormatter(new BareLogFormatter());
      }

      outputfile = cli.getOptionValue('f');
      createDLV = cli.hasOption("dlv");
      String optstr = cli.getOptionValue('d');
      if (optstr != null) digest_id = parseInt(optstr, digest_id);

      String[] cl_args = cli.getArgs();

      if (cl_args.length < 1)
      {
        System.err.println("error: missing key file ");
        usage();
      }

      keyname = cl_args[0];
    }

    /** Print out the usage and help statements, then quit. */
    private void usage()
    {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out, 75, "jdnssec-dstool [..options..] keyfile", null, opts,
                  HelpFormatter.DEFAULT_LEFT_PAD,
                  HelpFormatter.DEFAULT_DESC_PAD, null);

      out.flush();
      System.exit(64);
    }
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

  public static void execute(CLIState state) throws Exception
  {

    DnsKeyPair key = BINDKeyUtils.loadKey(state.keyname, null);
    DNSKEYRecord dnskey = key.getDNSKEYRecord();

    if ((dnskey.getFlags() & DNSKEYRecord.Flags.SEP_KEY) == 0)
    {
      log.warning("DNSKEY is not an SEP-flagged key.");
    }

    DSRecord ds = SignUtils.calculateDSRecord(dnskey, state.digest_id,
                                              dnskey.getTTL());
    Record res = ds;

    if (state.createDLV)
    {
      log.fine("creating DLV.");
      DLVRecord dlv = new DLVRecord(ds.getName(), ds.getDClass(), ds.getTTL(),
                                    ds.getFootprint(), ds.getAlgorithm(),
                                    ds.getDigestID(), ds.getDigest());
      res = dlv;
    }

    if (state.outputfile != null)
    {
      PrintWriter out = new PrintWriter(new FileWriter(state.outputfile));
      out.println(res);
      out.close();
    }
    else
    {
      System.out.println(res);
    }
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
      System.err.println("error: mutually exclusive options have been selected:\n     "
          + e.getMessage());
      state.usage();
    }
    catch (Exception e)
    {
      System.err.println("error: unknown command line parsing exception:");
      e.printStackTrace();
      state.usage();
    }

    log = Logger.getLogger(DSTool.class.toString());

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
