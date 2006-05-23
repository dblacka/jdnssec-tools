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

import java.io.File;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.*;
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
 * @author David Blacka (original)
 * @author $Author$
 * @version $Revision$
 */
public class KeyGen
{
  private static Logger log;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  private static class CLIState
  {
    private Options opts;
    public int      algorithm  = 5;
    public int      keylength  = 1024;
    public String   outputfile = null;
    public File     keydir     = null;
    public boolean  zoneKey    = true;
    public boolean  kskFlag    = false;
    public String   owner      = null;
    public long     ttl        = 86400;

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
      opts.addOption("k",
          "kskflag",
          false,
          "Key is a key-signing-key (sets the SEP flag).");

      // Argument options
      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("nametype");
      OptionBuilder.withArgName("type");
      OptionBuilder.withDescription("ZONE | OTHER (default ZONE)");
      opts.addOption(OptionBuilder.create('n'));

      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("verbose");
      OptionBuilder.withArgName("level");
      OptionBuilder.withDescription("verbosity level -- 0 is silence, "
          + "5 is debug information, " + "6 is trace information.\n"
          + "default is level 5.");
      opts.addOption(OptionBuilder.create('v'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("algorithm");
      OptionBuilder
          .withDescription("RSA | RSASHA1 | RSAMD5 | DH | DSA | alias, "
              + "RSASHA1 is default.");
      opts.addOption(OptionBuilder.create('a'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("size");
      OptionBuilder.withDescription("key size, in bits. (default = 1024)\n"
          + "RSA|RSASHA1|RSAMD5: [512..4096]\n"
          + "DSA:                [512..1024]\n"
          + "DH:                 [128..4096]");
      opts.addOption(OptionBuilder.create('b'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("file");
      OptionBuilder.withLongOpt("output-file");
      OptionBuilder
          .withDescription("base filename for the public/private key files");
      opts.addOption(OptionBuilder.create('f'));

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("keydir");
      OptionBuilder.withArgName("dir");
      OptionBuilder.withDescription("place generated key files in this "
          + "directory");
      opts.addOption(OptionBuilder.create('d'));

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("alg-alias");
      OptionBuilder.withArgName("alias:original:mnemonic");
      OptionBuilder.withDescription("define an alias for an algorithm");
      opts.addOption(OptionBuilder.create('A'));
    }

    public void parseCommandLine(String[] args)
        throws org.apache.commons.cli.ParseException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

      String optstr = null;

      if (cli.hasOption('h')) usage();

      if (cli.hasOption('v'))
      {
        int value = parseInt(cli.getOptionValue('v'), 5);
        Logger rootLogger = Logger.getLogger("");
        switch (value)
        {
          case 0 :
            rootLogger.setLevel(Level.OFF);
            break;
          case 5 :
          default :
            rootLogger.setLevel(Level.FINE);
            break;
          case 6 :
            rootLogger.setLevel(Level.ALL);
            break;
        }
      }

      if (cli.hasOption('k')) kskFlag = true;

      outputfile = cli.getOptionValue('f');

      if ((optstr = cli.getOptionValue('d')) != null)
      {
        keydir = new File(optstr);
      }

      if ((optstr = cli.getOptionValue('n')) != null)
      {
        if (!optstr.equalsIgnoreCase("ZONE"))
        {
          zoneKey = false;
        }
      }

      String[] optstrs;
      if ((optstrs = cli.getOptionValues('A')) != null)
      {
        for (int i = 0; i < optstrs.length; i++)
        {
          addArgAlias(optstrs[i]);
        }
      }

      if ((optstr = cli.getOptionValue('a')) != null)
      {
        algorithm = parseAlg(optstr);
      }

      if ((optstr = cli.getOptionValue('b')) != null)
      {
        keylength = parseInt(optstr, 1024);
      }

      if ((optstr = cli.getOptionValue("ttl")) != null)
      {
        ttl = parseInt(optstr, 86400);
      }

      String[] cl_args = cli.getArgs();

      if (cl_args.length < 1)
      {
        System.err.println("error: missing key owner name");
        usage();
      }

      owner = cl_args[0];
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
    private void usage()
    {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out,
          75,
          "jdnssec-keygen [..options..] name",
          null,
          opts,
          HelpFormatter.DEFAULT_LEFT_PAD,
          HelpFormatter.DEFAULT_DESC_PAD,
          null);

      out.flush();
      System.exit(64);
    }
  }

  /**
   * This is just a convenience method for parsing integers from strings.
   * 
   * @param s the string to parse.
   * @param def the default value, if the string doesn't parse.
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

  private static int parseAlg(String s)
  {
    DnsKeyAlgorithm algs = DnsKeyAlgorithm.getInstance();

    int alg = parseInt(s, -1);
    if (alg > 0) return alg;

    return algs.stringToAlgorithm(s);
  }

  public static void execute(CLIState state) throws Exception
  {
    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    // Minor hack to make the owner name absolute.
    if (!state.owner.endsWith("."))
    {
      state.owner = state.owner + ".";
    }

    Name owner_name = Name.fromString(state.owner);

    // Calculate our flags
    int flags = 0;
    if (state.zoneKey) flags |= DNSKEYRecord.Flags.ZONE_KEY;
    if (state.kskFlag) flags |= DNSKEYRecord.Flags.SEP_KEY;

    log.fine("create key pair with (name = " + owner_name + ", ttl = "
        + state.ttl + ", alg = " + state.algorithm + ", flags = " + flags
        + ", length = " + state.keylength + ")");

    DnsKeyPair pair = signer.generateKey(owner_name,
        state.ttl,
        DClass.IN,
        state.algorithm,
        flags,
        state.keylength);

    if (state.outputfile != null)
    {
      BINDKeyUtils.writeKeyFiles(state.outputfile, pair, state.keydir);
    }
    else
    {
      BINDKeyUtils.writeKeyFiles(pair, state.keydir);
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
      System.err.println("error: unknown option encountered: "
          + e.getMessage());
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

    log = Logger.getLogger(KeyGen.class.toString());

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
