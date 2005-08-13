// $Id: KeyGen.java,v 1.2 2004/01/16 17:56:17 davidb Exp $
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

import java.util.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.security.GeneralSecurityException;

import org.xbill.DNS.*;

import com.verisignlabs.dnssec.security.*;

import org.apache.commons.cli.*;
import org.apache.commons.cli.Options;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/** This class forms the command line implementation of a DNSSEC key
 *  generator
 *
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.2 $
 */
public class KeyGen
{
  private static Log log;
  
  /** This is a small inner class used to hold all of the command line
   *  option state. */
  private static class CLIState
  {
    public int     algorithm  = 5;
    public int     keylength  = 1024;
    public String  outputfile = null;
    public File    keydir     = null;
    public boolean zoneKey    = true;
    public boolean kskFlag    = false;
    public String  owner      = null;
    public long    ttl        = 86400;
    
    public CLIState() { }

    public void parseCommandLine(Options opts, String[] args)
      throws org.apache.commons.cli.ParseException, ParseException,
	     IOException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine       cli        = cli_parser.parse(opts, args);

      String optstr = null;

      if (cli.hasOption('h')) usage(opts);
      
      if (cli.hasOption('v'))
      {
	int value = parseInt(cli.getOptionValue('v'), 5);

	switch (value)
	{
	case 0:
	  System.setProperty("org.apache.commons.logging.simplelog.defaultlog",
			     "fatal");
	  break;
	case 5:
	default:
	  System.setProperty("org.apache.commons.logging.simplelog.defaultlog",
			     "debug");
	  break;
	case 6:
	  System.setProperty("org.apache.commons.logging.simplelog.defaultlog",
			     "trace");
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
        if (! optstr.equalsIgnoreCase("ZONE"))
        {
          zoneKey = false;
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
	usage(opts);
      }

      owner = cl_args[0];
    }
  }

  /** This is just a convenience method for parsing integers from
   *  strings.
   *
   *  @param s the string to parse.
   *  @param def the default value, if the string doesn't parse.
   *  @return the parsed integer, or the default.
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
    int alg = parseInt(s, -1);
    if (alg > 0) return alg;
    
    s = s.toUpperCase();

    if (s.equals("RSA"))
    {
      return DNSSEC.RSASHA1;
    }
    else if (s.equals("RSAMD5"))
    {
      return DNSSEC.RSA;
    }
    else if (s.equals("DH"))
    {
      return DNSSEC.DH;
    }
    else if (s.equals("DSA"))
    {
      return DNSSEC.DSA;
    }
    else if (s.equals("RSASHA1"))
    {
      return DNSSEC.RSASHA1;
    }

    // default
    return DNSSEC.RSASHA1;
  }
  
  /** Set up the command line options.
   *
   *  @return a set of command line options.
   */
  private static Options setupCLI()
  {
    Options options = new Options();
    
    // boolean options
    options.addOption("h", "help", false, "Print this message.");
    options.addOption("k", "kskflag", false,
                      "Key is a key-signing-key (sets the SEP flag).");

    // Argument options
    options.addOption(OptionBuilder.hasArg()
                      .withLongOpt("nametype")
                      .withArgName("type")
                      .withDescription("ZONE | OTHER (default ZONE)")
                      .create('n'));
    options.addOption(OptionBuilder.hasOptionalArg()
                      .withLongOpt("verbose")
		      .withArgName("level")
		      .withDescription("verbosity level -- 0 is silence, " +
				       "5 is debug information, " +
				       "6 is trace information.\n"+
				       "default is level 5.")
		      .create('v'));
    options.addOption(OptionBuilder.hasArg()
                      .withArgName("algorithm")
                      .withDescription("RSA | RSASHA1 | RSAMD5 | DH | DSA, " +
                                       "RSASHA1 is default.")
                      .create('a'));
    options.addOption(OptionBuilder.hasArg()
                      .withArgName("size")
                      .withDescription
                      ("key size, in bits. (default = 1024)\n" +
                       "RSA|RSASHA1|RSAMD5: [512..4096]\n" +
                       "DSA:                [512..1024]\n" +
                       "DH:                 [128..4096]")
                      .create('b'));
    options.addOption(OptionBuilder.hasArg()
                      .withArgName("file")
                      .withLongOpt("output-file")
                      .withDescription
                      ("base filename for the public/private key files")
                      .create('f'));
    options.addOption(OptionBuilder.hasArg()
                      .withLongOpt("keydir")
                      .withArgName("dir")
                      .withDescription
                      ("place generated key files in this directory")
                      .create('d'));
    
    return options;
  }

  /** Print out the usage and help statements, then quit. */
  private static void usage(Options opts)
  {
    HelpFormatter f = new HelpFormatter();

    PrintWriter out = new PrintWriter(System.err);

    // print our own usage statement:
    f.printHelp(out, 75, "keyGen.sh [..options..] name", null, opts,
		HelpFormatter.DEFAULT_LEFT_PAD,
                HelpFormatter.DEFAULT_DESC_PAD, null);

    out.flush();
    System.exit(64);
  }


  public static void execute(CLIState state, Options opts)
    throws Exception
  {
    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    // Minor hack to make the owner name absolute.
    if (! state.owner.endsWith("."))
    {
      state.owner = state.owner + ".";
    }
    
    Name owner_name = Name.fromString(state.owner);

    // Calculate our flags
    int flags = 0;
    if (state.zoneKey) flags |= DNSKEYRecord.OWNER_ZONE;
    if (state.kskFlag) flags |= DNSKEYRecord.FLAG_SEP;

    log.debug("create key pair with (name = " + owner_name + ", ttl = " +
              state.ttl + ", alg = " + state.algorithm + ", flags = " +
              flags + ", length = " + state.keylength + ")");
          
    
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
    // set up logging.
    // For now, we force the commons logging to use the built-in
    // SimpleLog.
    System.setProperty("org.apache.commons.logging.Log",
		       "org.apache.commons.logging.impl.SimpleLog");

    // set up the command line options
    Options opts = setupCLI();
    
    CLIState  state = new CLIState();

    try
    {
      state.parseCommandLine(opts, args);
    }
    catch (UnrecognizedOptionException e)
    {
      System.err.println("error: unknown option encountered: " +
			 e.getMessage());
      usage(opts);
    }
    catch (AlreadySelectedException e)
    {
      System.err.println("error: mutually exclusive options have " +
			 "been selected:\n     " + e.getMessage());
      usage(opts);
    }
    catch (Exception e)
    {
      System.err.println("error: unknown command line parsing exception:");
      e.printStackTrace();
      usage(opts);
    }

    log = LogFactory.getLog(KeyGen.class);

    try
    {
      execute(state, opts);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
}
