// $Id: VerifyZone.java,v 1.1 2004/01/16 17:57:59 davidb Exp $
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

/** This class forms the command line implementation of a DNSSEC zone
 *  validator.
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.1 $
 */
public class VerifyZone
{
  private static Log log;
  
  /** This is a small inner class used to hold all of the command line
   *  option state. */
  private static class CLIState
  {

    public boolean strict    = false;
    public File    keydir    = null;
    public String  zonefile  = null;
    public String[] keyfiles = null;
    
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

      if (cli.hasOption('s')) strict = true;

      if ((optstr = cli.getOptionValue('d')) != null)
      {
        keydir = new File(optstr);
      }
      
      
      String[] cl_args = cli.getArgs();

      if (cl_args.length < 1)
      {
	System.err.println("error: missing zone file");
	usage(opts);
      }

      zonefile = cl_args[0];

      if (cl_args.length < 2)
      {
        System.err.println("error: at least one trusted key is required");
        usage(opts);
      }
      
      keyfiles = new String[cl_args.length - 1];
      System.arraycopy(cl_args, 1, keyfiles, 0, keyfiles.length);
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
  
  /** Set up the command line options.
   *
   *  @return a set of command line options.
   */
  private static Options setupCLI()
  {
    Options options = new Options();
    
    // boolean options
    options.addOption("h", "help", false, "Print this message.");
    options.addOption("s", "strict", false,
                      "Zone will only be considered valid if all " +
                      "signatures could be cryptographically verified");

    // Argument options
    options.addOption(OptionBuilder.hasArg()
                      .withLongOpt("keydir")
                      .withArgName("dir")
                      .withDescription("directory to find trusted key files")
                      .create('d'));
    
    options.addOption(OptionBuilder.hasOptionalArg()
                      .withLongOpt("verbose")
		      .withArgName("level")
		      .withDescription("verbosity level -- 0 is silence, " +
				       "5 is debug information, " +
				       "6 is trace information.\n" +
				       "default is level 5.")
		      .create('v'));
    
    return options;
  }

  /** Print out the usage and help statements, then quit. */
  private static void usage(Options opts)
  {
    HelpFormatter f = new HelpFormatter();

    PrintWriter out = new PrintWriter(System.err);

    // print our own usage statement:
    f.printHelp(out, 75,
                "verifyZone.sh [..options..] zonefile " +
                "keyfile [keyfile...]", null, opts,
		HelpFormatter.DEFAULT_LEFT_PAD,
                HelpFormatter.DEFAULT_DESC_PAD, null);

    out.flush();
    System.exit(64);
  }


  private static byte verifyZoneSignatures(List records, List keypairs)
  {
    // Zone is secure until proven otherwise.
    byte result = DNSSEC.Secure;

    DnsSecVerifier verifier = new DnsSecVerifier();

    for (Iterator i = keypairs.iterator(); i.hasNext(); )
    {
      verifier.addTrustedKey((DnsKeyPair) i.next());
    }

    List rrsets = SignUtils.assembleIntoRRsets(records);
    
    for (Iterator i = rrsets.iterator(); i.hasNext(); )
    {
      RRset rrset = (RRset) i.next();

      // We verify each signature separately so that we can report
      // which exact signature failed.
      for (Iterator j = rrset.sigs(); j.hasNext(); )
      {
        Object o = j.next();
        if (! (o instanceof RRSIGRecord))
        {
          log.debug("found " + o + " where expecting a RRSIG");
          continue;
        }
        RRSIGRecord sigrec = (RRSIGRecord) o;
        
        byte res = verifier.verifySignature(rrset, sigrec, null);
        if (res != DNSSEC.Secure)
        {
          log.info("Signature failed to verify RRset: " + rrset + "\nsig: " + sigrec);
        }
        if (res < result) result = res;
      }
    }

    return result;
  }

  private static List getTrustedKeys(String[] keyfiles, File inDirectory)
    throws IOException
  {
    if (keyfiles == null) return null;

    List keys = new ArrayList(keyfiles.length);

    for (int i = 0; i < keyfiles.length; i++)
    {
      DnsKeyPair pair = BINDKeyUtils.loadKeyPair(keyfiles[i], inDirectory);
      if (pair != null) keys.add(pair);
    }

    return keys;
  }
  
  public static void execute(CLIState state, Options opts)
    throws Exception
  {

    List keypairs = getTrustedKeys(state.keyfiles, state.keydir);
    
    List records = ZoneUtils.readZoneFile(state.zonefile, null);
    Collections.sort(records, new RecordComparator());

    log.debug("verifying signatures...");
    byte result = verifyZoneSignatures(records, keypairs);
    log.debug("completed verification process.");

    switch (result)
    {
    case DNSSEC.Failed:
      System.out.println("zone did not verify.");
      System.exit(1);
      break;
    case DNSSEC.Insecure:
      if (state.strict)
      {
        System.out.println("zone did not verify.");
        System.exit(1);
      }
    case DNSSEC.Secure:
      System.out.println("zone verified.");
      break;
    }
    System.exit(0);
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

    log = LogFactory.getLog(VerifyZone.class);

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
