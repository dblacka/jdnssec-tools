// $Id: SignZone.java,v 1.4 2004/01/16 17:57:47 davidb Exp $
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
 *  signer.
 *
 *  @author David Blacka (original)
 *  @author $Author: davidb $
 *  @version $Revision: 1.4 $
 */
public class SignZone
{
  private static Log log;
  
  /** This is a small inner class used to hold all of the command line
   *  option state. */
  private static class CLIState
  {
    private File    keyDirectory    = null;
    public File     keysetDirectory = null;
    public String[] kskFiles        = null;
    public String[] keyFiles        = null;
    public String   zonefile        = null;
    public Date     start           = null;
    public Date     expire          = null;
    public String   outputfile      = null;
    public boolean  verifySigs      = false;
    public boolean  selfSignKeys    = true;
    public boolean  useOptIn        = false;
    public boolean  optInConserve   = false;
    public boolean  fullySignKeyset = false;
    public List     includeNames    = null;

    public CLIState() { }

    public void parseCommandLine(Options opts, String[] args)
      throws org.apache.commons.cli.ParseException, ParseException,
	     IOException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

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

      if (cli.hasOption('a')) verifySigs = true;
      if (cli.hasOption('O')) useOptIn = true;
      if (cli.hasOption('C'))
      {
	useOptIn      = true;
	optInConserve = true;
      }

      if (cli.hasOption('F')) fullySignKeyset = true;
      
      if ((optstr = cli.getOptionValue('d')) != null)
      {
	keysetDirectory = new File(optstr);
	if (! keysetDirectory.isDirectory())
	{
          System.err.println("error: " + optstr + " is not a directory");
          usage(opts);

	}
      }
      
      if ((optstr = cli.getOptionValue('D')) != null)
      {
        keyDirectory = new File(optstr);
        if (! keyDirectory.isDirectory())
        {
          System.err.println("error: " + optstr + " is not a directory");
          usage(opts);
        }
      }

      if ((optstr = cli.getOptionValue('s')) != null)
      {
        start = convertDuration(null, optstr);
      }
      else
      {
	// default is now - 1 hour.
        start = new Date(System.currentTimeMillis() - (3600 * 1000));
      }

      if ((optstr = cli.getOptionValue('e')) != null)
      {
        expire = convertDuration(start, optstr);
      }
      else
      {
        expire = convertDuration(start, "+2592000"); // 30 days
      }

      outputfile = cli.getOptionValue('f');

      kskFiles = cli.getOptionValues('k');

      if ((optstr = cli.getOptionValue('I')) != null)
      {
	File includeNamesFile = new File(optstr);
	includeNames = getNameList(includeNamesFile);
      }      
      
      String[] files = cli.getArgs();

      if (files.length < 2)
      {
	System.err.println("error: missing zone file and/or key files");
	usage(opts);
      }

      zonefile = files[0];
      keyFiles = new String[files.length - 1];
      System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
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

  /** Verify the generated signatures.
   *
   *  @param zonename the origin name of the zone.
   *  @param records a list of {@link org.xbill.DNS.Record}s.
   *  @param keypairs a list of keypairs used the sign the zone.
   *  @return true if all of the signatures validated.
   */
  private static boolean verifyZoneSigs(Name zonename, List records,
					List keypairs)
  {
    boolean secure = true;
    
    DnsSecVerifier verifier = new DnsSecVerifier();

    for (Iterator i = keypairs.iterator(); i.hasNext(); )
    {
      verifier.addTrustedKey((DnsKeyPair) i.next());
    }

    verifier.setVerifyAllSigs(true);

    List rrsets = SignUtils.assembleIntoRRsets(records);

    for (Iterator i = rrsets.iterator(); i.hasNext(); )
    {
      RRset rrset = (RRset) i.next();

      // skip unsigned rrsets.
      if (!rrset.sigs().hasNext()) continue;
      
      byte result = verifier.verify(rrset, null);

      if (result != DNSSEC.Secure)
      {
	log.debug("Signatures did not verify for RRset: (" + result + "): " +
		  rrset);
	secure = false;
      }
    }

    return secure;
  }

  /** Load the key pairs from the key files.
   *
   *  @param keyfiles a string array containing the base names or
   *  paths of the keys to be loaded.
   *  @param start_index the starting index of keyfiles string array
   *  to use.  This allows us to use the straight command line
   *  argument array.
   *  @param inDirectory the directory to look in (may be null).
   *  @return a list of keypair objects.
   */
  private static List getKeys(String[] keyfiles, int start_index,
                              File inDirectory)
    throws IOException
  {
    if (keyfiles == null) return null;

    int len = keyfiles.length - start_index;
    if (len <= 0) return null;

    ArrayList keys = new ArrayList(len);

    for (int i = start_index; i < keyfiles.length; i++)
    {
      DnsKeyPair k = BINDKeyUtils.loadKeyPair(keyfiles[i], inDirectory);
      if (k != null) keys.add(k);
    }

    return keys;
  }

  /** Load a single key from a given keyfile.
   *
   *  @param keyfile the keyfile.
   *  @param inDirectory the default directory to look in (may be
   *  null).
   *  @return a list containing one or zero keypair objects.
   */
  private static List getKeys(File keyfile, File inDirectory)
    throws IOException
  {
    if (keyfile == null) return null;

    DnsKeyPair k = BINDKeyUtils.loadKeyPair(keyfile.getPath(),
					    inDirectory);
    if (k != null)
    {
      ArrayList keys = new ArrayList(1);
      keys.add(k);
      return keys;
    }

    return null;
  }

  /** This is an implementation of a file filter used for finding BIND
   *  9-style keyset-* files. */
  private static class KeysetFileFilter implements FileFilter
  {
    public boolean accept(File pathname)
    {
      if (! pathname.isFile()) return false;
      String name = pathname.getName();
      if (name.startsWith("keyset-")) return true;
      return false;
    }
  }

  /** Load keysets (which contain delegation point security info).
   *
   *  @param inDirectory the directory to look for the keyset files
   *  (may be null, in which case it defaults to looking in the
   *  current working directory).
   *  @param zonename the name of the zone we are signing, so we can
   *  ignore keysets that do not belong in the zone.
   *  @return a list of {@link org.xbill.DNS.Record}s found in the
   *  keyset files.
   */
  private static List getKeysets(File inDirectory, Name zonename)
    throws IOException
  {
    if (inDirectory == null)
    {
      // FIXME: dunno how cross-platform this is
      inDirectory = new File(".");
    }

    // get the list of "keyset-" files.
    FileFilter filter = new KeysetFileFilter();
    File[] files = inDirectory.listFiles(filter);

    // read in all of the records
    ArrayList keysetRecords = new ArrayList();
    for (int i = 0; i < files.length; i++)
    {
      List l = ZoneUtils.readZoneFile(files[i].getAbsolutePath(), zonename);
      keysetRecords.addAll(l);
    }

    // discard records that do not belong to the zone in question.
    for (Iterator i = keysetRecords.iterator(); i.hasNext(); )
    {
      Record r = (Record) i.next();
      if (!r.getName().subdomain(zonename))
      {
	i.remove();
      }
    }

    return keysetRecords;
  }

  /** Load a list of DNS names from a file.
   *
   *  @param nameListFile the path of a file containing a bare list of
   *  DNS names.
   *  @return a list of {@link org.xbill.DNS.Name} objects.
   */
  private static List getNameList(File nameListFile)
    throws IOException
  {
    BufferedReader br = new BufferedReader(new FileReader(nameListFile));
    List res = new ArrayList();

    String line = null;
    while ( (line = br.readLine()) != null )
    {
      try
      {
	Name n = Name.fromString(line);
	// force the name to be absolute.
	// FIXME: we should probably get some fancy logic here to
	// detect if the name needs the origin appended, or just the
	// root.
	if (! n.isAbsolute()) n = Name.concatenate(n, Name.root);
	  
	res.add(n);
      }
      catch (TextParseException e)
      {
	log.error("DNS Name parsing error", e);
      }
    }

    if (res.size() == 0) return null;
    return res;
  }

  /** Calculate a date/time from a command line time/offset duration string.
   *
   *  @param start the start time to calculate offsets from.
   *  @param duration the time/offset string to parse.
   *  @return the calculated time.
   */
  private static Date convertDuration(Date start, String duration)
    throws ParseException
  {
    if (start == null) start = new Date();
    if (duration.startsWith("now"))
    {
      start = new Date();
      if (duration.indexOf("+") < 0) return start;
      
      duration = duration.substring(3);
    }

    if (duration.startsWith("+"))
    {
      long offset = (long) parseInt(duration.substring(1), 0) * 1000;
      return new Date(start.getTime() + offset);
    }

    SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMddHHmmss");
    dateFormatter.setTimeZone(TimeZone.getTimeZone("GMT"));
    return dateFormatter.parse(duration);
  }

  /** Determine if the given keypairs can be used to sign the zone.
   *  @param zonename the zone origin.
   *  @param keypairs a list of {@link DnsKeyPair} objects that will
   *  be used to sign the zone.
   *  @return true if the keypairs valid.
  */
  private static boolean keyPairsValidForZone(Name zonename, List keypairs)
  {
    if (keypairs == null) return true; // technically true, I guess.
    
    for (Iterator i = keypairs.iterator(); i.hasNext(); )
    {
      DnsKeyPair kp = (DnsKeyPair) i.next();
      Name keyname = kp.getDNSKEYRecord().getName();
      if (!keyname.equals(zonename))
      {
	return false;
      }
    }

    return true;
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
    options.addOption("a", false, "verify generated signatures>");
    options.addOption("F", "fully-sign-keyset", false,
		      "sign the zone apex keyset with all " +
		      "available keys, instead of just key-signing-keys.");
    
    // Opt-In generation switches
    OptionGroup opt_in_opts = new OptionGroup();
    opt_in_opts.addOption(new Option
			  ("O", "generate a fully Opt-In zone."));
    opt_in_opts.addOption(new Option
			  ("C", "generate a conservative Opt-In zone."));
    options.addOptionGroup(opt_in_opts);

    // Argument options
    options.addOption(OptionBuilder.hasOptionalArg()
		      .withArgName("level")
		      .withDescription("verbosity level -- 0 is silence, " +
				       "5 is debug information, " +
				       "6 is trace information. " +
				       "No argument means 5.")
		      .create('v'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("dir")
		      .withLongOpt("keyset-directory")
		      .withDescription
		      ("directory to find keyset files (default '.').")
		      .create('d'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("dir")
		      .withLongOpt("key-directory")
		      .withDescription
		      ("directory to find key files (default '.').")
		      .create('D'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("time/offset")
		      .withLongOpt("start-time")
		      .withDescription
		      ("signature starting time (default is now - 1 hour)")
		      .create('s'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("time/offset")
		      .withLongOpt("expire-time")
		      .withDescription
		      ("signature expiration time (default is " +
		       "start-time + 30 days")
		      .create('e'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("outfile")
		      .withDescription("file the signed zone is written " +
				       "to (default is <origin>.signed).")
		      .create('f'));
    options.addOption(OptionBuilder.hasArgs()
		      .withArgName("KSK file")
		      .withLongOpt("ksk-file")
		      .withDescription("this key is a key signing key " +
				       "(may repeat)")
		      .create('k'));
    options.addOption(OptionBuilder.hasArg()
		      .withArgName("file")
		      .withLongOpt("include-file")
		      .withDescription("include names in this file " +
				       "in the NSEC chain")
		      .create('I'));

    return options;
  }

  /** Print out the usage and help statements, then quit. */
  private static void usage(Options opts)
  {
    HelpFormatter f = new HelpFormatter();

    PrintWriter out = new PrintWriter(System.err);

    // print our own usage statement:
    out.println("usage: signZone.sh [..options..] zone_file [key_file ...] ");    
    f.printHelp(out, 75, "signZone.sh", null, opts,
		HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD,
		"\ntime/offset = YYYYMMDDHHmmss|+offset|\"now\"+offset\n");

    out.flush();
    System.exit(64);
  }


  public static void execute(CLIState state, Options opts)
    throws Exception
  {
    // Load the key pairs.
    
    // FIXME: should we do what BIND 9.3.x snapshots do and look at
    // zone apex DNSKEY RRs, and from that be able to load all of the
    // keys?
    
    List   keypairs = getKeys(state.keyFiles, 0, state.keyDirectory);
    List   kskpairs = getKeys(state.kskFiles, 0, state.keyDirectory);

    // If we don't have any KSKs, but we do have more than one zone
    // signing key (presumably), presume that the zone signing keys
    // are just not differentiated and try to figure out which keys
    // are actually ksks by looking at the SEP flag.
    if ( (kskpairs == null || kskpairs.size() == 0) &&
         keypairs != null && keypairs.size() > 1)
    {
      for (Iterator i = keypairs.iterator(); i.hasNext(); )
      {
        DnsKeyPair pair = (DnsKeyPair) i.next();
        DNSKEYRecord kr = pair.getDNSKEYRecord();
        if ((kr.getFlags() & DNSKEYRecord.FLAG_SEP) != 0)
        {
          if (kskpairs == null) kskpairs = new ArrayList();
          kskpairs.add(pair);
          i.remove();
        }
      }
    }
    
    // Read in the zone
    List records = ZoneUtils.readZoneFile(state.zonefile, null);
    if (records == null || records.size() == 0)
    {
      System.err.println("error: empty zone file");
      usage(opts);
    }

    // calculate the zone name.
    Name zonename = ZoneUtils.findZoneName(records);
    if (zonename == null)
    {
      System.err.println("error: invalid zone file - no SOA");
      usage(opts);
    }

    // default the output file, if not set.
    if (state.outputfile == null)
    {
      if (zonename.isAbsolute())
      {
	state.outputfile = zonename + "signed";
      }
      else
      {
	state.outputfile = zonename + ".signed";
      }
    }
    
    // Verify that the keys can be in the zone.
    List kpairs = keypairs;

    if (!keyPairsValidForZone(zonename, keypairs) ||
	!keyPairsValidForZone(zonename, kskpairs))
    {
      usage(opts);
    }

    // We force the signing keys to be in the zone by just appending
    // them to the zone here.  Currently JCEDnsSecSigner.signZone
    // removes duplicate records.
    if (kskpairs != null)
    {
      for (Iterator i = kskpairs.iterator(); i.hasNext(); )
      {
        records.add( ((DnsKeyPair) i.next()).getDNSKEYRecord() );
      }
    }
    if (keypairs != null)
    {
      for (Iterator i = keypairs.iterator(); i.hasNext(); )
      {
        records.add( ((DnsKeyPair) i.next()).getDNSKEYRecord() );
      }
    }
      
    // read in the keysets, if any.
    List keysetrecs = getKeysets(state.keysetDirectory, zonename);
    if (keysetrecs != null)
    {
      records.addAll(keysetrecs);
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner();

    // Sign the zone.
    List signed_records = signer.signZone(zonename,
					  records,
					  kskpairs,
					  keypairs,
					  state.start,
					  state.expire,
					  state.useOptIn,
					  state.optInConserve,
					  state.fullySignKeyset,
					  state.includeNames);
    
    // write out the signed zone
    // force multiline mode for now
    org.xbill.DNS.Options.set("multiline");
    ZoneUtils.writeZoneFile(signed_records, state.outputfile);

    if (state.verifySigs)
    {
      // FIXME: ugh.
      if (kskpairs != null)
      {
	keypairs.addAll(kskpairs);
      }
      
      log.debug("verifying generated signatures");
      boolean res = verifyZoneSigs(zonename, signed_records, keypairs);

      if (res)
      {
	System.out.println("Generated signatures verified");
	// log.info("Generated signatures verified");
      }
      else
      {
	System.out.println("Generated signatures did not verify.");
	// log.warn("Generated signatures did not verify.");
      }
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

    log = LogFactory.getLog(SignZone.class);

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
