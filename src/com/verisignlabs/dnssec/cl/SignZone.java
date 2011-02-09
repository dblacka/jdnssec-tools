// $Id$
//
// Copyright (C) 2001-2003, 2009 VeriSign, Inc.
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;
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
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base16;

import com.verisignlabs.dnssec.security.*;

/**
 * This class forms the command line implementation of a DNSSEC zone signer.
 * 
 * @author David Blacka (original)
 * @author $Author$
 * @version $Revision$
 */
public class SignZone
{
  private static Logger log;

  /**
   * This is an inner class used to hold all of the command line option state.
   */
  private static class CLIState
  {
    private Options opts;
    private File    keyDirectory    = null;
    public File     keysetDirectory = null;
    public String[] kskFiles        = null;
    public String[] keyFiles        = null;
    public String   zonefile        = null;
    public Date     start           = null;
    public Date     expire          = null;
    public String   outputfile      = null;
    public boolean  verifySigs      = false;
    public boolean  useOptOut       = false;
    public boolean  fullySignKeyset = false;
    public List     includeNames    = null;
    public boolean  useNsec3        = false;
    public byte[]   salt            = null;
    public int      iterations      = 0;
    public int      digest_id       = DSRecord.SHA1_DIGEST_ID;
    public long     nsec3paramttl   = -1;
    public boolean  verboseSigning  = false;

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
      opts.addOption("a", "verify", false, "verify generated signatures>");
      opts.addOption("F", "fully-sign-keyset", false,
                     "sign the zone apex keyset with all available keys.");
      opts.addOption("V", "verbose-signing", false, "Display verbose signing activity.");

      // Argument options
      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("verbose");
      OptionBuilder.withArgName("level");
      OptionBuilder.withDescription("verbosity level -- 0 is silence, 3 is info, "
          + "5 is debug information, 6 is trace information. default is level 2 (warning)");
      opts.addOption(OptionBuilder.create('v'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("dir");
      OptionBuilder.withLongOpt("keyset-directory");
      OptionBuilder.withDescription("directory to find keyset files (default '.').");
      opts.addOption(OptionBuilder.create('d'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("dir");
      OptionBuilder.withLongOpt("key-directory");
      OptionBuilder.withDescription("directory to find key files (default '.').");
      opts.addOption(OptionBuilder.create('D'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("time/offset");
      OptionBuilder.withLongOpt("start-time");
      OptionBuilder.withDescription("signature starting time (default is now - 1 hour)");
      opts.addOption(OptionBuilder.create('s'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("time/offset");
      OptionBuilder.withLongOpt("expire-time");
      OptionBuilder.withDescription("signature expiration time (default is start-time + 30 days).");
      opts.addOption(OptionBuilder.create('e'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("outfile");
      OptionBuilder.withDescription("file the signed zone is written to (default is <origin>.signed).");
      opts.addOption(OptionBuilder.create('f'));

      OptionBuilder.hasArgs();
      OptionBuilder.withArgName("KSK file");
      OptionBuilder.withLongOpt("ksk-file");
      OptionBuilder.withDescription("this key is a key signing key (may repeat).");
      opts.addOption(OptionBuilder.create('k'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("file");
      OptionBuilder.withLongOpt("include-file");
      OptionBuilder.withDescription("include names in this file in the NSEC/NSEC3 chain.");
      opts.addOption(OptionBuilder.create('I'));

      // NSEC3 options
      opts.addOption("3", "use-nsec3", false, "use NSEC3 instead of NSEC");
      opts.addOption("O", "use-opt-out", false,
                     "generate a fully Opt-Out zone (only valid with NSEC3).");

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("salt");
      OptionBuilder.withArgName("hex value");
      OptionBuilder.withDescription("supply a salt value.");
      opts.addOption(OptionBuilder.create('S'));

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("random-salt");
      OptionBuilder.withArgName("length");
      OptionBuilder.withDescription("generate a random salt.");
      opts.addOption(OptionBuilder.create('R'));

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("iterations");
      OptionBuilder.withArgName("value");
      OptionBuilder.withDescription("use this value for the iterations in NSEC3.");
      opts.addOption(OptionBuilder.create());

      OptionBuilder.hasArg();
      OptionBuilder.withLongOpt("nsec3paramttl");
      OptionBuilder.withArgName("ttl");
      OptionBuilder.withDescription("use this value for the NSEC3PARAM RR ttl");
      opts.addOption(OptionBuilder.create());

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("alias:original:mnemonic");
      OptionBuilder.withLongOpt("alg-alias");
      OptionBuilder.withDescription("Define an alias for an algorithm (may repeat).");
      opts.addOption(OptionBuilder.create('A'));

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("id");
      OptionBuilder.withLongOpt("ds-digest");
      OptionBuilder.withDescription("Digest algorithm to use for generated DSs");
      opts.addOption(OptionBuilder.create());
    }

    public void parseCommandLine(String[] args)
        throws org.apache.commons.cli.ParseException, ParseException, IOException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

      String optstr = null;
      String[] optstrs = null;

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

      if (cli.hasOption('a')) verifySigs = true;
      if (cli.hasOption('3')) useNsec3 = true;
      if (cli.hasOption('O')) useOptOut = true;
      if (cli.hasOption('V')) verboseSigning = true;

      if (useOptOut && !useNsec3)
      {
        System.err.println("Opt-Out not supported without NSEC3 -- ignored.");
        useOptOut = false;
      }

      if ((optstrs = cli.getOptionValues('A')) != null)
      {
        for (int i = 0; i < optstrs.length; i++)
        {
          addArgAlias(optstrs[i]);
        }
      }

      if (cli.hasOption('F')) fullySignKeyset = true;

      if ((optstr = cli.getOptionValue('d')) != null)
      {
        keysetDirectory = new File(optstr);
        if (!keysetDirectory.isDirectory())
        {
          System.err.println("error: " + optstr + " is not a directory");
          usage();

        }
      }

      if ((optstr = cli.getOptionValue('D')) != null)
      {
        keyDirectory = new File(optstr);
        if (!keyDirectory.isDirectory())
        {
          System.err.println("error: " + optstr + " is not a directory");
          usage();
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

      if ((optstr = cli.getOptionValue('S')) != null)
      {
        salt = base16.fromString(optstr);
        if (salt == null && !optstr.equals("-"))
        {
          System.err.println("error: salt is not valid hexidecimal.");
          usage();
        }
      }

      if ((optstr = cli.getOptionValue('R')) != null)
      {
        int length = parseInt(optstr, 0);
        if (length > 0 && length <= 255)
        {
          Random random = new Random();
          salt = new byte[length];
          random.nextBytes(salt);
        }
      }

      if ((optstr = cli.getOptionValue("iterations")) != null)
      {
        iterations = parseInt(optstr, iterations);
        if (iterations < 0 || iterations > 8388607)
        {
          System.err.println("error: iterations value is invalid");
          usage();
        }
      }

      if ((optstr = cli.getOptionValue("ds-digest")) != null)
      {
        digest_id = parseInt(optstr, -1);
        if (digest_id < 0)
        {
          System.err.println("error: DS digest ID is not a valid identifier");
          usage();
        }
      }

      if ((optstr = cli.getOptionValue("nsec3paramttl")) != null)
      {
        nsec3paramttl = parseInt(optstr, -1);
      }

      String[] files = cli.getArgs();

      if (files.length < 1)
      {
        System.err.println("error: missing zone file and/or key files");
        usage();
      }

      zonefile = files[0];
      if (files.length > 1)
      {
        keyFiles = new String[files.length - 1];
        System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
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
    private void usage()
    {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out, 75,
                  "jdnssec-signzone [..options..] " + "zone_file [key_file ...]", null,
                  opts, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD,
                  "\ntime/offset = YYYYMMDDHHmmss|+offset|\"now\"+offset\n");

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

  /**
   * Verify the generated signatures.
   * 
   * @param zonename
   *          the origin name of the zone.
   * @param records
   *          a list of {@link org.xbill.DNS.Record}s.
   * @param keypairs
   *          a list of keypairs used the sign the zone.
   * @return true if all of the signatures validated.
   */
  private static boolean verifyZoneSigs(Name zonename, List records, List keypairs)
  {
    boolean secure = true;

    DnsSecVerifier verifier = new DnsSecVerifier();

    for (Iterator i = keypairs.iterator(); i.hasNext();)
    {
      verifier.addTrustedKey((DnsKeyPair) i.next());
    }

    verifier.setVerifyAllSigs(true);

    List rrsets = SignUtils.assembleIntoRRsets(records);

    for (Iterator i = rrsets.iterator(); i.hasNext();)
    {
      RRset rrset = (RRset) i.next();

      // skip unsigned rrsets.
      if (!rrset.sigs().hasNext()) continue;

      int result = verifier.verify(rrset, null);

      if (result != DNSSEC.Secure)
      {
        log.fine("Signatures did not verify for RRset: (" + result + "): " + rrset);
        secure = false;
      }
    }

    return secure;
  }

  /**
   * Load the key pairs from the key files.
   * 
   * @param keyfiles
   *          a string array containing the base names or paths of the keys to
   *          be loaded.
   * @param start_index
   *          the starting index of keyfiles string array to use. This allows us
   *          to use the straight command line argument array.
   * @param inDirectory
   *          the directory to look in (may be null).
   * @return a list of keypair objects.
   */
  private static List getKeys(String[] keyfiles, int start_index, File inDirectory)
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

  private static List getKeys(List dnskeyrrs, File inDirectory) throws IOException
  {
    List res = new ArrayList();
    for (Iterator i = dnskeyrrs.iterator(); i.hasNext();)
    {
      // Construct a public-key-only DnsKeyPair just so we can calculate the
      // base name.
      DnsKeyPair pub = new DnsKeyPair((DNSKEYRecord) i.next());
      DnsKeyPair pair = BINDKeyUtils.loadKeyPair(BINDKeyUtils.keyFileBase(pub),
                                                 inDirectory);
      if (pair != null)
      {
        res.add(pair);
      }
    }

    if (res.size() > 0) return res;
    return null;
  }

  private static class KeyFileFilter implements FileFilter
  {
    private String prefix;

    public KeyFileFilter(Name origin)
    {
      prefix = "K" + origin.toString();
    }

    public boolean accept(File pathname)
    {
      if (!pathname.isFile()) return false;
      String name = pathname.getName();
      if (name.startsWith(prefix) && name.endsWith(".private")) return true;
      return false;
    }
  }

  private static List findZoneKeys(File inDirectory, Name zonename) throws IOException
  {
    if (inDirectory == null)
    {
      inDirectory = new File(".");
    }

    // get the list of "K<zone>.*.private files.
    FileFilter filter = new KeyFileFilter(zonename);
    File[] files = inDirectory.listFiles(filter);

    // read in all of the records
    ArrayList keys = new ArrayList();
    for (int i = 0; i < files.length; i++)
    {
      DnsKeyPair p = BINDKeyUtils.loadKeyPair(files[i].getName(), inDirectory);
      keys.add(p);
    }

    if (keys.size() > 0) return keys;
    return null;
  }

  /**
   * This is an implementation of a file filter used for finding BIND 9-style
   * keyset-* files.
   */
  private static class KeysetFileFilter implements FileFilter
  {
    public boolean accept(File pathname)
    {
      if (!pathname.isFile()) return false;
      String name = pathname.getName();
      if (name.startsWith("keyset-")) return true;
      return false;
    }
  }

  /**
   * Load keysets (which contain delegation point security info).
   * 
   * @param inDirectory
   *          the directory to look for the keyset files (may be null, in which
   *          case it defaults to looking in the current working directory).
   * @param zonename
   *          the name of the zone we are signing, so we can ignore keysets that
   *          do not belong in the zone.
   * @return a list of {@link org.xbill.DNS.Record}s found in the keyset files.
   */
  private static List getKeysets(File inDirectory, Name zonename) throws IOException
  {
    if (inDirectory == null)
    {
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
    for (Iterator i = keysetRecords.iterator(); i.hasNext();)
    {
      Record r = (Record) i.next();
      if (!r.getName().subdomain(zonename))
      {
        i.remove();
      }
    }

    return keysetRecords;
  }

  /**
   * Load a list of DNS names from a file.
   * 
   * @param nameListFile
   *          the path of a file containing a bare list of DNS names.
   * @return a list of {@link org.xbill.DNS.Name} objects.
   */
  private static List getNameList(File nameListFile) throws IOException
  {
    BufferedReader br = new BufferedReader(new FileReader(nameListFile));
    List res = new ArrayList();

    String line = null;
    while ((line = br.readLine()) != null)
    {
      try
      {
        Name n = Name.fromString(line);
        // force the name to be absolute.
        // FIXME: we should probably get some fancy logic here to
        // detect if the name needs the origin appended, or just the
        // root.
        if (!n.isAbsolute()) n = Name.concatenate(n, Name.root);

        res.add(n);
      }
      catch (TextParseException e)
      {
        log.severe("DNS Name parsing error:" + e);
      }
    }

    if (res.size() == 0) return null;
    return res;
  }

  /**
   * Calculate a date/time from a command line time/offset duration string.
   * 
   * @param start
   *          the start time to calculate offsets from.
   * @param duration
   *          the time/offset string to parse.
   * @return the calculated time.
   */
  private static Date convertDuration(Date start, String duration) throws ParseException
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

  /**
   * Determine if the given keypairs can be used to sign the zone.
   * 
   * @param zonename
   *          the zone origin.
   * @param keypairs
   *          a list of {@link DnsKeyPair} objects that will be used to sign the
   *          zone.
   * @return true if the keypairs valid.
   */
  private static boolean keyPairsValidForZone(Name zonename, List keypairs)
  {
    if (keypairs == null) return true; // technically true, I guess.

    for (Iterator i = keypairs.iterator(); i.hasNext();)
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

  public static void execute(CLIState state) throws Exception
  {
    // Read in the zone
    List records = ZoneUtils.readZoneFile(state.zonefile, null);
    if (records == null || records.size() == 0)
    {
      System.err.println("error: empty zone file");
      state.usage();
    }

    // calculate the zone name.
    Name zonename = ZoneUtils.findZoneName(records);
    if (zonename == null)
    {
      System.err.println("error: invalid zone file - no SOA");
      state.usage();
    }

    // Load the key pairs.

    List keypairs = getKeys(state.keyFiles, 0, state.keyDirectory);
    List kskpairs = getKeys(state.kskFiles, 0, state.keyDirectory);

    // If we didn't get any keys on the command line, look at the zone apex for
    // any public keys.
    if (keypairs == null && kskpairs == null)
    {
      List dnskeys = ZoneUtils.findRRs(records, zonename, Type.DNSKEY);
      keypairs = getKeys(dnskeys, state.keyDirectory);
    }

    // If we *still* don't have any key pairs, look for keys the key directory
    // that match
    if (keypairs == null && kskpairs == null)
    {
      keypairs = findZoneKeys(state.keyDirectory, zonename);
    }

    // If we don't have any KSKs, but we do have more than one zone
    // signing key (presumably), presume that the zone signing keys
    // are just not differentiated and try to figure out which keys
    // are actually ksks by looking at the SEP flag.
    if ((kskpairs == null || kskpairs.size() == 0) && keypairs != null
        && keypairs.size() > 1)
    {
      for (Iterator i = keypairs.iterator(); i.hasNext();)
      {
        DnsKeyPair pair = (DnsKeyPair) i.next();
        DNSKEYRecord kr = pair.getDNSKEYRecord();
        if ((kr.getFlags() & DNSKEYRecord.Flags.SEP_KEY) != 0)
        {
          if (kskpairs == null) kskpairs = new ArrayList();
          kskpairs.add(pair);
          i.remove();
        }
      }
    }

    // If there are no ZSKs defined at this point (yet there are KSKs
    // provided), all KSKs will be treated as ZSKs, as well.
    if (keypairs == null || keypairs.size() == 0)
    {
      keypairs = kskpairs;
    }

    // If there *still* aren't any ZSKs defined, bail.
    if (keypairs == null || keypairs.size() == 0)
    {
      System.err.println("No zone signing keys could be determined.");
      state.usage();
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
    if (!keyPairsValidForZone(zonename, keypairs)
        || !keyPairsValidForZone(zonename, kskpairs))
    {
      System.err.println("error: specified keypairs are not valid for the zone.");
      state.usage();
    }

    // We force the signing keys to be in the zone by just appending
    // them to the zone here. Currently JCEDnsSecSigner.signZone
    // removes duplicate records.
    if (kskpairs != null)
    {
      for (Iterator i = kskpairs.iterator(); i.hasNext();)
      {
        records.add(((DnsKeyPair) i.next()).getDNSKEYRecord());
      }
    }
    if (keypairs != null)
    {
      for (Iterator i = keypairs.iterator(); i.hasNext();)
      {
        records.add(((DnsKeyPair) i.next()).getDNSKEYRecord());
      }
    }

    // read in the keysets, if any.
    List keysetrecs = getKeysets(state.keysetDirectory, zonename);
    if (keysetrecs != null)
    {
      records.addAll(keysetrecs);
    }

    JCEDnsSecSigner signer = new JCEDnsSecSigner(state.verboseSigning);

    // Sign the zone.
    List signed_records;

    if (state.useNsec3)
    {
      signed_records = signer.signZoneNSEC3(zonename, records, kskpairs, keypairs,
                                            state.start, state.expire,
                                            state.fullySignKeyset, state.useOptOut,
                                            state.includeNames, state.salt,
                                            state.iterations, state.digest_id,
                                            state.nsec3paramttl);
    }
    else
    {
      signed_records = signer.signZone(zonename, records, kskpairs, keypairs,
                                       state.start, state.expire, state.fullySignKeyset,
                                       state.digest_id);
    }

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

      log.fine("verifying generated signatures");
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

    log = Logger.getLogger(SignZone.class.toString());

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
