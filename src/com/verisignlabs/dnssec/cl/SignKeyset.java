// $Id: SignZone.java 2235 2009-02-07 20:37:29Z davidb $
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

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
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
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import com.verisignlabs.dnssec.security.*;

/**
 * This class forms the command line implementation of a DNSSEC keyset signer.
 * Instead of being able to sign an entire zone, it will just sign a given
 * DNSKEY RRset.
 * 
 * @author David Blacka (original)
 * @author $Author: davidb $
 * @version $Revision: 2235 $
 */
public class SignKeyset {
    private static Logger log;

    /**
     * This is an inner class used to hold all of the command line option state.
     */
    private static class CLIState {
        private Options opts;
        private File    keyDirectory = null;
        public String[] keyFiles     = null;
        public Date     start        = null;
        public Date     expire       = null;
        public String   inputfile    = null;
        public String   outputfile   = null;
        public boolean  verifySigs   = false;

        public CLIState() {
            setupCLI();
        }

        /**
         * Set up the command line options.
         * 
         * @return a set of command line options.
         */
        private void setupCLI() {
            opts = new Options();

            // boolean options
            opts.addOption("h", "help", false, "Print this message.");
            opts.addOption("a", "verify", false, "verify generated signatures>");

            OptionBuilder.hasOptionalArg();
            OptionBuilder.withLongOpt("verbose");
            OptionBuilder.withArgName("level");
            OptionBuilder.withDescription("verbosity level.");
            // Argument options
            opts.addOption(OptionBuilder.create('v'));

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
            OptionBuilder.withDescription("file the signed keyset is written to.");
            opts.addOption(OptionBuilder.create('f'));
        }

        public void parseCommandLine(String[] args)
                throws org.apache.commons.cli.ParseException, ParseException,
                IOException {
            CommandLineParser cli_parser = new PosixParser();
            CommandLine cli = cli_parser.parse(opts, args);

            String optstr = null;
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

            if ((optstr = cli.getOptionValue('D')) != null) {
                keyDirectory = new File(optstr);
                if (!keyDirectory.isDirectory()) {
                    System.err.println("error: " + optstr
                            + " is not a directory");
                    usage();
                }
            }

            if ((optstr = cli.getOptionValue('s')) != null) {
                start = convertDuration(null, optstr);
            } else {
                // default is now - 1 hour.
                start = new Date(System.currentTimeMillis() - (3600 * 1000));
            }

            if ((optstr = cli.getOptionValue('e')) != null) {
                expire = convertDuration(start, optstr);
            } else {
                expire = convertDuration(start, "+2592000"); // 30 days
            }

            outputfile = cli.getOptionValue('f');

            String[] files = cli.getArgs();

            if (files.length < 1) {
                System.err.println("error: missing zone file and/or key files");
                usage();
            }

            inputfile = files[0];
            if (files.length > 1) {
                keyFiles = new String[files.length - 1];
                System.arraycopy(files, 1, keyFiles, 0, files.length - 1);
            }
        }

        /** Print out the usage and help statements, then quit. */
        private void usage() {
            HelpFormatter f = new HelpFormatter();

            PrintWriter out = new PrintWriter(System.err);

            // print our own usage statement:
            out.println("usage: jdnssec-signkeyset [..options..] "
                    + "dnskeyset_file [key_file ...] ");
            f.printHelp(out, 75, "signZone.sh", null, opts,
                        HelpFormatter.DEFAULT_LEFT_PAD,
                        HelpFormatter.DEFAULT_DESC_PAD,
                        "\ntime/offset = YYYYMMDDHHmmss|+offset|\"now\"+offset\n");

            out.flush();
            System.exit(64);
        }
    }

    /**
     * This is just a convenience method for parsing integers from strings.
     * 
     * @param s
     *            the string to parse.
     * @param def
     *            the default value, if the string doesn't parse.
     * @return the parsed integer, or the default.
     */
    private static int parseInt(String s, int def) {
        try {
            int v = Integer.parseInt(s);
            return v;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /**
     * Verify the generated signatures.
     * 
     * @param zonename
     *            the origin name of the zone.
     * @param records
     *            a list of {@link org.xbill.DNS.Record}s.
     * @param keypairs
     *            a list of keypairs used the sign the zone.
     * @return true if all of the signatures validated.
     */
    private static boolean verifySigs(Name zonename, List records, List keypairs) {
        boolean secure = true;

        DnsSecVerifier verifier = new DnsSecVerifier();

        for (Iterator i = keypairs.iterator(); i.hasNext();) {
            verifier.addTrustedKey((DnsKeyPair) i.next());
        }

        verifier.setVerifyAllSigs(true);

        List rrsets = SignUtils.assembleIntoRRsets(records);

        for (Iterator i = rrsets.iterator(); i.hasNext();) {
            RRset rrset = (RRset) i.next();

            // skip unsigned rrsets.
            if (!rrset.sigs().hasNext()) continue;

            int result = verifier.verify(rrset, null);

            if (result != DNSSEC.Secure) {
                log.fine("Signatures did not verify for RRset: (" + result
                        + "): " + rrset);
                secure = false;
            }
        }

        return secure;
    }

    /**
     * Load the key pairs from the key files.
     * 
     * @param keyfiles
     *            a string array containing the base names or paths of the keys
     *            to be loaded.
     * @param start_index
     *            the starting index of keyfiles string array to use. This
     *            allows us to use the straight command line argument array.
     * @param inDirectory
     *            the directory to look in (may be null).
     * @return a list of keypair objects.
     */
    private static List getKeys(String[] keyfiles, int start_index,
                                File inDirectory) throws IOException {
        if (keyfiles == null) return null;

        int len = keyfiles.length - start_index;
        if (len <= 0) return null;

        ArrayList keys = new ArrayList(len);

        for (int i = start_index; i < keyfiles.length; i++) {
            DnsKeyPair k = BINDKeyUtils.loadKeyPair(keyfiles[i], inDirectory);
            if (k != null) keys.add(k);
        }

        return keys;
    }

    private static class KeyFileFilter implements FileFilter {
        private String prefix;

        public KeyFileFilter(Name origin) {
            prefix = "K" + origin.toString();
        }

        public boolean accept(File pathname) {
            if (!pathname.isFile()) return false;
            String name = pathname.getName();
            if (name.startsWith(prefix) && name.endsWith(".private"))
                return true;
            return false;
        }
    }

    private static List findZoneKeys(File inDirectory, Name zonename)
            throws IOException {
        if (inDirectory == null) {
            inDirectory = new File(".");
        }

        // get the list of "K<zone>.*.private files.
        FileFilter filter = new KeyFileFilter(zonename);
        File[] files = inDirectory.listFiles(filter);

        // read in all of the records
        ArrayList keys = new ArrayList();
        for (int i = 0; i < files.length; i++) {
            DnsKeyPair p = BINDKeyUtils.loadKeyPair(files[i].getName(),
                                                    inDirectory);
            keys.add(p);
        }

        if (keys.size() > 0) return keys;
        return null;
    }

    /**
     * Calculate a date/time from a command line time/offset duration string.
     * 
     * @param start
     *            the start time to calculate offsets from.
     * @param duration
     *            the time/offset string to parse.
     * @return the calculated time.
     */
    private static Date convertDuration(Date start, String duration)
            throws ParseException {
        if (start == null) start = new Date();
        if (duration.startsWith("now")) {
            start = new Date();
            if (duration.indexOf("+") < 0) return start;

            duration = duration.substring(3);
        }

        if (duration.startsWith("+")) {
            long offset = (long) parseInt(duration.substring(1), 0) * 1000;
            return new Date(start.getTime() + offset);
        }

        SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMddHHmmss");
        dateFormatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormatter.parse(duration);
    }

    public static void execute(CLIState state) throws Exception {
        // Read in the zone
        List records = ZoneUtils.readZoneFile(state.inputfile, null);
        if (records == null || records.size() == 0) {
            System.err.println("error: empty keyset file");
            state.usage();
        }

        // Make sure that all records are DNSKEYs with the same name.
        Name keysetName = null;
        RRset keyset = new RRset();
        for (Iterator i = records.iterator(); i.hasNext();) {
            Record r = (Record) i.next();
            if (r.getType() != Type.DNSKEY) {
                System.err.println("error: Non DNSKEY RR found in keyset: " + r);
                continue;
            }
            if (keysetName == null) {
                keysetName = r.getName();
            }
            if (!r.getName().equals(keysetName)) {
                System.err.println("error: DNSKEY with a different name found!");
                state.usage();
            }
            keyset.addRR(r);
        }

        if (keyset.size() == 0) {
            System.err.println("error: No DNSKEYs found in keyset file");
            state.usage();
        }

        // Load the key pairs.
        List keypairs = getKeys(state.keyFiles, 0, state.keyDirectory);

        // If we *still* don't have any key pairs, look for keys the key
        // directory
        // that match
        if (keypairs == null) {
            keypairs = findZoneKeys(state.keyDirectory, keysetName);
        }

        // If there *still* aren't any ZSKs defined, bail.
        if (keypairs == null || keypairs.size() == 0) {
            System.err.println("error: No signing keys could be determined.");
            state.usage();
        }

        // default the output file, if not set.
        if (state.outputfile == null) {
            if (keysetName.isAbsolute()) {
                state.outputfile = keysetName + "signed_keyset";
            } else {
                state.outputfile = keysetName + ".signed_keyset";
            }
        }

        JCEDnsSecSigner signer = new JCEDnsSecSigner();

        List sigs = signer.signRRset(keyset, keypairs, state.start,
                                     state.expire);
        for (Iterator i = sigs.iterator(); i.hasNext();) {
            keyset.addRR((Record) i.next());
        }

        // write out the signed RRset
        List signed_records = new ArrayList();
        for (Iterator i = keyset.rrs(); i.hasNext();) {
            signed_records.add(i.next());
        }
        for (Iterator i = keyset.sigs(); i.hasNext();) {
            signed_records.add(i.next());
        }

        // write out the signed zone
        // force multiline mode for now
        org.xbill.DNS.Options.set("multiline");
        ZoneUtils.writeZoneFile(signed_records, state.outputfile);

        if (state.verifySigs) {
            log.fine("verifying generated signatures");
            boolean res = verifySigs(keysetName, signed_records, keypairs);

            if (res) {
                System.out.println("Generated signatures verified");
                // log.info("Generated signatures verified");
            } else {
                System.out.println("Generated signatures did not verify.");
                // log.warn("Generated signatures did not verify.");
            }
        }

    }

    public static void main(String[] args) {
        CLIState state = new CLIState();
        try {
            state.parseCommandLine(args);
        } catch (UnrecognizedOptionException e) {
            System.err.println("error: unknown option encountered: "
                    + e.getMessage());
            state.usage();
        } catch (AlreadySelectedException e) {
            System.err.println("error: mutually exclusive options have "
                    + "been selected:\n     " + e.getMessage());
            state.usage();
        } catch (Exception e) {
            System.err.println("error: unknown command line parsing exception:");
            e.printStackTrace();
            state.usage();
        }

        log = Logger.getLogger(SignKeyset.class.toString());

        try {
            execute(state);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
