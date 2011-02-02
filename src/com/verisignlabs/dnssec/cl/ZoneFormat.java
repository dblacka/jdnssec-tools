/*
 * $Id$
 * 
 * Copyright (c) 2005 VeriSign. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. The name of the author may not
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 */

package com.verisignlabs.dnssec.cl;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.*;
import org.xbill.DNS.Master;
import org.xbill.DNS.Options;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

import com.verisignlabs.dnssec.security.RecordComparator;

/**
 * This class forms the command line implementation of a zone file normalizer.
 * That is, a tool to rewrite zones in a consistent, comparable format.
 * 
 * @author David Blacka (original)
 * @author $Author: davidb $
 * @version $Revision: 2218 $
 */
public class ZoneFormat
{
  // private static Logger log;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  private static class CLIState
  {
    private org.apache.commons.cli.Options opts;
    public String                          file;

    public CLIState()
    {
      setupCLI();
    }

    public void parseCommandLine(String[] args)
        throws org.apache.commons.cli.ParseException
    {
      CommandLineParser cli_parser = new PosixParser();
      CommandLine cli = cli_parser.parse(opts, args);

      // String optstr = null;

      if (cli.hasOption('h')) usage();
      if (cli.hasOption('m')) Options.set("multiline");

      if (cli.hasOption('v'))
      {
        int value = parseInt(cli.getOptionValue('v'), 5);
        Logger rootLogger = Logger.getLogger("");
        switch (value)
        {
          case 0:
            rootLogger.setLevel(Level.OFF);
            break;
          case 5:
          default:
            rootLogger.setLevel(Level.FINE);
            break;
          case 6:
            rootLogger.setLevel(Level.ALL);
            break;
        }
      }

      String[] cl_args = cli.getArgs();

      if (cl_args.length < 1)
      {
        System.err.println("error: must specify a zone file");
        usage();
      }

      file = cl_args[0];
    }

    /**
     * Set up the command line options.
     * 
     * @return a set of command line options.
     */
    private void setupCLI()
    {
      opts = new org.apache.commons.cli.Options();

      // boolean options
      opts.addOption("h", "help", false, "Print this message.");
      opts.addOption("m", "multiline", false, "Use a multiline format");

      // Argument options
      OptionBuilder.hasOptionalArg();
      OptionBuilder.withLongOpt("verbose");
      OptionBuilder.withArgName("level");
      OptionBuilder.withDescription("verbosity level -- 0 is silence, "
          + "5 is debug information, 6 is trace information.\n"
          + "default is level 5.");
      opts.addOption(OptionBuilder.create('v'));
    }

    /** Print out the usage and help statements, then quit. */
    public void usage()
    {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out, 75, "jdnssec-zoneformat [..options..] zonefile", null,
                  opts, HelpFormatter.DEFAULT_LEFT_PAD,
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

  private static List readZoneFile(String filename) throws IOException
  {
    Master master = new Master(filename);

    List res = new ArrayList();
    Record r = null;

    while ((r = master.nextRecord()) != null)
    {
      // Normalize each record by round-tripping it through canonical wire line
      // format. Mostly this just lowercases names that are subject to it.
      byte[] wire = r.toWireCanonical();
      Record canon_record = Record.fromWire(wire, Section.ANSWER);
      res.add(canon_record);
    }

    return res;
  }

  private static void formatZone(List zone)
  {
    // Put the zone into a consistent (name and RR type) order.
    RecordComparator cmp = new RecordComparator();

    Collections.sort(zone, cmp);

    for (Iterator i = zone.iterator(); i.hasNext();)
    {
      Record r = (Record) i.next();
      System.out.println(r.toString());
    }
  }

  private static void execute(CLIState state) throws IOException
  {
    List z = readZoneFile(state.file);
    formatZone(z);
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

    // log = Logger.getLogger(VerifyZone.class.toString());

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
