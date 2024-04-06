// Copyright (C) 2022 Verisign, Inc.
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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.Properties;
import java.util.TimeZone;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.apache.commons.cli.AlreadySelectedException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.UnrecognizedOptionException;

import com.verisignlabs.dnssec.security.DnsKeyAlgorithm;

/**
 * This is a base class for jdnssec command line tools. Each command line tool
 * should inherit from this class, create a subclass of CLIStateBase (overriding
 * setupOptions and processOptions), and implement the execute() method.
 * Subclasses also have their own main() methods, which should just create the
 * subclass variant of the CLIState and call run().
 */
public abstract class CLBase {
  protected static Logger staticLog = Logger.getLogger(CLBase.class.getName());
  protected Logger log;

  /**
   * This is a very simple log formatter that simply outputs the log level and
   * log string.
   */
  public static class BareLogFormatter extends Formatter {

    public String format(LogRecord arg0) {
      StringBuilder out = new StringBuilder();
      String lvl = arg0.getLevel().getName();

      out.append(lvl);
      out.append(": ");
      out.append(arg0.getMessage());
      out.append("\n");

      return out.toString();
    }
  }

  /**
   * This is a base class for command line parsing state. Subclasses should
   * override setupOptions and processOptions.
   */
  public static class CLIStateBase {
    protected Options opts;
    protected String name;
    protected String usageStr;
    protected Properties props;
    protected CommandLine cli;

    /**
     * The base constructor. This will setup the command line options.
     *
     * @param usage
     *              The command line usage string (e.g.,
     *              "jdnssec-foo [..options..] zonefile")
     */
    public CLIStateBase(String name, String usage) {
      this.name = name;
      usageStr = usage;
      setup();
    }

    /** This is the base set of command line options provided to all subclasses. */
    private void setup() {
      // Set up the standard set of options that all jdnssec command line tools will
      // implement.
      opts = new Options();

      // boolean options
      opts.addOption("h", "help", false, "Print this message.");
      opts.addOption("m", "multiline", false,
          "Output DNS records using 'multiline' format");

      opts.addOption(Option.builder("v").longOpt("verbose").argName("level").hasArg().desc(
          "verbosity level -- 0: silence, 1: error, 2: warning, 3: info, 4/5: fine, 6: finest; default: 2 (warning)")
          .build());

      opts.addOption(Option.builder("c").longOpt("config").argName("file").hasArg()
          .desc("configuration file (format: java properties)").build());

      opts.addOption(Option.builder("A").hasArg().argName("alias:original:mnemonic").longOpt("alg-alias")
          .desc("Define an alias for an algorithm").build());

      setupOptions(opts);
    }

    /**
     * This is an overridable method for subclasses to add their own command
     * line options.
     *
     * @param opts
     *             the options object to add (via OptionBuilder, typically) new
     *             options to.
     */
    protected void setupOptions(Options opts) {
      // Subclasses generally override this.
    }

    /**
     * This is the main method for parsing the command line arguments.
     * Subclasses generally override processOptions() rather than this method.
     * This method creates the parsing objects and processes the common
     * options.
     *
     * @param args The command line arguments.
     * @throws ParseException
     */
    public void parseCommandLine(String[] args) throws ParseException {
      String[] verboseOptionKeys = { "log_level", "verbose" };
      String[] multilineOptionKeys = { "multiline" };
      CommandLineParser parser = new DefaultParser();
      cli = parser.parse(opts, args);

      if (cli.hasOption('h')) {
        usage();
      }

      String loadedConfig = loadConfig(cli.getOptionValue('c'));

      Logger rootLogger = Logger.getLogger("");
      String logLevel = cliOption("v", verboseOptionKeys, null);
      if (logLevel != null) {
        setLogLevel(rootLogger, logLevel);
      }

      for (Handler h : rootLogger.getHandlers()) {
        h.setLevel(rootLogger.getLevel());
        h.setFormatter(new BareLogFormatter());
      }

      if (loadedConfig != null) {
        staticLog.info("Loaded config file: " + loadedConfig);
      }

      if (cliBooleanOption("m", multilineOptionKeys, false)) {
        org.xbill.DNS.Options.set("multiline");
      }

      processAliasOptions();

      processOptions();
    }

    /**
     * Process additional tool-specific options. Subclasses generally override
     * this.
     */
    protected void processOptions() throws ParseException {
      // Subclasses generally override this.
    }

    /**
     * Load a configuration (java properties) file for jdnssec-tools. Returns
     * the path of the loaded file.
     * 
     * @param configFile a given path to a config file. This will be considered
     *                   first.
     * @return The path of the file that was actually loaded, or null if no config
     *         file was loaded.
     */
    protected String loadConfig(String configFile) {
      props = new Properties();
      String[] configFiles = { configFile, "jdnssec-tools.properties", ".jdnssec-tools.properties",
          System.getProperty("user.home") + "/.jdnssec-tools.properties" };

      File f = null;

      for (String fname : configFiles) {
        if (fname == null) {
          continue;
        }
        f = new File(fname);
        if (!f.canRead()) {
          continue;
        }

        try (FileInputStream stream = new FileInputStream(f)) {
          props.load(stream);
          break; // load the first config file found in our list
        } catch (IOException e) {
          staticLog.warning("Could not read config file " + f.getName() + ": " + e);
        }
      }

      if (f != null) {
        return f.getPath();
      }
      return null;
    }

    /** Print out the usage and help statements, then quit. */
    public void usage() {
      HelpFormatter f = new HelpFormatter();

      PrintWriter out = new PrintWriter(System.err);

      // print our own usage statement:
      f.printHelp(out, 75, usageStr, null, opts, HelpFormatter.DEFAULT_LEFT_PAD,
          HelpFormatter.DEFAULT_DESC_PAD, null);

      out.flush();
      System.exit(64);

    }

    private void setLogLevel(Logger logger, String levelStr) {
      Level level;
      int internalLogLevel = parseInt(levelStr, -1);
      if (internalLogLevel != -1) {
        switch (internalLogLevel) {
          case 0:
            level = Level.OFF;
            break;
          case 1:
            level = Level.SEVERE;
            break;
          case 2:
          default:
            level = Level.WARNING;
            break;
          case 3:
            level = Level.INFO;
            break;
          case 4:
            level = Level.FINE;
            break;
          case 5:
          case 6:
            level = Level.ALL;
        }
      } else {
        try {
          level = Level.parse(levelStr.toUpperCase());
        } catch (IllegalArgumentException e) {
          System.err.println("Verbosity level '" + levelStr + "' not recognized");
          level = Level.WARNING;
        }
      }
      logger.setLevel(level);
    }

    /**
     * Process both property file based alias definitions and command line alias
     * definitions
     */
    protected void processAliasOptions() {
      DnsKeyAlgorithm algs = DnsKeyAlgorithm.getInstance();
      // First parse any command line options
      // those look like '-A <alias-num>:<orig-num>:<mnemonic>', e.g., '-A
      // 21:13:ECDSAP256-NSEC6'
      String[] optstrs = null;
      if ((optstrs = cli.getOptionValues('A')) != null) {
        for (String value : optstrs) {
          String[] valueComponents = value.split(":");
          int aliasAlg = parseInt(valueComponents[0], -1);
          int origAlg = parseInt(valueComponents[1], -1);
          String mnemonic = valueComponents[2];

          if (mnemonic != null && origAlg >= 0 && aliasAlg >= 0) {
            algs.addAlias(aliasAlg, mnemonic, origAlg);
          }
        }
      }

      // Next see if we have any alias options in properties
      // Those look like 'signzone.alias.<alias-mnemonic> =
      // <orig-alg-num>:<alias-alg-num>'
      for (String key : props.stringPropertyNames()) {
        if (key.startsWith(name + ".alias.") || key.startsWith("alias.")) {
          String[] keyComponents = key.split("\\.");
          String mnemonic = keyComponents[keyComponents.length - 1];
          String[] valueComponents = props.getProperty(key).split(":");
          int origAlg = parseInt(valueComponents[0], -1);
          int aliasAlg = parseInt(valueComponents[1], -1);

          if (mnemonic != null && origAlg >= 0 && aliasAlg >= 0) {
            algs.addAlias(aliasAlg, mnemonic, origAlg);
          }
        }
      }
    }

    /**
     * Given a parsed command line, and option, and list of possible config
     * properties, and a default value, determine value for the option
     *
     * @param option       The option name
     * @param properties   A list of configuration parameters that we would like
     *                     to use for this option, from most preferred to least.
     * @param defaultValue A default value to return if either the option or
     *                     config value cannot be parsed, or neither are
     *                     present.
     * @return The found value, or the default value.
     */
    protected String cliOption(String option, String[] properties, String defaultValue) {
      if (cli.hasOption(option)) {
        return cli.getOptionValue(option);
      }
      for (String property : properties) {
        // first look up the scoped version of the property
        String value = props.getProperty(name + "." + property);
        if (value != null) {
          return value;
        }
        value = props.getProperty(property);
        if (value != null) {
          return value;
        }
      }
      return defaultValue;
    }

    protected long cliLongOption(String option, String[] properties, long defaultValue) {
      String value = cliOption(option, properties, Long.toString(defaultValue));
      return parseLong(value, defaultValue);
    }

    protected int cliIntOption(String option, String[] properties, int defaultValue) {
      String value = cliOption(option, properties, Integer.toString(defaultValue));
      return parseInt(value, defaultValue);
    }

    protected boolean cliBooleanOption(String option, String[] properties, boolean defaultValue) {
      String value = cliOption(option, properties, Boolean.toString(defaultValue));
      return Boolean.parseBoolean(value);
    }
  }

  /**
   * Parse a string into an integer safely, using a default if the value does not
   * parse cleanly
   * 
   * @param s   The string to parse
   * @param def The default value
   * @return either the parsed int or the default
   */
  public static int parseInt(String s, int def) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      return def;
    }
  }

  /**
   * Parse a string into a long safely, using a default if the value does not
   * parse cleanly
   * 
   * @param s   The string to parse
   * @param def The default value
   * @return either the parsed long or the default
   */
  public static long parseLong(String s, long def) {
    try {
      return Long.parseLong(s);
    } catch (NumberFormatException e) {
      return def;
    }
  }

  /**
   * Calculate a date/time from a command line time/offset duration string.
   *
   * @param start    the start time to calculate offsets from.
   * @param duration the time/offset string to parse.
   * @return the calculated time.
   */
  public static Instant convertDuration(Instant start, String duration) throws ParseException {
    if (start == null) {
      start = Instant.now();
    }

    if (duration.startsWith("now")) {
      start = Instant.now();
      if (duration.indexOf("+") < 0)
        return start;

      duration = duration.substring(3);
    }

    if (duration.startsWith("+")) {
      long offset = parseLong(duration.substring(1), 0);
      return start.plusSeconds(offset);
    }

    // This is a heuristic to distinguish UNIX epoch times from the zone file
    // format standard (which is length == 14)
    if (duration.length() <= 10) {
      long epoch = parseLong(duration, 0);
      return Instant.ofEpochSecond(epoch);
    }

    SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMddHHmmss");
    dateFormatter.setTimeZone(TimeZone.getTimeZone("GMT"));
    try {
      Date parsedDate = dateFormatter.parse(duration);
      return parsedDate.toInstant();
    } catch (java.text.ParseException e) {
      throw new ParseException(e.getMessage());
    }
  }

  public abstract void execute() throws Exception;

  public void run(CLIStateBase state, String[] args) {
    try {
      state.parseCommandLine(args);
    } catch (UnrecognizedOptionException e) {
      System.err.println("error: unknown option encountered: " + e.getMessage());
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

    log = Logger.getLogger(this.getClass().toString());

    try {
      execute();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
