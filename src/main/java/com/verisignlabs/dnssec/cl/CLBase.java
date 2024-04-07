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
import java.util.Properties;
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
  protected Logger log = Logger.getLogger(this.getClass().toString());
  protected Options opts;
  protected String name;
  protected String usageStr;
  protected Properties props;
  protected CommandLine cli;

  protected CLBase(String name, String usageStr) {
    this.name = name;
    this.usageStr = usageStr;

    setup();
  }

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

  /** This is the base set of command line options provided to all subclasses. */
  private void setupCommonOptions() {
    // Set up the standard set of options that all jdnssec command line tools will
    // implement.

    // boolean options
    opts.addOption("h", "help", false, "Print this message.");
    opts.addOption("m", "multiline", false,
        "Output DNS records using 'multiline' format");

    opts.addOption(Option.builder("l").longOpt("log-level").argName("level").hasArg()
        .desc("set the logging level with either java.util.logging levels, or 0-6").build());
    opts.addOption(Option.builder("v").longOpt("verbose").desc(
        "set as verbose (log-level = fine)").build());

    opts.addOption(Option.builder("c").longOpt("config").argName("file").hasArg()
        .desc("configuration file (format: java properties)").build());

    opts.addOption(Option.builder("A").hasArg().argName("alias:original:mnemonic").longOpt("alg-alias")
        .desc("Define an alias for an algorithm").build());
  }

  /**
   * This is an overridable method for subclasses to add their own command line
   * options.
   */
  protected abstract void setupOptions();

  /**
   * Initialize the command line options
   */
  public void setup() {
    opts = new Options();
    setupCommonOptions();
    setupOptions();
  }

  /**
   * This is the main method for parsing the command line arguments. Subclasses
   * generally override processOptions() rather than this method. This method
   * creates the parsing objects and processes the common options.
   * 
   * @param args The command line arguments.
   */
  public void parseCommandLine(String[] args) {
    String[] logLevelOptionKeys = { "log_level", "log-level" };
    String[] multilineOptionKeys = { "multiline" };
    CommandLineParser parser = new DefaultParser();

    try {
      cli = parser.parse(opts, args);
    } catch (UnrecognizedOptionException e) {
      System.err.println("error: unknown option encountered: " + e.getMessage());
      usage(true);
    } catch (AlreadySelectedException e) {
      System.err.println("error: mutually exclusive options have "
          + "been selected:\n     " + e.getMessage());
      usage(true);
    } catch (ParseException e) {
      System.err.println("Unable to parse command line: " + e);
      usage(true);
    }

    if (cli.hasOption('h')) {
      usage(false);
    }

    String loadedConfig = loadConfig(cli.getOptionValue('c'));

    Logger rootLogger = Logger.getLogger("");

    // we set log level with both --log-level and -v/--verbose.
    String logLevel = cliOption("log-level", logLevelOptionKeys, null);
    if (logLevel == null) {
      logLevel = cli.hasOption("v") ? "fine" : "warning";
    }
    if (logLevel != null) {
      setLogLevel(rootLogger, logLevel);
    }

    for (Handler h : rootLogger.getHandlers()) {
      h.setLevel(rootLogger.getLevel());
      h.setFormatter(new BareLogFormatter());
    }

    if (loadedConfig != null) {
      log.info("Loaded config file: " + loadedConfig);
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
  protected abstract void processOptions();

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
    // Do not load config files twice
    if (props != null) {
      return null;
    }
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
        log.warning("Could not read config file " + f.getName() + ": " + e);
      }
    }

    if (f != null) {
      return f.getPath();
    }
    return null;
  }

  /** Print out the usage and help statements, then quit. */
  public void usage(boolean isError) {
    HelpFormatter f = new HelpFormatter();

    PrintWriter out = new PrintWriter(System.err);

    // print our own usage statement:
    f.printHelp(out, 120, usageStr, null, opts, HelpFormatter.DEFAULT_LEFT_PAD,
        HelpFormatter.DEFAULT_DESC_PAD, null);

    out.flush();
    if (isError) {
      System.exit(64);
    }
    System.exit(0);

  }

  /**
   * Set the logging level based on a string value
   *
   * @param logger   The logger to set -- usually the rootLogger
   * @param levelStr A level string that is either an integer from 0 to 6, or a
   *                 java.util.logging log level string (severe, warning, info,
   *                 fine, finer,
   *                 finest).
   */
  private void setLogLevel(Logger logger, String levelStr) {
    Level level;
    int internalLogLevel = Utils.parseInt(levelStr, -1);
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
        int aliasAlg = Utils.parseInt(valueComponents[0], -1);
        int origAlg = Utils.parseInt(valueComponents[1], -1);
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
        int origAlg = Utils.parseInt(valueComponents[0], -1);
        int aliasAlg = Utils.parseInt(valueComponents[1], -1);

        if (mnemonic != null && origAlg >= 0 && aliasAlg >= 0) {
          algs.addAlias(aliasAlg, mnemonic, origAlg);
        }
      }
    }
  }

  /**
   * Given a parsed command line, option, and list of possible config
   * properties, and a default value, determine value for the option
   *
   * @param option       The option name
   * @param properties   A list of configuration parameters that we would like
   *                     to use for this option, from most preferred to least.
   * @param defaultValue A default value to return if either the option or
   *                     config value cannot be parsed, or neither are present.
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

  /**
   * Given a parsed command line, option, and list of possible config
   * properties, determine the value for the option, converting the value to
   * long.
   */
  protected long cliLongOption(String option, String[] properties, long defaultValue) {
    String value = cliOption(option, properties, Long.toString(defaultValue));
    return Utils.parseLong(value, defaultValue);
  }

  /**
   * Given a parsed command line, option, and list of possible config
   * properties, determine the value for the option, converting the value to
   * int.
   */
  protected int cliIntOption(String option, String[] properties, int defaultValue) {
    String value = cliOption(option, properties, Integer.toString(defaultValue));
    return Utils.parseInt(value, defaultValue);
  }

  /**
   * Given a parsed command line, option, and list of possible config
   * properties, determine the value for the option, converting the value to
   * a boolean.
   */
  protected boolean cliBooleanOption(String option, String[] properties, boolean defaultValue) {
    String value = cliOption(option, properties, Boolean.toString(defaultValue));
    return Boolean.parseBoolean(value);
  }

  public abstract void execute() throws Exception;

  public void run(String[] args) {

    parseCommandLine(args);
    log = Logger.getLogger(this.getClass().toString());

    try {
      execute();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
