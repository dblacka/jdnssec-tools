package com.verisignlabs.dnssec.security;

import java.util.logging.LogRecord;

/**
 * This is a very simple log formatter that simply outputs the log level and log
 * string.
 */
public class BareLogFormatter extends java.util.logging.Formatter
{
  @Override
  public String format(LogRecord arg0)
  {
    StringBuilder out = new StringBuilder();
    String lvl = arg0.getLevel().getName();

    out.append(lvl);
    out.append(": ");
    out.append(arg0.getMessage());
    out.append("\n");

    return out.toString();
  }
}