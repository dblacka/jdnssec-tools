package com.verisignlabs.dnssec.cl;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.TimeZone;

import com.verisignlabs.dnssec.security.DnsKeyAlgorithm;

public class Utils {

    private Utils() {
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
     * Parse a DNSSEC algorithm number of mnemonic into the official algorithm number.
     * @param s The arge value
     * @return A DNSSEC algorithm number, or -1 if unrecognized.
     */
    public static int parseAlg(String s) {
        DnsKeyAlgorithm algs = DnsKeyAlgorithm.getInstance();

        int alg = Utils.parseInt(s, -1);
        if (alg > 0) {
            if (algs.supportedAlgorithm(alg))
                return alg;
            return -1;
        }

        return algs.stringToAlgorithm(s);
    }

    /**
     * Calculate a date/time from a command line time/offset duration string.
     *
     * @param start    the start time to calculate offsets from.
     * @param duration the time/offset string to parse.
     * @return the calculated time.
     */
    public static Instant convertDuration(Instant start, String duration) throws java.text.ParseException {
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
        Date parsedDate = dateFormatter.parse(duration);
        return parsedDate.toInstant();
    }

}
