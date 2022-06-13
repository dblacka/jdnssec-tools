// Copyright (C) 2011, 2022 VeriSign, Inc.
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.xbill.DNS.Master;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base32;

import com.verisignlabs.dnssec.security.RecordComparator;

/**
 * This class forms the command line implementation of a zone file normalizer.
 * That is, a tool to rewrite zones in a consistent, comparable format.
 *
 * @author David Blacka
 */
public class ZoneFormat extends CLBase {
  private CLIState state;

  /**
   * This is a small inner class used to hold all of the command line option
   * state.
   */
  protected static class CLIState extends CLIStateBase {
    public String file;
    public boolean assignNSEC3;

    public CLIState() {
      super("jdnssec-zoneformat [..options..] zonefile");
    }

    @Override
    protected void setupOptions(Options opts) {
      opts.addOption("N", "nsec3", false,
          "attempt to determine the original ownernames for NSEC3 RRs.");
    }

    @Override
    protected void processOptions(CommandLine cli) throws ParseException {
      if (cli.hasOption('N'))
        assignNSEC3 = true;

      String[] args = cli.getArgs();

      if (args.length < 1) {
        System.err.println("error: must specify a zone file");
        usage();
      }

      file = args[0];
    }
  }

  private static List<Record> readZoneFile(String filename) throws IOException {
    try (Master master = new Master(filename)) {
      List<Record> res = new ArrayList<>();
      Record r = null;

      while ((r = master.nextRecord()) != null) {
        // Normalize each record by round-tripping it through canonical wire line
        // format. Mostly this just lowercases names that are subject to it.
        byte[] wire = r.toWireCanonical();
        Record canonRec = Record.fromWire(wire, Section.ANSWER);
        res.add(canonRec);
      }

      return res;
    }
  }

  private static void formatZone(List<Record> zone) {


    for (Record r : zone) {
      System.out.println(r.toString());
    }
  }

  private static void determineNSEC3Owners(List<Record> zone)
      throws NoSuchAlgorithmException {

    // first, find the NSEC3PARAM record -- this is an inefficient linear
    // search, although it should be near the head of the list.
    NSEC3PARAMRecord nsec3param = null;
    HashMap<String, String> map = new HashMap<>();
    base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, true);
    Name zonename = null;

    for (Record r : zone) {
      if (r.getType() == Type.SOA) {
        zonename = r.getName();
        continue;
      }

      if (r.getType() == Type.NSEC3PARAM) {
        nsec3param = (NSEC3PARAMRecord) r;
        break;
      }
    }

    // If we couldn't determine a zone name, we have an issue.
    if (zonename == null || nsec3param == null) {
      formatZone(zone);
      return;
    }

    // Next pass, calculate a mapping between ownernames and hashnames
    Name lastName = null;
    for (Record r : zone) {
      if (r.getName().equals(lastName))
        continue;
      if (r.getType() == Type.NSEC3)
        continue;

      Name n = r.getName();
      byte[] hash = nsec3param.hashName(n);
      String hashname = b32.toString(hash);
      map.put(hashname, n.toString().toLowerCase());
      lastName = n;

      // inefficiently create hashes for the possible ancestor ENTs
      for (int i = zonename.labels() + 1; i < n.labels(); ++i) {
        Name parent = new Name(n, n.labels() - i);
        byte[] parentHash = nsec3param.hashName(parent);
        String parentHashName = b32.toString(parentHash);
        if (!map.containsKey(parentHashName)) {
          map.put(parentHashName, parent.toString().toLowerCase());
        }
      }
    }

    // Final pass, output the zone with added comments for the NSEC3 records
    for (Record r : zone) {
      if (r.getType() != Type.NSEC3) {
        System.out.println(r.toString());
        continue;
      }

      NSEC3Record nsec3 = (NSEC3Record) r;
      String hashname = nsec3.getName().getLabelString(0).toLowerCase();
      String ownername = map.get(hashname);
      System.out.println(r.toString() + " ; " + ownername);
    }
  }

  public void execute() throws IOException, NoSuchAlgorithmException {
    List<Record> z = readZoneFile(state.file);
    // Put the zone into a consistent (name and RR type) order.
    Collections.sort(z, new RecordComparator());

    if (state.assignNSEC3) {
      determineNSEC3Owners(z);
    } else {
      formatZone(z);
    }
  }

  public static void main(String[] args) {
    ZoneFormat tool = new ZoneFormat();
    tool.state = new CLIState();

    tool.run(tool.state, args);
  }

}
