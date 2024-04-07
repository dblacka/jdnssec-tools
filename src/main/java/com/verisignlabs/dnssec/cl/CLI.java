package com.verisignlabs.dnssec.cl;

public class CLI {
    private SubCommandType subCommand = null;
    private String[] subCommandArgs = null;
    private String commandSetStr = null;

    enum SubCommandType {
        DSTOOL, KEYGEN, KEYINFO, SIGNKEYSET, SIGNRRSET, SIGNZONE, VERIFYZONE, ZONEFORMAT;
    }

    public CLI(String name, String usageStr) {
        StringBuilder sb = new StringBuilder();
        for (SubCommandType type : SubCommandType.class.getEnumConstants()) {
            sb.append(type.toString().toLowerCase());
            sb.append(" ");
        }
        commandSetStr = sb.toString().trim();
    }

    private void fail(String errorMessage){
        System.err.println("ERROR: " + errorMessage);
        System.exit(2);
    }

    public void run(String[] args) {
        if (args.length < 1) {
            fail("missing command: must be one of: " + commandSetStr);
        }

        String command = args[0];
        if (command.equals("-h")) {
            System.err.println("usage: jdnssec-tools <command> <command args..>");
            System.err.println("  <command> is one of: " + commandSetStr);
            System.exit(0);
        }

        try {
            subCommand = SubCommandType.valueOf(command.toUpperCase());
        } catch (IllegalArgumentException e) {
            fail("unrecognized command '" + command + "': must be one of: " + commandSetStr);
        }
        subCommandArgs = new String[args.length - 1];
        System.arraycopy(args, 1, subCommandArgs, 0, args.length - 1);

        CLBase cmd = null;

        switch(subCommand) {
            case DSTOOL:
                cmd = new DSTool("dstool", "jdnssec-tools dstool [..options..] keyfile [keyfile..]");
                break;
            case KEYGEN:
                cmd = new KeyGen("keygen", "jdnssec-tools keygen [..options..] zonename");
                break;
            case KEYINFO:
                cmd = new KeyInfoTool("keyinfotool", "jdnssec-tools keyinfo [..options..] keyfile");
                break;
            case SIGNKEYSET:
                cmd = new SignKeyset("signkeyset", "jdnssec-tools signkeyset [..options..] dnskeyset_file [key_file ...]");
                break;
            case SIGNRRSET:
                cmd = new SignRRset("signrrset", "jdnssec-tools signrrset [..options..] rrset_file key_file [key_file ...]");
                break;
            case SIGNZONE:
                cmd = new SignZone("signzone", "jdnssec-tools signzone [..options..] zone_file [key_file ...]");
                break;
            case VERIFYZONE:
                cmd = new VerifyZone("verifyzone", "jdnssec-tools verifyzone [..options..] zonefile");
                break;
            case ZONEFORMAT:
                cmd = new ZoneFormat("zoneformat", "jdnssec-tools zoneformat [..options..] zonefile");
                break;
            default:
                fail("commmand " + command + " has not been implemented.");
                break;
        }
        cmd.run(subCommandArgs);
    }

    public static void main(String[] args) {
        CLI cli = new CLI("cli", "jdnssec-tools <command> [..args..]");
        cli.run(args);
      }
}
