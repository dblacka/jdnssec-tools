# jdnssec-tools

* <https://github.com/dblacka/jdnssec-tools/wiki>

Author: David Blacka (davidb@verisign.com)

This is a collection of DNSSEC tools written in Java.  They are intended to be an addition or replacement for the DNSSEC tools that are part of BIND 9.

These tools depend upon DNSjava (<https://github.com/dnsjava/dnsjava>), the Jakarta Commons CLI and Logging libraries (<https://commons.apache.org/proper/commons-cli>), slf4j (<https://www.slf4j.org>), and Sun's Java Cryptography extensions.  A copy of each of these libraries is included in the distribution.

See the "licenses" directory for the licensing information of this package and the other packages that are distributed with it.

Getting started:

1. Unpack the binary distribution:

        tar zxvf java-dnssec-tools-x.x.x.tar.gz

2. Run the various tools from their unpacked location:

        cd java-dnssec-tools-x.x.x
        ./bin/jdnssec-signzone -h

Building from source:

1. Unpack the source distribution, preferably into the same directory that the binary distribution was unpacked.

        tar zxvf java-dnssec-tools-x.x.x-src.tar.gz

2. Edit the build.properties file to suit your environment.
3. Run Ant (see <http://ant.apache.org> for information about the Ant build tool).

        ant

4. You can build the distribution tarballs with 'ant dist'.  You can run the tools directly from the build area (without building the jdnssec-tools.jar file) by using the ./bin/\_jdnssec_* wrappers.

5. Alternatively, build the project using gradle:

        gradlew clean
        gradlew assemble -i

The resulting jar file gets generated in build/libs.

The source for this project is available in git on github: <https://github.com/dblacka/jdnssec-tools>

---

Questions or comments may be directed to the author (mailto:davidb@verisign.com), or by creating issues in the [github issue tracker](https://github.com/dblacka/jdnssec-tools/issues).
