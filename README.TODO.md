# jdnssec-tools TODO List

This bit of code has been around since approximately 2005, and has been in "minimal maintenance" mode for much of that time.  But that doesn't mean there aren't features that we *want* to do, if we could arrange time and attention.  Here is a partial list:

* More feature parity with the current BIND 9 tools
  * Support the "v1.3" private key format.  This basically means supporting the timing parameters that BiND 9 added.
  * Have `jdnssec-signzone` support incremental signing, including key rollovers
* Rewrite `jdnssec-signzone` to use a "TreeMap" and arrange the data into a map of RRsets, rather than a sorted list of Record objects.  This wouldn't be more efficient, but might be easier to understand.
* Allow `jdnssec-signzone` to scale by either:
  * Allowing for pre-sorted zone data, and/or
  * allowing for an external sort once the data is shown to be larger than X, and/or
  * allowing for a memory-constrained internal sort that uses disk, and/or,
  * figuring out how to let the JVM use *a lot* of memory.
