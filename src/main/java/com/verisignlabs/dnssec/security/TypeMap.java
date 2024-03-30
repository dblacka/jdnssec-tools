// Copyright (C) 2004, 2022 Verisign, Inc.
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
package com.verisignlabs.dnssec.security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.xbill.DNS.DNSOutput;
import org.xbill.DNS.Type;

/**
 * This class represents the multiple type maps of the NSEC record. Currently it
 * is just used to convert the wire format type map to the int array that
 * org.xbill.DNS.NSECRecord uses. Note that there is now a very similar class in
 * DNSjava: {@link org.xbill.DNS.TypeBitmap}.
 */

public class TypeMap {
  private static final Integer[] integerArray = new Integer[0];
  private static final byte[] emptyBitmap = new byte[0];

  private Set<Integer> typeSet;

  public TypeMap() {
    this.typeSet = new HashSet<>();
  }

  /** Add the given type to the typemap. */
  public void set(int type) {
    typeSet.add(type);
  }

  /** Remove the given type from the type map. */
  public void clear(int type) {
    typeSet.remove(type);
  }

  /** @return true if the given type is present in the type map. */
  public boolean get(int type) {
    return typeSet.contains(type);
  }

  /**
   * Given an array of DNS type code, construct a TypeMap object.
   */
  public static TypeMap fromTypes(int[] types) {
    TypeMap m = new TypeMap();
    if (types == null)
      return m;
    for (int i = 0; i < types.length; i++) {
      m.set(types[i]);
    }

    return m;
  }

  /**
   * Given an array of bytes representing a wire-format type map, construct the
   * TypeMap object.
   */
  public static TypeMap fromBytes(byte[] map) {
    int m = 0;
    TypeMap typemap = new TypeMap();

    int page;
    int byteLength;

    while (m < map.length) {
      page = map[m++];
      byteLength = map[m++];

      for (int i = 0; i < byteLength; i++) {
        for (int j = 0; j < 8; j++) {
          if (((map[m + i] & 0xFF) & (1 << (7 - j))) != 0) {
            typemap.set((page << 8) + (i * 8) + j);
          }
        }
      }
      m += byteLength;
    }

    return typemap;
  }

  /**
   * Given list of type mnemonics, construct a TypeMap object.
   */
  public static TypeMap fromString(String types) {
    TypeMap typemap = new TypeMap();

    for (String type : types.split("\\s+")) {
      typemap.set(Type.value(type));
    }

    return typemap;
  }

  /** @return the normal string representation of the typemap. */
  public String toString() {
    int[] types = getTypes();
    Arrays.sort(types);

    StringBuilder sb = new StringBuilder();

    for (int i = 0; i < types.length; i++) {
      if (i > 0)
        sb.append(" ");
      sb.append(Type.string(types[i]));
    }

    return sb.toString();
  }

  protected static void mapToWire(DNSOutput out, int[] types, int base, int start, int end) {
    // calculate the length of this map by looking at the largest
    // typecode in this section.
    int maxType = types[end - 1] & 0xFF;
    int mapLength = (maxType / 8) + 1;

    // write the map "header" -- the base and the length of the map.
    out.writeU8(base & 0xFF);
    out.writeU8(mapLength & 0xFF);

    // allocate a temporary scratch space for caculating the actual
    // bitmap.
    byte[] map = new byte[mapLength];

    // for each type in our sub-array, set its corresponding bit in the map.
    for (int i = start; i < end; i++) {
      map[(types[i] & 0xFF) / 8] |= (1 << (7 - types[i] % 8));
    }
    // write out the resulting binary bitmap.
    for (int i = 0; i < map.length; i++) {
      out.writeU8(map[i]);
    }
  }

  public byte[] toWire() {
    int[] types = getTypes();

    if (types.length == 0)
      return emptyBitmap;

    Arrays.sort(types);

    int mapbase = -1;
    int mapstart = -1;

    DNSOutput out = new DNSOutput();

    for (int i = 0; i < types.length; i++) {
      int base = (types[i] >> 8) & 0xFF;
      if (base == mapbase)
        continue;
      if (mapstart >= 0) {
        mapToWire(out, types, mapbase, mapstart, i);
      }
      mapbase = base;
      mapstart = i;
    }
    mapToWire(out, types, mapbase, mapstart, types.length);

    return out.toByteArray();
  }

  public int[] getTypes() {
    Integer[] a = typeSet.toArray(integerArray);

    int[] res = new int[a.length];
    for (int i = 0; i < res.length; i++) {
      res[i] = a[i].intValue();
    }

    return res;
  }

  public static int[] fromWireToTypes(byte[] wireFmt) {
    return TypeMap.fromBytes(wireFmt).getTypes();
  }

  public static byte[] fromTypesToWire(int[] types) {
    return TypeMap.fromTypes(types).toWire();
  }

}
