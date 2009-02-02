/*************************************************************************
 * SHA256
 *
 * a homebrew of the SHA256 algorithm for dnsjava.  Some of the concepts 
 * are taken from the Cryptix crypto provider: http://www.cryptix.org
 *
 * Scott Rose
 * NIST
 * 04/16/04
 *************************************************************************/

package com.verisignlabs.dnssec.security;

import java.io.ByteArrayOutputStream;

public class SHA256
{
  private int Ch(int a, int b, int c)
  {
    return (a & b) ^ (~a & c);
  }

  private int Maj(int a, int b, int c)
  {
    return (a & b) ^ (a & c) ^ (b & c);
  }

  private int SHR(int x, int n)
  {
    return (x >>> n);
  }

  private int ROTR(int x, int n)
  {
    return ((x >>> n) | (x << (32 - n)));
  }

  private int SIG0(int x)
  {
    return (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22));
  }

  private int SIG1(int x)
  {
    return (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25));
  }

  private int sig0(int x)
  {
    return (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3));
  }

  private int sig1(int x)
  {
    return (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10));
  }

  // Constants "K"
  private static final int K[]      = { 0x428a2f98, 0x71374491, 0xb5c0fbcf,
      0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
      0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
      0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
      0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
      0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c,
      0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
      0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2                   };

  private int              digest[] = new int[8];
  private byte             data[];

  public SHA256()
  {

  }

  public void init()
  {
    digest[0] = 0x6a09e667;
    digest[1] = 0xbb67ae85;
    digest[2] = 0x3c6ef372;
    digest[3] = 0xa54ff53a;
    digest[4] = 0x510e527f;
    digest[5] = 0x9b05688c;
    digest[6] = 0x1f83d9ab;
    digest[7] = 0x5be0cd19;
  }

  public void setData(byte input[])
  {
    // clone the array
    data = doDataPad(input);
  }

  private byte[] doDataPad(byte input[])
  {
    int n, fill;

    n = input.length + 9;
    if (input.length < 55)
    {
      fill = 64 - n;
    }
    else
    {
      fill = 64 - (n % 64);
    }

    if ((input.length % 64) != 0)
    {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(input, 0, input.length);
      out.write(0x80);
      for (int i = 0; i < fill; i++)
        out.write(0x00);

      long l = input.length * 8; // length is measured in bits
      out.write((int) (l >>> 56) & 0xFF);
      out.write((int) (l >>> 48) & 0xFF);
      out.write((int) (l >>> 40) & 0xFF);
      out.write((int) (l >>> 32) & 0xFF);
      out.write((int) (l >>> 24) & 0xFF);
      out.write((int) (l >>> 16) & 0xFF);
      out.write((int) (l >>> 8) & 0xFF);
      out.write((int) l & 0xFF);
      // we are replacing data here with a new padded version

      return out.toByteArray();
    }
    return input;
  }

  /*
   * utility method to convert a byte input array to an int[] for easier
   * processing. Also does the padding as necessary
   */
  private int[] convertToInt(byte block[])
  {
    int output[] = new int[16];

    int w = -1;
    for (int i = 0; i < 16; i++)
    {
      output[i] = (block[++w] << 24) | ((block[++w] & 0xFF) << 16)
          | ((block[++w] & 0xFF) << 8) | (block[++w] & 0xFF);
    }

    return output;
  }

  /*
   * method called to get the SHA1 digest of the input
   */
  public byte[] getDigest()
  {
    byte output[] = new byte[32];
    int aBlock[];
    byte byteBlock[];

    // for (int n = 0; n < data.length; n++)
    // {
    // System.out.print(Integer.toHexString(data[n]) + " ");
    // }
    // System.out.println("\n\n");
    if (data.length > 64)
    {
      int n = data.length / 64;
      int place = 0;
      for (int i = 0; i < n; i++)
      {
        byteBlock = new byte[64];
        for (int x = 0; x < 64; x++)
        {
          byteBlock[x] = data[place++];
        }
        aBlock = convertToInt(byteBlock);
        transform(aBlock);
      }
    }
    else
    {
      aBlock = convertToInt(data);
      transform(aBlock);
    }

    // convert the int array back to byte and return
    int out = -1;
    for (int i = 0; i < 8; i++)
    {
      output[++out] = (byte) ((digest[i] >>> 24) & 0xFF);
      output[++out] = (byte) ((digest[i] >>> 16) & 0xFF);
      output[++out] = (byte) ((digest[i] >>> 8) & 0xFF);
      output[++out] = (byte) (digest[i] & 0xFF);
    }

    return output;
  }

  /*
   * this is the method that actually performs the digest and returns the result
   */
  private void transform(int block[])
  {

    // first, break into blocks and process one by one

    int A = digest[0];
    int B = digest[1];
    int C = digest[2];
    int D = digest[3];
    int E = digest[4];
    int F = digest[5];
    int G = digest[6];
    int H = digest[7];

    // doing the message schedule
    int W[] = new int[64];
    for (int i = 0; i < 16; i++)
    {
      W[i] = block[i];
      // System.out.println("W: " + Integer.toHexString(W[i]) + "\n");
    }
    for (int i = 16; i < 64; i++)
    {
      W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];
    }

    for (int t = 0; t < 64; t++)
    {
      int T1 = H + SIG1(E) + Ch(E, F, G) + K[t] + W[t];
      int T2 = SIG0(A) + Maj(A, B, C);
      H = G;
      G = F;
      F = E;
      E = D + T1;
      D = C;
      C = B;
      B = A;
      A = T1 + T2;

      // System.out.println("A: " + Integer.toHexString(A));
      // System.out.println("B: " + Integer.toHexString(B));
      // System.out.println("C: " + Integer.toHexString(C));
      // System.out.println("D: " + Integer.toHexString(D));
      // System.out.println("E: " + Integer.toHexString(E));
      // System.out.println("F: " + Integer.toHexString(F));
      // System.out.println("G: " + Integer.toHexString(G));
      // System.out.println("H: " + Integer.toHexString(H) + "\n");

    }

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
    digest[6] += F;
    digest[7] += G;

  }

  public static void main(String argv[])
  {
    String data1 = "abc";
    SHA256 sha = new SHA256();
    byte output[];

    sha.init();
    System.out.println("ready to set the data");
    sha.setData(data1.getBytes());
    System.out.println("ready to get the digest");
    output = sha.getDigest();

    for (int i = 0; i < output.length; i++)
    {
      // Integer b = new Integer((int)output[i]);
      System.out.print(Integer.toHexString(output[i]) + " ");
    }
  }

}
