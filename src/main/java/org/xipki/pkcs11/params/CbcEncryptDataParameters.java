// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters CBC key derivation algorithms.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public abstract class CbcEncryptDataParameters implements Parameters {

  /**
   * This is the block size in byte of the underlying cipher, e.g. 8 for DES and Triple DES and 16
   * for AES.
   */
  protected int blockSize;

  /**
   * The initialization vector for CBC mode of the cipher.
   */
  protected byte[] iv;

  /**
   * The data to be used in the key derivation. It must have a length that is a multiple of the
   * block-size of the underlying cipher.
   */
  protected byte[] data;

  /**
   * Create a new CbcEncryptDataParameters object with the given IV and data.
   *
   * @param blockSize
   *          The block size of the cipher.
   * @param iv
   *          The initialization vector whose length must be block size.
   * @param data
   *          The key derivation data whose length must be multiple of the block size.
   *
   */
  protected CbcEncryptDataParameters(int blockSize, byte[] iv, byte[] data) {
    this.iv = Functions.requireNonNull("iv", iv);
    Functions.requireAmong("iv.length", iv.length, blockSize);

    this.data = Functions.requireNonNull("data", data);

    if (data.length % blockSize != 0) {
      throw new IllegalArgumentException("Argument data must have a length that is a multiple of blockSize.");
    }
    this.blockSize = blockSize;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() +
        "\n  IV: 0x" + Functions.toHex(iv) + "\n  Data: 0x" + Functions.toHex(data);
  }

}
