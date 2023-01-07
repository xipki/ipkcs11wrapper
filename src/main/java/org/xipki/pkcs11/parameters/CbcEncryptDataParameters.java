// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.xipki.pkcs11.parameters;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters CBC key derivation algorithms.
 *
 * @author Karl Scheibelhofer
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
  public String toString() {
    return "Class: " + getClass().getName() +
        "\n  IV: 0x" + Functions.toHex(iv) + "\n  Data: 0x" + Functions.toHex(data);
  }

}
