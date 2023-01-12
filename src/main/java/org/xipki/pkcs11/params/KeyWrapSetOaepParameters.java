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

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_WRAP_SET_OAEP_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEY_WRAP_SET_OAEP.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class KeyWrapSetOaepParameters implements Parameters {

  /**
   * The block contents byte.
   */
  private byte blockContents;

  /**
   * The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  private byte[] x;

  /**
   * Create a new KEADeriveParameters object with the given attributes.
   *
   * @param blockContents
   *          The block contents byte.
   * @param x
   *          The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public KeyWrapSetOaepParameters(byte blockContents, byte[] x) {
    this.blockContents = blockContents;
    this.x = x;
  }

  /**
   * Get this parameters object as an object of the CK_KEY_WRAP_SET_OAEP_PARAMS class.
   *
   * @return This object as a CK_KEY_WRAP_SET_OAEP_PARAMS object.
   *
   */
  @Override
  public CK_KEY_WRAP_SET_OAEP_PARAMS getPKCS11ParamsObject() {
    CK_KEY_WRAP_SET_OAEP_PARAMS params = new CK_KEY_WRAP_SET_OAEP_PARAMS();

    params.bBC = blockContents;
    params.pX = x;

    return params;
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
        "\n  Block Contents Byte: 0x" + Integer.toHexString(0xFF & blockContents) + "\n  X: " + Functions.toHex(x);
  }

}
