// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Salsa20 en/decryption.
 *
 * @author Patrick Schuster (SIC)
 * @author Lijun Liao (xipki)
 */
public class Salsa20Parameters implements Parameters {

  private final byte[] blockCounter;
  private final byte[] nonce;

  /**
   * Create a new Salsa20Parameters object with the given attributes.
   *
   * @param blockCounter the Blockcounter
   * @param nonce    the nonce
   */
  public Salsa20Parameters(byte[] blockCounter, byte[] nonce) {
    this.blockCounter = blockCounter;
    this.nonce = nonce;
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_PARAMS class.
   *
   * @return This object as a CK_SALSA20_PARAMS object.
   */
  @Override
  public CK_SALSA20_PARAMS getPKCS11ParamsObject() {
    CK_SALSA20_PARAMS params = new CK_SALSA20_PARAMS();
    params.pBlockCounter = blockCounter;
    params.pNonce = nonce;
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
    return "Class: " + getClass().getName() + "\n  Nonce: " + Functions.toHex(nonce);
  }

}

