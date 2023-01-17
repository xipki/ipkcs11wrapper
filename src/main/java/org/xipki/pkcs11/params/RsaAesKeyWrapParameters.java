// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_RSA_AES_KEY_WRAP_PARAMS;
import org.xipki.pkcs11.Functions;
import org.xipki.pkcs11.PKCS11Constants;

/**
 * This class encapsulates parameters for the RSA AES Key Wrapping.
 *
 * @author Patrick Schuster (SIC)
 * @author Lijun Liao (xipki)
 */
public class RsaAesKeyWrapParameters implements Parameters {

  private final int AESKeyBits;
  private final RSAPkcsOaepParameters OAEPParams;

  /**
   * Create a new RsaAesKeyWrapParameters object with the given attributes.
   *
   * @param  AESKeyBits length of the temporary AES key in bits. Can be only 128, 192 or 256.
   * @param  OAEPParams parameters of the temporary AES key wrapping. See also the description of <br>
   *                     PKCS #1 RSA OAEP mechanism parameters.
   */
  public RsaAesKeyWrapParameters(int AESKeyBits, RSAPkcsOaepParameters OAEPParams) {
    this.AESKeyBits = AESKeyBits;
    this.OAEPParams = OAEPParams;
  }

  /**
   * Get this parameters object as an object of the CK_SALSA20_PARAMS class.
   *
   * @return This object as a CK_SALSA20_PARAMS object.
   */
  @Override
  public CK_RSA_AES_KEY_WRAP_PARAMS getPKCS11ParamsObject() {
    CK_RSA_AES_KEY_WRAP_PARAMS params = new CK_RSA_AES_KEY_WRAP_PARAMS();
    params.ulAESKeyBits = AESKeyBits;
    params.pOAEPParams = OAEPParams.getPKCS11ParamsObject();
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
    return super.toString() + "\n  AESKeyBits: " + AESKeyBits + "\n  OAEPParams:" +
        "\n    Source: " + PKCS11Constants.codeToName(PKCS11Constants.Category.CKZ, OAEPParams.source) +
        "\n    Source Data: " + Functions.toHex(OAEPParams.sourceData);
  }

}
