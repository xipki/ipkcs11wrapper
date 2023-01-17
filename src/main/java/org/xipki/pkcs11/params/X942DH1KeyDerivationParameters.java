// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DH1_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH
 * Mechanism.X9_42_DH_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class X942DH1KeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  private final byte[] otherInfo;

  /**
   * Create a new X942DH1KeyDerivationParameters object with the given
   * attributes.
   *
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param otherInfo
   *          The data shared between the two parties.
   * @param publicData
   *          The other party's public key value.
   */
  public X942DH1KeyDerivationParameters(long keyDerivationFunction, byte[] otherInfo, byte[] publicData) {
    super(keyDerivationFunction, publicData);
    this.otherInfo = otherInfo;
  }

  /**
   * Get this parameters object as an object of the CK_X9_42_DH1_DERIVE_PARAMS
   * class.
   *
   * @return This object as a CK_X9_42_DH1_DERIVE_PARAMS object.
   */
  @Override
  public CK_X9_42_DH1_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_X9_42_DH1_DERIVE_PARAMS params = new CK_X9_42_DH1_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
    params.pPublicData = publicData;

    return params;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Other Info: " + Functions.toHex(otherInfo);
  }

}
