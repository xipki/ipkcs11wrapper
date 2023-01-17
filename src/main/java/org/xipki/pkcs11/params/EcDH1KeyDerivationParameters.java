// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the DH mechanisms
 * Mechanism.ECDH1_DERIVE and Mechanism.ECDH1_COFACTOR_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class EcDH1KeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  private final byte[] sharedData;

  /**
   * Create a new EcDH1KeyDerivationParameters object with the given
   * attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other party's public key value.
   */
  public EcDH1KeyDerivationParameters(long kdf, byte[] sharedData, byte[] publicData) {
    super(kdf, publicData);
    this.sharedData = sharedData;
  }

  /**
   * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS
   * class.
   *
   * @return This object as a CK_ECDH1_DERIVE_PARAMS object.
   */
  @Override
  public CK_ECDH1_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_ECDH1_DERIVE_PARAMS ret = new CK_ECDH1_DERIVE_PARAMS();
    ret.kdf = kdf;
    ret.pPublicData = publicData;
    ret.pSharedData = sharedData;
    return ret;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return super.toString() + "\n  Shared Data: " + Functions.toHex(sharedData);
  }

}
