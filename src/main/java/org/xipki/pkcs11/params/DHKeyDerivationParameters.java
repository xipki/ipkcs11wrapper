// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This abstract class encapsulates parameters for the DH mechanisms
 * CKM_ECDH1_DERIVE, CKM_CDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE,
 * CKM_X9_42_DH_DERIVE, CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
abstract public class DHKeyDerivationParameters implements Parameters {

  /**
   * The key derivation function used on the shared secret value.
   */
  protected long kdf;

  /**
   * The other party's public key value.
   */
  protected byte[] publicData;

  /**
   * Create a new DHKeyDerivationParameters object with the given attributes.
   *
   * @param kdf
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in CKD_
   * @param publicData
   *          The other party's public key value.
   */
  public DHKeyDerivationParameters(long kdf, byte[] publicData) {
    this.publicData = Functions.requireNonNull("publicData", publicData);
    this.kdf = Functions.requireAmong("kdf", kdf,
        CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Key Derivation Function: " + codeToName(Category.CKD, kdf) +
        "\n  Public Data: " + Functions.toHex(publicData);
  }

}
