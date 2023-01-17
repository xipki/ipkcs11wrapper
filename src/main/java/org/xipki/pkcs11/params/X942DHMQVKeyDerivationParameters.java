// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DHMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH mechanisms
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 *
 * @author Stiftung SIC (SIC)
 * @author Lijun Liao (xipki)
 */
public class X942DHMQVKeyDerivationParameters extends X942DH2KeyDerivationParameters {

  private final long publicKeyHandle;

  public X942DHMQVKeyDerivationParameters(long keyDerivationFunction, byte[] sharedData,
      byte[] publicData, int privateDataLength, long privateDataHandle, byte[] publicData2, long publicKeyHandle) {
    super(keyDerivationFunction, sharedData, publicData, privateDataLength, privateDataHandle, publicData2);

    this.publicKeyHandle = publicKeyHandle;
  }

  /**
   * Get this parameters object as an object of the CK_X9_42_DH2_DERIVE_PARAMS class.
   *
   * @return This object as a CK_X9_42_DH2_DERIVE_PARAMS object.
   */
  @Override
  public CK_X9_42_DHMQV_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_X9_42_DHMQV_DERIVE_PARAMS params = new CK_X9_42_DHMQV_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
    params.pPublicData = publicData;
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = publicData2;
    params.hPublicKey = publicKeyHandle;

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
    return super.toString() + "\n  Private Data Length (dec): " + "\n  Private Data Handle: "+ privateDataHandle +
        "\n  Public Data 2: " + Functions.toHex(publicData2) + "\n Public Key Handle: " + publicKeyHandle;
  }

}
