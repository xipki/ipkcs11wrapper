// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECDH2_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the DH mechanism
 * CKM_ECMQV_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class EcDH2KeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  private final byte[] sharedData;

  /**
   * The length in bytes of the second EC private key.
   */
  private final int privateDataLength;

  /**
   * The key for the second EC private key value.
   */
  private final long privateDataHandle;

  /**
   * The other party's second EC public key value.
   */
  private final byte[] publicData2;

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
   *          The other partie's public key value.
   * @param privateDataLength
   *          The length in bytes of the second EC private key.
   * @param privateDataHandle
   *          The key for the second EC private key value.
   * @param publicData2
   *          The other party's second EC public key value.
   */
  public EcDH2KeyDerivationParameters(long kdf, byte[] sharedData, byte[] publicData,
      int privateDataLength, long privateDataHandle, byte[] publicData2) {
    super(kdf, publicData);
    this.sharedData = sharedData;
    this.privateDataLength = privateDataLength;
    this.privateDataHandle = privateDataHandle;
    this.publicData2 = Functions.requireNonNull("publicData2", publicData2);
  }

  /**
   * Get this parameters object as an object of the CK_ECDH2_DERIVE_PARAMS
   * class.
   *
   * @return This object as a CK_ECDH2_DERIVE_PARAMS object.
   */
  @Override
  public CK_ECDH2_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_ECDH2_DERIVE_PARAMS params = new CK_ECDH2_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pSharedData = sharedData;
    params.pPublicData = publicData;
    params.ulPrivateDataLen = privateDataLength;
    params.hPrivateData = privateDataHandle;
    params.pPublicData2 = publicData2;

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
    return super.toString() +
        "\n  Shared Data: " + Functions.toHex(sharedData) + "\n  Private Data Length (dec): " + privateDataLength +
        "\n  Private Data: " + privateDataHandle + "\n  Public Data 2: " + Functions.toHex(publicData2);
  }

}
