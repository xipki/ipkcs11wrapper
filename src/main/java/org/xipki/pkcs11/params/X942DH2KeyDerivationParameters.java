// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DH2_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH mechanisms
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class X942DH2KeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  protected final byte[] otherInfo;

  /**
   * The length in bytes of the second EC private key.
   */
  protected final int privateDataLength;

  /**
   * The key for the second EC private key value.
   */
  protected final long privateDataHandle;

  /**
   * The other party's second EC public key value.
   */
  protected final byte[] publicData2;

  /**
   * Create a new X942DH1KeyDerivationParameters object with the given
   * attributes.
   *
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value.
   *          One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other party's public key value.
   * @param privateDataLength
   *          The length in bytes of the second EC private key.
   * @param privateDataHandle
   *          The key for the second X9.42 private key value.
   * @param publicData2
   *          The other party's second X9.42 public key value.
   */
  public X942DH2KeyDerivationParameters(long keyDerivationFunction, byte[] sharedData, byte[] publicData,
                                        int privateDataLength, long privateDataHandle, byte[] publicData2) {
    super(keyDerivationFunction, publicData);
    this.otherInfo = sharedData;
    this.privateDataLength = privateDataLength;
    this.privateDataHandle = privateDataHandle;
    this.publicData2 = Functions.requireNonNull("publicData2", publicData2);
  }

  /**
   * Get this parameters object as an object of the CK_X9_42_DH2_DERIVE_PARAMS
   * class.
   *
   * @return This object as a CK_X9_42_DH2_DERIVE_PARAMS object.
   */
  @Override
  public Object getPKCS11ParamsObject() {
    CK_X9_42_DH2_DERIVE_PARAMS params = new CK_X9_42_DH2_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pOtherInfo = otherInfo;
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
        "\n  Other Info: "+ Functions.toHex(otherInfo)  + "\n  Private Data Length (dec): " + privateDataLength +
        "\n  Private Data Handle: " + privateDataHandle + "\n  Public Data 2: " + Functions.toHex(publicData2);
  }

}
