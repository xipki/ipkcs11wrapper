// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_ECMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the DH mechanisms Mechanism.ECMQV_DERIVE.
 *
 *  @author Stiftung SIC (SIC)
 * @author Lijun Liao (xipki)
 */
public class EcMQVKeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  private final byte[] sharedData;

  /** the length in bytes of the second EC private key. */
  private final int privateDataLen;

  /** key handle for second EC private key value. */
  private final long privateData;

  /** pointer to other party's second EC public key value. */
  private final byte[] publicData2;

  /** Handle to the first party's ephemeral public key. */
  private final long publicKey;

  /**
   * Create a new EcMQVKeyDerivationParameters object with the given attributes.
   *
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other partie's public key value.
   * @param privateDataLen
   *          the length in bytes of the second EC private key
   * @param privateData
   *          Key handle for second EC private key value
   * @param publicData2
   *          pointer to other party's second EC public key value
   * @param publicKey
   *          Handle to the first party's ephemeral public key
   */
  public EcMQVKeyDerivationParameters(long keyDerivationFunction, byte[] sharedData, byte[] publicData,
      int privateDataLen, long privateData, byte[] publicData2, long publicKey) {
    super(keyDerivationFunction, publicData);
    this.sharedData = sharedData;
    this.privateDataLen = privateDataLen;
    this.privateData = privateData;
    this.publicData2 = publicData2;
    this.publicKey = publicKey;
  }

  /**
   * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
   *
   * @return This object as a CK_ECDH1_DERIVE_PARAMS object.
   *
   */
  @Override
  public CK_ECMQV_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_ECMQV_DERIVE_PARAMS params = new CK_ECMQV_DERIVE_PARAMS();

    params.kdf = kdf;
    params.pSharedData = sharedData;
    params.pPublicData = publicData;
    params.ulPrivateDataLen = privateDataLen;
    params.hPrivateData = privateData;
    params.pPublicData2 = publicData2;
    params.publicKey = publicKey;

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
    return super.toString() + "\n  Shared Data: " + Functions.toHex(sharedData) +
        "\n  Private Data Handle: " + privateData + "\n  Public Data 2: " + Functions.toHex(publicData2) +
        "\n  public key handle: " + publicKey;
  }

}
