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

import iaik.pkcs.pkcs11.wrapper.CK_ECMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the DH mechanisms Mechanism.ECMQV_DERIVE.
 *
 *  @author Stiftung SIC
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
