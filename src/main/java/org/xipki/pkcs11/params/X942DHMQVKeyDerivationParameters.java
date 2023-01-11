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

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DHMQV_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH mechanisms
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 * @author Stiftung SIC
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
  public String toString() {
    return super.toString() + "\n  Private Data Length (dec): " + "\n  Private Data Handle: "+ privateDataHandle +
        "\n  Public Data 2: " + Functions.toHex(publicData2) + "\n Public Key Handle: " + publicKeyHandle;
  }

}