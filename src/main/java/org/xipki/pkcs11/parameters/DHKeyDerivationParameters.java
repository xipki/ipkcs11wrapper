// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
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

package org.xipki.pkcs11.parameters;

import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This abstract class encapsulates parameters for the DH mechanisms
 * CKM_ECDH1_DERIVE, CKM_CDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE,
 * CKM_X9_42_DH_DERIVE, CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE.
 *
 * @author Karl Scheibelhofer
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
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Key Derivation Function: " + Functions.ckdCodeToName(kdf) +
        "\n  Public Data: " + Functions.toHex(publicData);
  }

}
