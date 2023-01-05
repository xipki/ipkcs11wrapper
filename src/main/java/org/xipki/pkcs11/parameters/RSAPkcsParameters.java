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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This abstract class encapsulates parameters for the RSA PKCS mechanisms
 * Mechanism.RSA_PKCS_OAEP and Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
abstract public class RSAPkcsParameters implements Parameters {

  protected static final Map<Long, Long> mgf2HashAlgMap;

  /**
   * The message digest algorithm used to calculate the digest of the encoding
   * parameter.
   */
  protected long hashAlg;

  /**
   * The mask to apply to the encoded block.
   */
  protected long mgf;

  static {
    Map<Long, Long> map = new HashMap<>();
    map.put(CKG_MGF1_SHA1, CKM_SHA_1);
    map.put(CKG_MGF1_SHA224, CKM_SHA224);
    map.put(CKG_MGF1_SHA256, CKM_SHA256);
    map.put(CKG_MGF1_SHA384, CKM_SHA384);
    map.put(CKG_MGF1_SHA512, CKM_SHA512);
    map.put(CKG_MGF1_SHA3_224, CKM_SHA3_224);
    map.put(CKG_MGF1_SHA3_256, CKM_SHA3_256);
    map.put(CKG_MGF1_SHA3_384, CKM_SHA3_384);
    map.put(CKG_MGF1_SHA3_512, CKM_SHA3_512);
    mgf2HashAlgMap = Collections.unmodifiableMap(map);
  }

  /**
   * Create a new RSAPkcsParameters object with the given attributes.
   *
   * @param hashAlg
   *          The message digest algorithm used to calculate the digest of the
   *          encoding parameter.
   * @param mgf
   *          The mask to apply to the encoded block. One of the constants
   *          defined in the MessageGenerationFunctionType interface.
   *          Due to limitation in the underlying jdk.crypto.cryptoki
   *          implementation, only MGF1 is allowed and the hash algorithm
   *          in mgf must be same as hashAlg.
   */
  protected RSAPkcsParameters(long hashAlg, long mgf) {
    if (!mgf2HashAlgMap.containsKey(mgf)) {
      throw new IllegalArgumentException("Illegal value for argument 'mgf': " + Functions.ckgCodeToName(mgf));
    }

    this.hashAlg = hashAlg;
    this.mgf = mgf;
  }

  /**
   * Get the message digest algorithm used to calculate the digest of the
   * encoding parameter.
   *
   * @return The message digest algorithm used to calculate the digest of the
   *         encoding parameter.
   */
  public long getHashAlgorithm() {
    return hashAlg;
  }

  /**
   * Get the mask to apply to the encoded block.
   *
   * @return The mask to apply to the encoded block.
   */
  public long getMaskGenerationFunction() {
    return mgf;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Hash Algorithm: " + Functions.ckmCodeToName(hashAlg) +
        "\n  Mask Generation Function: " + Functions.ckgCodeToName(mgf);
  }

}
