// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This abstract class encapsulates parameters for the RSA PKCS mechanisms
 * Mechanism.RSA_PKCS_OAEP and Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
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
    map.put(CKG_MGF1_SHA1,     CKM_SHA_1);
    map.put(CKG_MGF1_SHA224,   CKM_SHA224);
    map.put(CKG_MGF1_SHA256,   CKM_SHA256);
    map.put(CKG_MGF1_SHA384,   CKM_SHA384);
    map.put(CKG_MGF1_SHA512,   CKM_SHA512);
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
      throw new IllegalArgumentException("Illegal value for argument 'mgf': " + codeToName(Category.CKG_MGF, mgf));
    }

    this.hashAlg = hashAlg;
    this.mgf = mgf;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Hash Algorithm: " + ckmCodeToName(hashAlg) +
        "\n  Mask Generation Function: " + codeToName(Category.CKG_MGF, mgf);
  }

}
