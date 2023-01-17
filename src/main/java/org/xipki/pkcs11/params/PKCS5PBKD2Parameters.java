// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_PKCS5_PBKD2_PARAMS;
import org.xipki.pkcs11.Functions;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * This class encapsulates parameters for the Mechanism.PKCS5_PKKD2 mechanism.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class PKCS5PBKD2Parameters implements Parameters {

  /**
   * The source of the salt value.
   */
  private final long saltSource;

  /**
   * The data used as the input for the salt source.
   */
  private final byte[] saltSourceData;

  /**
   * The number of iterations to perform when generating each block of random
   * data.
   */
  private final int iterations;

  /**
   * The pseudo-random function (PRF) to used to generate the key.
   */
  private final long pseudoRandomFunction;

  /**
   * The data used as the input for PRF in addition to the salt value.
   */
  private final byte[] pseudoRandomFunctionData;

  /**
   * Create a new PBEDeriveParameters object with the given attributes.
   *
   * @param saltSource
   *          The source of the salt value. One of the constants defined in
   *          the SaltSourceType interface.
   * @param saltSourceData
   *          The data used as the input for the salt source.
   * @param iterations
   *          The number of iterations to perform when generating each block
   *          of random data.
   * @param pseudoRandomFunction
   *          The pseudo-random function (PRF) to used to generate the key.
   *          One of the constants defined in the PseudoRandomFunctionType
   *          interface.
   * @param pseudoRandomFunctionData
   *          The data used as the input for PRF in addition to the salt
   *          value.
   */
  public PKCS5PBKD2Parameters(long saltSource, byte[] saltSourceData,
      int iterations, long pseudoRandomFunction, byte[] pseudoRandomFunctionData) {
    this.saltSource = Functions.requireAmong("saltSource", saltSource, CKZ_SALT_SPECIFIED);
    this.pseudoRandomFunction = Functions.requireAmong("pseudoRandomFunction",
                                  pseudoRandomFunction, CKP_PKCS5_PBKD2_HMAC_SHA1);
    this.saltSourceData = Functions.requireNonNull("saltSourceData", saltSourceData);
    this.iterations = iterations;
    this.pseudoRandomFunctionData = Functions.requireNonNull("pseudoRandomFunctionData", pseudoRandomFunctionData);
  }

  /**
   * Get this parameters object as an object of the CK_PKCS5_PBKD2_PARAMS
   * class.
   *
   * @return This object as a CK_PKCS5_PBKD2_PARAMS object.
   */
  @Override
  public CK_PKCS5_PBKD2_PARAMS getPKCS11ParamsObject() {
    CK_PKCS5_PBKD2_PARAMS params = new CK_PKCS5_PBKD2_PARAMS();

    params.saltSource = saltSource;
    params.pSaltSourceData = saltSourceData;
    params.iterations = iterations;
    params.prf = pseudoRandomFunction;
    params.pPrfData = pseudoRandomFunctionData;

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
    return "Class: " + getClass().getName() + "\n  Salt Source: " + codeToName(Category.CKZ, saltSource) +
        "\n  Salt Source Data (hex): " + Functions.toHex(saltSourceData) + "\n  Iterations (dec): " + iterations +
        "\n  Pseudo-Random Function: " + codeToName(Category.CKP_PRF, pseudoRandomFunction) +
        "\n  Pseudo-Random Function Data: " + Functions.toHex(pseudoRandomFunctionData);
  }

}
