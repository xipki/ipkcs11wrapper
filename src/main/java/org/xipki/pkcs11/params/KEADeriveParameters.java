// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_KEA_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEA_KEY_DERIVE.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class KEADeriveParameters implements Parameters {

  /**
   * Option for generating the key (called a TEK). The value is TRUE if the sender (originator)
   * generates the TEK, FALSE if the recipient is regenerating the TEK.
   */
  private boolean isSender;

  /**
   * The Ra data.
   */
  private byte[] randomA;

  /**
   * The Rb data.
   */
  private byte[] randomB;

  /**
   * The other party's KEA public key value.
   */
  private byte[] publicData;

  /**
   * Create a new KEADeriveParameters object with the given attributes.
   *
   * @param isSender
   *          Option for generating the key (called a TEK). The value is TRUE if the sender
   *          (originator) generates the TEK, FALSE if the recipient is regenerating the TEK.
   * @param randomA
   *          The random data Ra.
   * @param randomB
   *          The random data Rb.
   * @param publicData
   *          The other party's KEA public key value.
   */
  public KEADeriveParameters(boolean isSender, byte[] randomA, byte[] randomB, byte[] publicData) {
    this.isSender = isSender;
    this.randomA = Functions.requireNonNull("randomA", randomA);
    this.randomB = Functions.requireNonNull("randomB", randomB);
    this.publicData = Functions.requireNonNull("publicData", publicData);
  }

  /**
   * Get this parameters object as an object of the CK_KEA_DERIVE_PARAMS class.
   *
   * @return This object as a CK_KEA_DERIVE_PARAMS object.
   *
   */
  @Override
  public CK_KEA_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_KEA_DERIVE_PARAMS params = new CK_KEA_DERIVE_PARAMS();

    params.isSender = isSender;
    params.pRandomA = randomA;
    params.pRandomB = randomB;
    params.pPublicData = publicData;

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
    return "Class: " + getClass().getName() + "\n  Is Sender: " + isSender +
        "\n  Random Data A: " + Functions.toHex(randomA) + "\n  Random Data B: " + Functions.toHex(randomB) +
        "\n  Public Data: " + Functions.toHex(publicData);
  }

}
