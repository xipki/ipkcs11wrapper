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

package org.xipki.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_KEA_DERIVE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEA_KEY_DERIVE.
 *
 * @author Karl Scheibelhofer
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
   * @postconditions (result != null)
   */
  public CK_KEA_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_KEA_DERIVE_PARAMS params = new CK_KEA_DERIVE_PARAMS();

    params.isSender = isSender;
    params.pRandomA = randomA;
    params.pRandomB = randomB;
    params.pPublicData = publicData;

    return params;
  }

  /**
   * Get the other party's KEA public key value.
   *
   * @return The other party's KEA public key value.
   *
   * @postconditions (result != null)
   */
  public byte[] getPublicData() {
    return publicData;
  }

  /**
   * Get the random data Ra.
   *
   * @return The random data Ra.
   *
   * @postconditions (result != null)
   */
  public byte[] getRandomA() {
    return randomA;
  }

  /**
   * Get the random data Rb.
   *
   * @return The random data Rb.
   *
   * @postconditions (result != null)
   */
  public byte[] getRandomB() {
    return randomB;
  }

  /**
   * Get the option for generating the key (called a TEK).
   *
   * @return True if the sender (originator) generates the TEK, false if the recipient is
   *         regenerating the TEK.
   */
  public boolean isSender() {
    return isSender;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Is Sender: " + isSender +
        "\n  Random Data A: " + Functions.toHex(randomA) + "\n  Random Data B: " + Functions.toHex(randomB) +
        "\n  Public Data: " + Functions.toHex(publicData);
  }

}
