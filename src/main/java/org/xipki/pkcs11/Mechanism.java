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

package org.xipki.pkcs11;

import org.xipki.pkcs11.parameters.Parameters;

/**
 * Objects of this class represent a mechanism as defined in PKCS#11. There are
 * constants defined for all mechanisms that PKCS#11 version 2.11 defines.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class Mechanism {

  /**
   * The code of the mechanism as defined in PKCS11Constants (or pkcs11t.h
   * likewise).
   */
  private final long pkcs11MechanismCode;

  /**
   * The parameters of the mechanism. Not all mechanisms use these parameters.
   */
  private Parameters parameters;

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param pkcs11MechanismCode
   *          The mechanism code.
   */
  public Mechanism(long pkcs11MechanismCode) {
    this.pkcs11MechanismCode = pkcs11MechanismCode;
  }

  /**
   * Gets the mechanism specified by the given mechanism code. Helper
   * {@link PKCS11Constants} is available.
   *
   * @param pkcs11MechanismCode
   *          the pkcs11 mechanism code
   * @return the mechanism
   */
  public static Mechanism get(long pkcs11MechanismCode) {
    return new Mechanism(pkcs11MechanismCode);
  }

  /**
   * Get the parameters object of this mechanism.
   *
   * @return The parameters of this mechanism. May be null.
   */
  public Parameters getParameters() {
    return parameters;
  }

  /**
   * Set the parameters for this mechanism.
   *
   * @param parameters
   *          The mechanism parameters to set.
   */
  public void setParameters(Parameters parameters) {
    this.parameters = parameters;
  }

  /**
   * Get the code of this mechanism as defined in PKCS11Constants (of
   * pkcs11t.h likewise).
   *
   * @return The code of this mechanism.
   */
  public long getMechanismCode() {
    return pkcs11MechanismCode;
  }

  /**
   * Get the name of this mechanism.
   *
   * @return The name of this mechanism.
   */
  public String getName() {
    return Functions.ckmCodeToName(pkcs11MechanismCode);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  public String toString() {
    return "    Mechanism: " + getName() + "\n    Parameters:\n" + parameters;
  }

}
