// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import org.xipki.pkcs11.params.Parameters;

/**
 * Objects of this class represent a mechanism as defined in PKCS#11. There are
 * constants defined for all mechanisms that PKCS#11 version 2.11 defines.
 *
 * @author Karl Scheibelhofer (SIC)
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
  private final Parameters parameters;

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param pkcs11MechanismCode
   *          The mechanism code.
   */
  public Mechanism(long pkcs11MechanismCode) {
    this(pkcs11MechanismCode, null);
  }

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param pkcs11MechanismCode The mechanism code.
   * @param parameters The mechanism parameters.
   */
  public Mechanism(long pkcs11MechanismCode, Parameters parameters) {
    this.pkcs11MechanismCode = pkcs11MechanismCode;
    this.parameters = parameters;
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
    return PKCS11Constants.ckmCodeToName(pkcs11MechanismCode);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "    Mechanism: " + getName() + "\n    Parameters:\n" + parameters;
  }

}
