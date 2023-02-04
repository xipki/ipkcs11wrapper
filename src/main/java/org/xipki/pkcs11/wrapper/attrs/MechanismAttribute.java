// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent a mechanism attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class MechanismAttribute extends LongAttribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE_LEN.
   */
  public MechanismAttribute(long type) {
    super(type);
  }

  /**
   * Set the mechanism value of this attribute.
   * <code>null</code>, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param mechanism
   *          The mechanism value to set. May be <code>null</code>.
   */
  public MechanismAttribute setMechanism(Long mechanism) {
    ckAttribute.pValue = mechanism;
    present = true;
    return this;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    Long value = getValue();
    if (value == null) {
      return "<NULL_PTR>";
    }

    return PKCS11Constants.isUnavailableInformation(value) ? "N/A" : PKCS11Constants.ckmCodeToName(value);
  }

}
