// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * This class encapsulates parameters for Mechanisms.CONCATENATE_BASE_AND_KEY.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class ObjectHandleParameters implements Parameters {

  /**
   * The PKCS#11 object.
   */
  private final long objectHandle;

  /**
   * Create a new ObjectHandleParameters object using the given object.
   *
   * @param objectHandle
   *          The PKCS#11 object whose handle to use.
   */
  public ObjectHandleParameters(long objectHandle) {
    this.objectHandle = objectHandle;
  }

  /**
   * Get this parameters object as a Long object, which is the handle of the
   * underlying object.
   *
   * @return This object as a Long object.
   */
  @Override
  public Long getPKCS11ParamsObject() {
    return objectHandle;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  PKCS11Object: " + objectHandle;
  }

}
