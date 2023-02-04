// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_VERSION;

/**
 * Objects of this class represent a version. This consists of a major and a
 * minor version number.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 *
 */
public class Version {

  /**
   * The major version number.
   */
  private final byte major;

  /**
   * The minor version number.
   */
  private final  byte minor;

  /**
   * Constructor for internal use only.
   *
   */
  protected Version(byte major, byte minor) {
    this.major = major;
    this.minor = minor;
  }

  /**
   * Constructor taking a CK_VERSION object.
   *
   * @param ckVersion
   *          A CK_VERSION object.
   *
   */
  protected Version(CK_VERSION ckVersion) {
    this(Functions.requireNonNull("ckVersion", ckVersion).major, ckVersion.minor);
  }

  /**
   * Get the major version number.
   *
   * @return The major version number.
   */
  public byte getMajor() {
    return major;
  }

  /**
   * Get the minor version number.
   *
   * @return The minor version number.
   */
  public byte getMinor() {
    return minor;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return (major & 0xff) + "." + (minor & 0xff);
  }

}
