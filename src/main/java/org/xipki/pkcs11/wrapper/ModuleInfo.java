// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_INFO;

/**
 * Objects of this class provide information about a PKCS#11 module; i.e. the
 * driver for a specific token.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class ModuleInfo {

  /**
   * The module claims to be compliant to this version of PKCS#11.
   */
  private final Version cryptokiVersion;

  /**
   * The identifier for the manufacturer of this module.
   */
  private final String manufacturerID;

  /**
   * A description of this module.
   */
  private final String libraryDescription;

  /**
   * The version number of this module.
   */
  private final Version libraryVersion;

  /**
   * Constructor taking the CK_INFO object of the token.
   *
   * @param ckInfo
   *          The info object as got from PKCS11.C_GetInfo().
   */
  public ModuleInfo(CK_INFO ckInfo) {
    Functions.requireNonNull("ckInfo", ckInfo);
    cryptokiVersion = new Version(ckInfo.cryptokiVersion);
    manufacturerID = new String(ckInfo.manufacturerID).trim();
    libraryDescription = new String(ckInfo.libraryDescription).trim();
    libraryVersion = new Version(ckInfo.libraryVersion);
  }

  /**
   * Get the version of PKCS#11 that this module claims to be compliant to.
   *
   * @return The version object.
   */
  public Version getCryptokiVersion() {
    return cryptokiVersion;
  }

  /**
   * Get the identifier of the manufacturer.
   *
   * @return A string identifying the manufacturer of this module.
   */
  public String getManufacturerID() {
    return manufacturerID;
  }

  /**
   * Get a short description of this module.
   *
   * @return A string describing the module.
   */
  public String getLibraryDescription() {
    return libraryDescription;
  }

  /**
   * Get the version of this PKCS#11 module.
   *
   * @return The version of this module.
   */
  public Version getLibraryVersion() {
    return libraryVersion;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  @Override
  public String toString() {
    return  "Cryptoki Version:    " + cryptokiVersion    + "\nManufacturerID:      " + manufacturerID +
          "\nLibrary Description: " + libraryDescription + "\nLibrary Version:     " + libraryVersion;
  }

}
