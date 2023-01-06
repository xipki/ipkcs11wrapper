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

import iaik.pkcs.pkcs11.wrapper.CK_INFO;

/**
 * Objects of this class provide information about a PKCS#11 module; i.e. the
 * driver for a specific token.
 *
 * @author Karl Scheibelhofer
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
    manufacturerID = new String(ckInfo.manufacturerID);
    libraryDescription = new String(ckInfo.libraryDescription);
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
  public String toString() {
    return "Cryptoki Version: " + cryptokiVersion + "\nManufacturerID: " + manufacturerID +
        "\nLibrary Description: " + libraryDescription + "\nLibrary Version: " + libraryVersion;
  }

}
