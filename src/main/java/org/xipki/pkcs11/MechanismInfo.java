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

import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Objects of this class provide information about a certain mechanism that a
 * token implements.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class MechanismInfo {

  /**
   * The minimum key length supported by this algorithm.
   */
  private final long minKeySize;

  /**
   * The maximum key length supported by this algorithm.
   */
  private final long maxKeySize;

  /**
   * Contains all feature flags of this mechanism info.
   */
  private long flags;

  /**
   * Constructor taking a CK_MECHANISM_INFO object as data source.
   *
   * @param ckMechanismInfo
   *          The CK_MECHANISM_INFO object that provides the data.
   */
  public MechanismInfo(CK_MECHANISM_INFO ckMechanismInfo) {
    this(Functions.requireNonNull("ckMechanismInfo", ckMechanismInfo).ulMinKeySize,
        ckMechanismInfo.ulMaxKeySize, ckMechanismInfo.flags);
  }

  /**
   * @param minKeySize
   *          The minimum key length supported by this mechanism.
   * @param maxKeySize
   *          The maximum key length supported by this mechanism.
   * @param flags
   *          The flag bit(s).
   */
  public MechanismInfo(long minKeySize, long maxKeySize, long flags) {
    this.minKeySize = minKeySize;
    this.maxKeySize = maxKeySize;
    this.flags = flags;
  }

  /**
   * Get the minimum key length supported by this mechanism.
   *
   * @return The minimum key length supported by this mechanism.
   */
  public long getMinKeySize() {
    return minKeySize;
  }

  /**
   * Get the maximum key length supported by this mechanism.
   *
   * @return The maximum key length supported by this mechanism.
   */
  public long getMaxKeySize() {
    return maxKeySize;
  }

  public boolean hasFlagBit(long flagMask) {
    return (flags & flagMask) != 0L;
  }

  /**
   * Set the given feature flag.
   *
   * @param flagMask
   *          The mask of the flag bit(s).
   */
  public void setFlagBit(long flagMask) {
    flags |= flagMask;
  }

  /**
   * Clear the given feature flag.
   *
   * @param flagMask
   *          The mask of the flag bit(s).
   */
  public void clearFlagBit(long flagMask) {
    flags &= ~flagMask;
  }

  /**
   * Check, if this mechanism info has those flags set to true, which are set
   * in the given mechanism info. This may be used as a simple check, if some
   * operations are supported.
   * This also checks the key length range, if they are specified in the given
   * mechanism object; i.e. if they are not zero.
   *
   * @param requiredFeatures
   *          The required features.
   * @return True, if the required features are supported.
   */
  public boolean supports(MechanismInfo requiredFeatures) {
    Functions.requireNonNull("requiredFeatures", requiredFeatures);

    long requiredMaxKeySize = requiredFeatures.getMaxKeySize();
    long requiredMinKeySize = requiredFeatures.getMinKeySize();

    return (requiredMaxKeySize != 0 && requiredMaxKeySize > maxKeySize) ? false
        :  (requiredMinKeySize != 0 && requiredMinKeySize < minKeySize) ? false
        :  (requiredFeatures.flags & flags) == requiredFeatures.flags;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    String text = "  Minimum Key-Size: " + minKeySize + "\n  Maximum Key-Size: " + maxKeySize + "\n  Flags: ";

    return Functions.toStringFlags(Category.CKF_MECHANISM, text, flags,
        CKF_HW,             CKF_MESSAGE_ENCRYPT, CKF_MESSAGE_DECRYPT, CKF_MESSAGE_SIGN,
        CKF_MESSAGE_VERIFY, CKF_MULTI_MESSAGE,   CKF_FIND_OBJECTS,

        CKF_ENCRYPT,  CKF_DECRYPT,  CKF_DIGEST,  CKF_SIGN,  CKF_SIGN_RECOVER,  CKF_VERIFY,  CKF_VERIFY_RECOVER,
        CKF_GENERATE, CKF_GENERATE_KEY_PAIR,     CKF_WRAP,  CKF_UNWRAP,        CKF_DERIVE,

        CKF_EC_F_P,        CKF_EC_F_2M,      CKF_EC_ECPARAMETERS,    CKF_EC_OID,
        CKF_EC_UNCOMPRESS, CKF_EC_COMPRESS,  CKF_EC_CURVENAME);
  }

}
