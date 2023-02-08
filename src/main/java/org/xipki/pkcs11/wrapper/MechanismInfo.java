// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;

/**
 * Objects of this class provide information about a certain mechanism that a
 * token implements.
 *
 * @author Karl Scheibelhofer (SIC)
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
    return toString("");
  }

  public String toString(String indent) {
    String text = indent + "  Key-Size: [" + minKeySize + ", " + maxKeySize + "]\n";

    return text + Functions.toStringFlags(PKCS11Constants.Category.CKF_MECHANISM, indent + "  Flags: ", flags,
        PKCS11Constants.CKF_HW,             PKCS11Constants.CKF_MESSAGE_ENCRYPT, PKCS11Constants.CKF_MESSAGE_DECRYPT,
        PKCS11Constants.CKF_MESSAGE_SIGN,   PKCS11Constants.CKF_MESSAGE_VERIFY,  PKCS11Constants.CKF_MULTI_MESSAGE,
        PKCS11Constants.CKF_FIND_OBJECTS,

        PKCS11Constants.CKF_ENCRYPT,        PKCS11Constants.CKF_DECRYPT,       PKCS11Constants.CKF_DIGEST,
        PKCS11Constants.CKF_SIGN,           PKCS11Constants.CKF_SIGN_RECOVER,  PKCS11Constants.CKF_VERIFY,
        PKCS11Constants.CKF_VERIFY_RECOVER, PKCS11Constants.CKF_GENERATE,      PKCS11Constants.CKF_GENERATE_KEY_PAIR,
        PKCS11Constants.CKF_WRAP,           PKCS11Constants.CKF_UNWRAP,        PKCS11Constants.CKF_DERIVE,

        PKCS11Constants.CKF_EC_F_P,        PKCS11Constants.CKF_EC_F_2M,      PKCS11Constants.CKF_EC_ECPARAMETERS,
        PKCS11Constants.CKF_EC_OID,        PKCS11Constants.CKF_EC_UNCOMPRESS, PKCS11Constants.CKF_EC_COMPRESS,
        PKCS11Constants.CKF_EC_CURVENAME);
  }

}
