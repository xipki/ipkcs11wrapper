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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;

import java.util.Date;

/**
 * Objects of this class provide information about a token. Serial number,
 * manufacturer, free memory,... . Notice that this is just a snapshot of the
 * token's status at the time this object was created.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class TokenInfo {

  /**
   * This is the value which can be used for ulMaxSessionCount and
   * ulMaxRwSessionCount to express an infinite number.
   */
  public static final long EFFECTIVELY_INFINITE = PKCS11Constants.CK_EFFECTIVELY_INFINITE;

  /**
   * This is the value which can be used for ulMaxSessionCount,
   * ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount,
   * ulTotalPublicMemory, ulFreePublicMemory, ulTotalPrivateMemory, and
   * ulFreePrivateMemory to signal that the information is unavailable.
   */
  public static final long UNAVAILABLE_INFORMATION = PKCS11Constants.CK_UNAVAILABLE_INFORMATION;

  /**
   * The label of this token.
   */
  private final String label;

  /**
   * The identifier of the manufacturer of this token.
   */
  private final String manufacturerID;

  /**
   * The model of this token.
   */
  private final String model;

  /**
   * The serial number of this token.
   */
  private final String serialNumber;

  /**
   * The maximum number of concurrent (open) sessions.
   */
  private final long maxSessionCount;

  /**
   * The current number of open sessions.
   */
  private final long sessionCount;

  /**
   * Maximum number of concurrent (open) read-write sessions.
   */
  private final long maxRwSessionCount;

  /**
   * The current number of open read-write sessions.
   */
  private final long rwSessionCount;

  /**
   * The maximum PIN length that this token allows.
   */
  private final long maxPinLen;

  /**
   * The minimum PIN length that this token allows.
   */
  private final long minPinLen;

  /**
   * The total amount of memory for public objects on this token.
   */
  private final long totalPublicMemory;

  /**
   * The amount of free memory for public objects on this token.
   */
  private final long freePublicMemory;

  /**
   * The total amount of memory for private objects on this token.
   */
  private final long totalPrivateMemory;

  /**
   * The amount of free memory for private objects on this token.
   */
  private final long freePrivateMemory;

  /**
   * The version of the hardware of this token.
   */
  private final Version hardwareVersion;

  /**
   * The version of the firmware of this token.
   */
  private final Version firmwareVersion;

  /**
   * The current time on the token. This value only makes sense, if the token
   * contains a clock.
   */
  private final Date time;

  /**
   * The token flags.
   */
  private final long flags;

  /**
   * Constructor taking CK_TOKEN_INFO as given returned by
   * PKCS11.C_GetTokenInfo.
   *
   * @param ckTokenInfo
   *          The CK_TOKEN_INFO object as returned by PKCS11.C_GetTokenInfo.
   */
  protected TokenInfo(CK_TOKEN_INFO ckTokenInfo) {
    Util.requireNonNull("ckTokenInfo", ckTokenInfo);
    label = new String(ckTokenInfo.label);
    manufacturerID = new String(ckTokenInfo.manufacturerID);
    model = new String(ckTokenInfo.model);
    serialNumber = new String(ckTokenInfo.serialNumber);
    maxSessionCount = ckTokenInfo.ulMaxSessionCount;
    sessionCount = ckTokenInfo.ulSessionCount;
    maxRwSessionCount = ckTokenInfo.ulMaxRwSessionCount;
    rwSessionCount = ckTokenInfo.ulRwSessionCount;
    maxPinLen = ckTokenInfo.ulMaxPinLen;
    minPinLen = ckTokenInfo.ulMinPinLen;
    totalPublicMemory = ckTokenInfo.ulTotalPublicMemory;
    freePublicMemory = ckTokenInfo.ulFreePublicMemory;
    totalPrivateMemory = ckTokenInfo.ulTotalPrivateMemory;
    freePrivateMemory = ckTokenInfo.ulFreePrivateMemory;
    hardwareVersion = new Version(ckTokenInfo.hardwareVersion);
    firmwareVersion = new Version(ckTokenInfo.firmwareVersion);
    time = Util.parseTime(ckTokenInfo.utcTime);
    flags = ckTokenInfo.flags;
  }

  /**
   * Get the label of this token.
   *
   * @return The label of this token.
   */
  public String getLabel() {
    return label;
  }

  /**
   * Get the manufacturer identifier.
   *
   * @return A string identifying the manufacturer of this token.
   */
  public String getManufacturerID() {
    return manufacturerID;
  }

  /**
   * Get the model of this token.
   *
   * @return A string specifying the model of this token.
   */
  public String getModel() {
    return model;
  }

  /**
   * Get the serial number of this token.
   *
   * @return A string holding the serial number of this token.
   */
  public String getSerialNumber() {
    return serialNumber;
  }

  /**
   * Get the maximum allowed number of (open) concurrent sessions.
   *
   * @return The maximum allowed number of (open) concurrent sessions.
   */
  public long getMaxSessionCount() {
    return maxSessionCount;
  }

  /**
   * Get the current number of open sessions.
   *
   * @return The current number of open sessions.
   */
  public long getSessionCount() {
    return sessionCount;
  }

  /**
   * Get the maximum allowed number of (open) concurrent read-write sessions.
   *
   * @return The maximum allowed number of (open) concurrent read-write
   *         sessions.
   */
  public long getMaxRwSessionCount() {
    return maxRwSessionCount;
  }

  /**
   * Get the current number of open read-write sessions.
   *
   * @return The current number of open read-write sessions.
   */
  public long getRwSessionCount() {
    return rwSessionCount;
  }

  /**
   * Get the maximum length for the PIN.
   *
   * @return The maximum length for the PIN.
   */
  public long getMaxPinLen() {
    return maxPinLen;
  }

  /**
   * Get the minimum length for the PIN.
   *
   * @return The minimum length for the PIN.
   */
  public long getMinPinLen() {
    return minPinLen;
  }

  /**
   * Get the total amount of memory for public objects.
   *
   * @return The total amount of memory for public objects.
   */
  public long getTotalPublicMemory() {
    return totalPublicMemory;
  }

  /**
   * Get the amount of free memory for public objects.
   *
   * @return The amount of free memory for public objects.
   */
  public long getFreePublicMemory() {
    return freePublicMemory;
  }

  /**
   * Get the total amount of memory for private objects.
   *
   * @return The total amount of memory for private objects.
   */
  public long getTotalPrivateMemory() {
    return totalPrivateMemory;
  }

  /**
   * Get the amount of free memory for private objects.
   *
   * @return The amount of free memory for private objects.
   */
  public long getFreePrivateMemory() {
    return freePrivateMemory;
  }

  /**
   * Get the version of the token's hardware.
   *
   * @return The version of the token's hardware.
   */
  public Version getHardwareVersion() {
    return hardwareVersion;
  }

  /**
   * Get the version of the token's firmware.
   *
   * @return The version of the token's firmware.
   */
  public Version getFirmwareVersion() {
    return firmwareVersion;
  }

  /**
   * Get the current time of the token's clock. This value does only make
   * sense if the token has a clock. Remind that, this is the time this object
   * was created and not the time the application called this method.
   *
   * @return The current time on the token's clock.
   * @see #isClockOnToken()
   */
  public Date getTime() {
    return time;
  }

  /**
   * Return the token flags.
   * @return the token flags.
   */
  public long getFlags() {
    return flags;
  }

  /**
   * Check, if the token has a random number generator.
   *
   * @return True, if the token has a random number generator. False,
   *         otherwise.
   */
  public boolean isRNG() {
    return hasFlag(PKCS11Constants.CKF_RNG);
  }

  /**
   * Check, if the token is write protected.
   *
   * @return True, if the token is write protected. False, otherwise.
   */
  public boolean isWriteProtected() {
    return hasFlag(PKCS11Constants.CKF_WRITE_PROTECTED);

  }

  /**
   * Check, if the token requires the user to log in before certain operations
   * can be performed.
   *
   * @return True, if the token requires the user to log in before certain
   *         operations can be performed. False, otherwise.
   */
  public boolean isLoginRequired() {
    return hasFlag(PKCS11Constants.CKF_LOGIN_REQUIRED);
  }

  /**
   * Check, if the user-PIN is already initialized.
   *
   * @return True, if the user-PIN is already initialized. False, otherwise.
   */
  public boolean isUserPinInitialized() {
    return hasFlag(PKCS11Constants.CKF_USER_PIN_INITIALIZED);
  }

  /**
   * Check, if a successful save of a session's cryptographic operations
   * state always contains all keys needed to restore the state of the
   * session.
   *
   * @return True, if a successful save of a session's cryptographic
   *         operations state always contains all keys needed to restore the
   *         state of the session. False, otherwise.
   */
  public boolean isRestoreKeyNotNeeded() {
    return hasFlag(PKCS11Constants.CKF_RESTORE_KEY_NOT_NEEDED);
  }

  /**
   * Check, if the token has an own clock.
   *
   * @return True, if the token has its own clock. False, otherwise.
   */
  public boolean isClockOnToken() {
    return hasFlag(PKCS11Constants.CKF_CLOCK_ON_TOKEN);
  }

  /**
   * Check, if the token has a protected authentication path. This means that
   * a user may log in without providing a PIN to the login method, because
   * the token has other means to authenticate the user; e.g. a PIN-pad on the
   * reader or some biometric authentication.
   *
   * @return True, if the token has a protected authentication path. False,
   *         otherwise.
   */
  public boolean isProtectedAuthenticationPath() {
    return hasFlag(PKCS11Constants.CKF_PROTECTED_AUTHENTICATION_PATH);
  }

  /**
   * Check, if the token supports dual crypto operations.
   *
   * @return True, if the token supports dual crypto operations. False,
   *         otherwise.
   */
  public boolean isDualCryptoOperations() {
    return hasFlag(PKCS11Constants.CKF_DUAL_CRYPTO_OPERATIONS);
  }

  /**
   * Check, if the token is already initialized.
   *
   * @return True, if the token is already initialized. False, otherwise.
   */
  public boolean isTokenInitialized() {
    return hasFlag(PKCS11Constants.CKF_TOKEN_INITIALIZED);
  }

  /**
   * Check, if the token supports secondary authentication for private key
   * objects.
   *
   * @return True, if the token supports secondary authentication. False,
   *         otherwise.
   */
  public boolean isSecondaryAuthentication() {
    return hasFlag(PKCS11Constants.CKF_SECONDARY_AUTHENTICATION);
  }

  /**
   * Check, if the user-PIN has been entered incorrectly at least once since
   * the last successful authentication.
   *
   * @return True, if the the user-PIN has been entered incorrectly at least
   *         one since the last successful authentication. False, otherwise.
   */
  public boolean isUserPinCountLow() {
    return hasFlag(PKCS11Constants.CKF_USER_PIN_COUNT_LOW);
  }

  /**
   * Check, if the user has just one try left to supply the correct PIN before
   * the user-PIN gets locked.
   *
   * @return True, if the user has just one try left to supply the correct PIN
   *         before the user-PIN gets locked. False, otherwise.
   */
  public boolean isUserPinFinalTry() {
    return hasFlag(PKCS11Constants.CKF_USER_PIN_FINAL_TRY);
  }

  /**
   * Check, if the user-PIN is locked.
   *
   * @return True, if the user-PIN is locked. False, otherwise.
   */
  public boolean isUserPinLocked() {
    return hasFlag(PKCS11Constants.CKF_USER_PIN_LOCKED);
  }

  /**
   * Check, if the user PIN value is the default value set by token
   * initialization or manufacturing.
   *
   * @return True, if the user PIN value is the default value set by token
   *         initialization or manufacturing. False, otherwise.
   */
  public boolean isUserPinToBeChanged() {
    return hasFlag(PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED);
  }

  /**
   * Check, if the security officer-PIN has been entered incorrectly at least
   * once since the last successful authentication.
   *
   * @return True, if the the security officer-PIN has been entered
   *         incorrectly at least one since the last successful
   *         authentication. False, otherwise.
   */
  public boolean isSoPinCountLow() {
    return hasFlag(PKCS11Constants.CKF_SO_PIN_COUNT_LOW);
  }

  /**
   * Check, if the security officer has just one try left to supply the
   * correct PIN before the security officer-PIN gets locked.
   *
   * @return True, if the security officer has just one try left to supply the
   *         correct PIN before the security officer-PIN gets locked. False,
   *         otherwise.
   */
  public boolean isSoPinFinalTry() {
    return hasFlag(PKCS11Constants.CKF_SO_PIN_FINAL_TRY);
  }

  /**
   * Check, if the security officer-PIN is locked.
   *
   * @return True, if the security officer-PIN is locked. False, otherwise.
   */
  public boolean isSoPinLocked() {
    return hasFlag(PKCS11Constants.CKF_SO_PIN_LOCKED);
  }

  /**
   * Check, if the security officer PIN value is the default value set by
   * token initialization or manufacturing.
   *
   * @return True, if the security officer PIN value is the default value set
   *         by token initialization or manufacturing. False, otherwise.
   */
  public boolean isSoPinToBeChanged() {
    return hasFlag(PKCS11Constants.CKF_SO_PIN_TO_BE_CHANGED);
  }

  private boolean hasFlag(long mask) {
    return (flags & mask) != 0L;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  @Override
  public String toString() {
    return Util.concatObjectsCap(1000,
      "\nManufacturer ID: ", manufacturerID,
      "\nModel: ", model,
      "\nSerial Number: ", serialNumber,
      "\nFlags: 0x", Functions.toFullHex(flags),
      "\nRandom Number Generator: ", isRNG(),
      "\nWrite protected: ", isWriteProtected(),
      "\nLogin required: ", isLoginRequired(),
      "\nUser PIN initialized: ", isUserPinInitialized(),
      "\nRestore Key not needed: ", isRestoreKeyNotNeeded(),
      "\nClock on Token: ", isClockOnToken(),
      "\nProtected Authentication Path: ", isProtectedAuthenticationPath(),
      "\nDual Crypto Operations: ", isDualCryptoOperations(),
      "\nToken initialized: ", isTokenInitialized(),
      "\nSecondary Authentication: ", isSecondaryAuthentication(),
      "\nUser PIN-Count low: ", isUserPinCountLow(),
      "\nUser PIN final Try: ", isUserPinFinalTry(),
      "\nUser PIN locked: ", isUserPinLocked(),
      "\nUser PIN to be changed: ", isUserPinToBeChanged(),
      "\nSecurity Officer PIN-Count low: ", isSoPinCountLow(),
      "\nSecurity Officer PIN final Try: ", isSoPinFinalTry(),
      "\nSecurity Officer PIN locked: ", isSoPinLocked(),
      "\nSecurity Officer PIN to be changed: ", isSoPinToBeChanged(),
      "\nMaximum Session Count: ", maxCountToString(maxSessionCount),
      "\nSession Count: ", countToString(sessionCount),
      "\nMaximum Read/Write Session Count: ", maxCountToString(maxRwSessionCount),
      "\nRead/Write Session Count: ", countToString(rwSessionCount),
      "\nMaximum PIN Length: ", maxPinLen,
      "\nMinimum PIN Length: ", minPinLen,
      "\nTotal Public Memory: ", countToString(totalPrivateMemory),
      "\nFree Public Memory: ", countToString(freePublicMemory),
      "\nTotal Private Memory: ", countToString(totalPrivateMemory),
      "\nFree Private Memory: ", countToString(freePublicMemory),
      "\nHardware Version: ", hardwareVersion,
      "\nFirmware Version: ", firmwareVersion,
      "\nTime: ", time);
  }

  private static String maxCountToString(long count) {
    if (count == UNAVAILABLE_INFORMATION) {
      return "<Information unavailable>";
    } else {
      return (count == EFFECTIVELY_INFINITE) ? "<effectively infinite>" : Long.toString(count);
    }
  }

  private static String countToString(long count) {
    return (count == UNAVAILABLE_INFORMATION) ? "<Information unavailable>" : Long.toString(count);
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other TokenInfo object.
   * @return True, if other is an instance of Info and all member variables of
   *         both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof TokenInfo)) return false;

    TokenInfo other = (TokenInfo) otherObject;
    return label.equals(other.label)
        && manufacturerID.equals(other.manufacturerID)
        && model.equals(other.model)
        && serialNumber.equals(other.serialNumber)
        && (maxSessionCount == other.maxSessionCount)
        && (sessionCount == other.sessionCount)
        && (maxRwSessionCount == other.maxRwSessionCount)
        && (rwSessionCount == other.rwSessionCount)
        && (maxPinLen == other.maxPinLen)
        && (minPinLen == other.minPinLen)
        && (totalPublicMemory == other.totalPublicMemory)
        && (freePublicMemory == other.freePublicMemory)
        && (totalPrivateMemory == other.totalPrivateMemory)
        && (freePrivateMemory == other.freePrivateMemory)
        && hardwareVersion.equals(other.hardwareVersion)
        && firmwareVersion.equals(other.firmwareVersion)
        && time.equals(other.time)
        && (flags == other.flags);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the label,
   *         manufacturerID, model and serialNumber.
   */
  @Override
  public int hashCode() {
    return label.hashCode() ^ manufacturerID.hashCode() ^ model.hashCode() ^ serialNumber.hashCode();
  }

}
