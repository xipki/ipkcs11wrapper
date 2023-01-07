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

import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Objects of this class provide information about a token. Serial number,
 * manufacturer, free memory,... . Notice that this is just a snapshot of the
 * token's status at the time this object was created.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class TokenInfo {

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
    Functions.requireNonNull("ckTokenInfo", ckTokenInfo);
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
    flags = ckTokenInfo.flags;

    Date time = null;
    try {
      SimpleDateFormat utc = new SimpleDateFormat("yyyyMMddhhmmss");
      utc.setTimeZone(TimeZone.getTimeZone("UTC"));
      time = utc.parse(new String(ckTokenInfo.utcTime, 0, ckTokenInfo.utcTime.length - 2));
    } catch (Exception ex) {
    }
    this.time = time;
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

  public boolean hasFlagBit(long flagMask) {
    return (flags & flagMask) != 0L;
  }

  public boolean isProtectedAuthenticationPath() {
    return hasFlagBit(CKF_PROTECTED_AUTHENTICATION_PATH);
  }

  public boolean isLoginRequired() {
    return hasFlagBit(CKF_LOGIN_REQUIRED);
  }

  protected boolean isTokenInitialized() {
    return hasFlagBit(CKF_TOKEN_INITIALIZED);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  public String toString() {
    String text = "Manufacturer ID:      " + manufacturerID         +
        "\nModel:                " + model                  + "\nSerial Number:        " + serialNumber +
        "\nMax Session Count:    " + mct(maxSessionCount)   + "\nSession Count:        " + ct(sessionCount) +
        "\nMax RW Session Count: " + mct(maxRwSessionCount) + "\nRW Session Count:     " + ct(rwSessionCount) +
        "\nMaxPIN Length:        " + maxPinLen              + "\nMin PIN Length:       " + minPinLen +
        "\nTotal Private Memory: " + ct(totalPrivateMemory) + "\nFree Public Memory:   " + ct(freePublicMemory) +
        "\nTotal Private Memory: " + ct(totalPrivateMemory) + "\nFree Public Memory:   " + ct(freePublicMemory) +
        "\nHardware Version:     " + hardwareVersion        + "\nFirmware Version:     " + firmwareVersion +
        "\nTime:                 " + time                   + "\nFlags:                ";

    return Functions.toStringFlags(text, flags, CKF_RNG, CKF_WRITE_PROTECTED, CKF_LOGIN_REQUIRED,
        CKF_RESTORE_KEY_NOT_NEEDED, CKF_CLOCK_ON_TOKEN, CKF_PROTECTED_AUTHENTICATION_PATH, CKF_DUAL_CRYPTO_OPERATIONS,
        CKF_TOKEN_INITIALIZED, CKF_SECONDARY_AUTHENTICATION, CKF_USER_PIN_INITIALIZED, CKF_USER_PIN_COUNT_LOW,
        CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED, CKF_USER_PIN_TO_BE_CHANGED, CKF_SO_PIN_COUNT_LOW,
        CKF_SO_PIN_FINAL_TRY, CKF_SO_PIN_LOCKED, CKF_SO_PIN_TO_BE_CHANGED);
  }

  private static String mct(long count) {
    return (count == CK_UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
        : (count == CK_EFFECTIVELY_INFINITE) ? "<effectively infinite>" : Long.toString(count);
  }

  private static String ct(long count) {
    return (count == CK_UNAVAILABLE_INFORMATION) ? "<Information unavailable>" : Long.toString(count);
  }

}
