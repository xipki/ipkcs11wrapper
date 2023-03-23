// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Objects of this class provide information about a token. Serial number,
 * manufacturer, free memory,... . Notice that this is just a snapshot of the
 * token's status at the time this object was created.
 *
 * @author Karl Scheibelhofer (SIC)
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
  private final Instant time;

  private final CK_TOKEN_INFO ckTokenInfo;

  /**
   * Constructor taking CK_TOKEN_INFO as given returned by
   * PKCS11.C_GetTokenInfo.
   *
   * @param ckTokenInfo
   *          The CK_TOKEN_INFO object as returned by PKCS11.C_GetTokenInfo.
   */
  protected TokenInfo(CK_TOKEN_INFO ckTokenInfo) {
    Functions.requireNonNull("ckTokenInfo", ckTokenInfo);
    label = new String(ckTokenInfo.label).trim();
    manufacturerID = new String(ckTokenInfo.manufacturerID).trim();
    model = new String(ckTokenInfo.model).trim();
    serialNumber = new String(ckTokenInfo.serialNumber).trim();
    hardwareVersion = new Version(ckTokenInfo.hardwareVersion);
    firmwareVersion = new Version(ckTokenInfo.firmwareVersion);

    this.ckTokenInfo = ckTokenInfo;
    Instant time = null;
    try {
      int year   = Integer.parseInt(new String(ckTokenInfo.utcTime,  0, 4));
      int month  = Integer.parseInt(new String(ckTokenInfo.utcTime,  4, 2));
      int day    = Integer.parseInt(new String(ckTokenInfo.utcTime,  6, 2));
      int hour   = Integer.parseInt(new String(ckTokenInfo.utcTime,  8, 2));
      int minute = Integer.parseInt(new String(ckTokenInfo.utcTime, 10, 2));
      int second = Integer.parseInt(new String(ckTokenInfo.utcTime, 12, 2));
      time = ZonedDateTime.of(year, month, day, hour, minute, second, 0, ZoneOffset.UTC).toInstant();
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
    return ckTokenInfo.ulMaxSessionCount;
  }

  /**
   * Get the current number of open sessions.
   *
   * @return The current number of open sessions.
   */
  public long getSessionCount() {
    return ckTokenInfo.ulSessionCount;
  }

  /**
   * Get the maximum allowed number of (open) concurrent read-write sessions.
   *
   * @return The maximum allowed number of (open) concurrent read-write
   *         sessions.
   */
  public long getMaxRwSessionCount() {
    return ckTokenInfo.ulMaxRwSessionCount;
  }

  /**
   * Get the current number of open read-write sessions.
   *
   * @return The current number of open read-write sessions.
   */
  public long getRwSessionCount() {
    return ckTokenInfo.ulRwSessionCount;
  }

  /**
   * Get the maximum length for the PIN.
   *
   * @return The maximum length for the PIN.
   */
  public long getMaxPinLen() {
    return ckTokenInfo.ulMaxPinLen;
  }

  /**
   * Get the minimum length for the PIN.
   *
   * @return The minimum length for the PIN.
   */
  public long getMinPinLen() {
    return ckTokenInfo.ulMinPinLen;
  }

  /**
   * Get the total amount of memory for public objects.
   *
   * @return The total amount of memory for public objects.
   */
  public long getTotalPublicMemory() {
    return ckTokenInfo.ulTotalPublicMemory;
  }

  /**
   * Get the amount of free memory for public objects.
   *
   * @return The amount of free memory for public objects.
   */
  public long getFreePublicMemory() {
    return ckTokenInfo.ulFreePublicMemory;
  }

  /**
   * Get the total amount of memory for private objects.
   *
   * @return The total amount of memory for private objects.
   */
  public long getTotalPrivateMemory() {
    return ckTokenInfo.ulTotalPrivateMemory;
  }

  /**
   * Get the amount of free memory for private objects.
   *
   * @return The amount of free memory for private objects.
   */
  public long getFreePrivateMemory() {
    return ckTokenInfo.ulFreePrivateMemory;
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
  public Instant getTime() {
    return time;
  }

  /**
   * Return the token flags.
   * @return the token flags.
   */
  public long getFlags() {
    return ckTokenInfo.flags;
  }

  public boolean hasFlagBit(long flagMask) {
    return (ckTokenInfo.flags & flagMask) != 0L;
  }

  public boolean isProtectedAuthenticationPath() {
    return hasFlagBit(CKF_PROTECTED_AUTHENTICATION_PATH);
  }

  public boolean isLoginRequired() {
    return hasFlagBit(CKF_LOGIN_REQUIRED);
  }

  public boolean isTokenInitialized() {
    return hasFlagBit(CKF_TOKEN_INITIALIZED);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    final String ni = "\n" + indent;
    String text = indent + "Manufacturer ID:      " + manufacturerID +
        ni + "Model:                " + model +
        ni + "Serial Number:        " + serialNumber +
        ni + "Max Session Count:    " + mct(getMaxSessionCount()) +
        ni + "Session Count:        " + ct(getSessionCount()) +
        ni + "Max RW Session Count: " + mct(getMaxRwSessionCount()) +
        ni + "RW Session Count:     " + ct(getRwSessionCount()) +
        ni + "PIN Length:           [" + getMinPinLen() + ", " + getMaxPinLen() + "]" +
        ni + "Total Private Memory: " + ct(getTotalPrivateMemory()) +
        ni + "Free Private Memory:  " + ct(getFreePrivateMemory()) +
        ni + "Total Public Memory:  " + ct(getTotalPublicMemory()) +
        ni + "Free Public Memory:   " + ct(getFreePublicMemory()) +
        ni + "Hardware Version:     " + hardwareVersion +
        ni + "Firmware Version:     " + firmwareVersion +
        ni + "Time:                 " + time;

    return text + "\n" + Functions.toStringFlags(Category.CKF_TOKEN, indent + "Flags: ", ckTokenInfo.flags,
        CKF_RNG,                    CKF_WRITE_PROTECTED,        CKF_LOGIN_REQUIRED,
        CKF_RESTORE_KEY_NOT_NEEDED, CKF_CLOCK_ON_TOKEN,         CKF_PROTECTED_AUTHENTICATION_PATH,
        CKF_DUAL_CRYPTO_OPERATIONS, CKF_TOKEN_INITIALIZED,      CKF_SECONDARY_AUTHENTICATION,
        CKF_USER_PIN_INITIALIZED,   CKF_USER_PIN_COUNT_LOW,     CKF_USER_PIN_FINAL_TRY,
        CKF_USER_PIN_LOCKED,        CKF_USER_PIN_TO_BE_CHANGED, CKF_SO_PIN_COUNT_LOW,
        CKF_SO_PIN_FINAL_TRY,       CKF_SO_PIN_LOCKED,          CKF_SO_PIN_TO_BE_CHANGED);
  }

  private static String mct(long count) {
    return isUnavailableInformation(count) ? "N/A"
        : (count == CK_EFFECTIVELY_INFINITE) ? "unlimited" : Long.toString(count);
  }

  private static String ct(long count) {
    return isUnavailableInformation(count) ? "N/A" : Long.toString(count);
  }

}
