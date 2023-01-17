// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11;

import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * An object of this class provides information about a session. The information
 * provided is just a snapshot at the time this information object was created;
 * it does not retrieve the information from the session on demand.
 *
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class SessionInfo {

  /**
   * The identifier of the slot in which the token resides this session is
   * bound to.
   */
  private final long slotID;

  /**
   * The current session state.
   */
  private final long state;

  /**
   * A token specific error-code. The meaning of this value is not defined in
   * PKCS#11.
   */
  private final long deviceError;

  /**
   * The flags.
   */
  private final long flags;

  /**
   * Constructor taking a CK_SESSION_INFO object that provides the
   * information.
   *
   * @param ckSessionInfo
   *          The object providing the session information.
   */
  protected SessionInfo(CK_SESSION_INFO ckSessionInfo) {
    Functions.requireNonNull("ckSessionInfo", ckSessionInfo);
    this.slotID = ckSessionInfo.slotID;
    this.state = ckSessionInfo.state;
    this.deviceError = ckSessionInfo.ulDeviceError;
    this.flags = ckSessionInfo.flags;
  }

  /**
   * Get the current state of this session.
   *
   * @return The current state of this session.
   */
  public long getState() {
    return state;
  }

  /**
   * Get the current device error-code of the token. Notice that this code is
   * device-specific. Its meaning is not defined in the PKCS#11 standard.
   *
   * @return The error-code of the device.
   */
  public long getDeviceError() {
    return deviceError;
  }

  /**
   * Check, if this is a read-write session.
   *
   * @return True, if this is a read-write session; false, if this is a
   *         read-only session.
   */
  public boolean isRwSession() {
    return (flags & CKF_RW_SESSION) != 0L;
  }

  /**
   * Check, if this is a serial session. Should always be true for version 2.x
   * of the PKCS#11 standard.
   *
   * @return True, if this is a serial session; false, if this is a parallel
   *         session. Should always be true for version 2.x of the PKCS#11
   *         standard.
   */
  public boolean isSerialSession() {
    return (flags & CKF_SERIAL_SESSION) != 0L;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  @Override
  public String toString() {
    String text = "State: " + codeToName(Category.CKS, state) + "\nSlot ID: " + slotID +
        "\nDevice Error: 0x" + Long.toHexString(deviceError) + "\n";
    return text + Functions.toStringFlags(Category.CKF_SESSION, "Flags: ", flags, CKF_RW_SESSION, CKF_SERIAL_SESSION);
  }

}
