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

import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;

import static org.xipki.pkcs11.PKCS11Constants.CKF_RW_SESSION;
import static org.xipki.pkcs11.PKCS11Constants.CKF_SERIAL_SESSION;

/**
 * An object of this class provides information about a session. The information
 * provided is just a snapshot at the time this information object was created;
 * it does not retrieve the information from the session on demand.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
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
  public String toString() {
    String text = "State: " + Functions.cksCodeToName(state) +
        "\nDevice Error: 0x" + Long.toHexString(deviceError) + "\nFlags: ";
    return Functions.toStringFlags(text, flags, CKF_RW_SESSION, CKF_SERIAL_SESSION);
  }

}
