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

import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Objects of this call provide information about a slot. A slot can be a
 * smart card reader, for instance. Notice that this object is immutable; i.e.
 * it gets its state at object creation and does not alter afterwards. Thus,
 * all information this object provides, is a snapshot at the object creation.
 * This is especially important when calling isTokenPresent().
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class SlotInfo {

  /**
   * A short description of this slot.
   */
  private final String slotDescription;

  /**
   * A string identifying the manufacturer of this slot.
   */
  private final String manufacturerID;

  /**
   * The version of the slot's hardware.
   */
  private final Version hardwareVersion;

  /**
   * The version of the slot's firmware.
   */
  private final Version firmwareVersion;

  /**
   * The flags.
   */
  private final long flags;

  /**
   * Constructor that takes the CK_SLOT_INFO object as given by
   * PKCS11.C_GetSlotInfo().
   *
   * @param ckSlotInfo
   *          The CK_SLOT_INFO object as given by PKCS11.C_GetSlotInfo().
   */
  protected SlotInfo(CK_SLOT_INFO ckSlotInfo) {
    Functions.requireNonNull("ckSlotInfo", ckSlotInfo);
    this.slotDescription = new String(ckSlotInfo.slotDescription);
    this.manufacturerID = new String(ckSlotInfo.manufacturerID);
    this.hardwareVersion = new Version(ckSlotInfo.hardwareVersion);
    this.firmwareVersion = new Version(ckSlotInfo.firmwareVersion);
    this.flags = ckSlotInfo.flags;
  }

  /**
   * Get a short description of this slot.
   *
   * @return A string describing this slot.
   */
  public String getSlotDescription() {
    return slotDescription;
  }

  /**
   * Get an identifier for the manufacturer of this slot.
   *
   * @return A string identifying the manufacturer of this slot.
   */
  public String getManufacturerID() {
    return manufacturerID;
  }

  /**
   * Get the version of the slot's hardware.
   *
   * @return The version of the hardware of this slot.
   */
  public Version getHardwareVersion() {
    return hardwareVersion;
  }

  /**
   * Get the version of the slot's firmware.
   *
   * @return The version of the firmware of this slot.
   */
  public Version getFirmwareVersion() {
    return firmwareVersion;
  }

  /**
   * Indicates, if there is a token present in this slot. Notice, that this
   * refers to the time this object was created and not when this method is
   * invoked.
   *
   * @return True, if there is a (compatible) token in the slot. False,
   *         otherwise.
   */
  public boolean isTokenPresent() {
    return (flags & CKF_TOKEN_PRESENT) != 0L;
  }

  /**
   * Indicate, if the token is removable from this slot or not. In some
   * cases slot and token will be one device.
   *
   * @return True, if the tokens are removable. False, otherwise.
   */
  public boolean isRemovableDevice() {
    return (flags & CKF_REMOVABLE_DEVICE) != 0L;
  }

  /**
   * Indicate, if the token is a hardware device or if it is just a pure
   * software implementation; e.g. in case of a pure software token.
   *
   * @return True, if it is a hardware slot. False, otherwise.
   */
  public boolean isHwSlot() {
    return (flags & CKF_HW_SLOT) != 0L;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  public String toString() {
    String text = "Slot Description: " + slotDescription + "\nManufacturer ID: " + manufacturerID +
        "\nHardware Version: " + hardwareVersion + "\nFirmware Version: " + firmwareVersion + "\nFlags: ";
    return Functions.toStringFlags(text, flags, CKF_TOKEN_PRESENT, CKF_REMOVABLE_DEVICE, CKF_HW);
  }

}
