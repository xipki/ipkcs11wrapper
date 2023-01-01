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
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;

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
    Util.requireNonNull("ckSlotInfo", ckSlotInfo);
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
    return (flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0L;
  }

  /**
   * Indicate, if the token is removable from this slot or not. In some
   * cases slot and token will be one device.
   *
   * @return True, if the tokens are removable. False, otherwise.
   */
  public boolean isRemovableDevice() {
    return (flags & PKCS11Constants.CKF_REMOVABLE_DEVICE) != 0L;
  }

  /**
   * Indicate, if the token is a hardware device or if it is just a pure
   * software implementation; e.g. in case of a pure software token.
   *
   * @return True, if it is a hardware slot. False, otherwise.
   */
  public boolean isHwSlot() {
    return (flags & PKCS11Constants.CKF_HW_SLOT) != 0L;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of object
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(200)
        .append("Slot Description: ").append(slotDescription)
        .append("\nManufacturer ID: ").append(manufacturerID)
        .append("\nHardware Version: ").append(hardwareVersion)
        .append("\nFirmware Version: ").append(firmwareVersion)
        .append("\nFlags: 0X").append(Functions.toFullHex(flags));
    TokenInfo.addFlag(sb, "token present", isTokenPresent());
    TokenInfo.addFlag(sb, "removable device", isRemovableDevice());
    TokenInfo.addFlag(sb, "hardware slot", isHwSlot());
    return sb.toString();
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other SlotInfo object.
   * @return True, if other is an instance of Info and all member variables of
   *         both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof SlotInfo)) return false;

    SlotInfo other = (SlotInfo) otherObject;
    return slotDescription.equals(other.slotDescription) && manufacturerID.equals(other.manufacturerID)
        && hardwareVersion.equals(other.hardwareVersion) && firmwareVersion.equals(other.firmwareVersion)
        && (flags == other.flags);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the slotDescription,
   *         manufacturerID, hardwareVersion and firmwareVersion.
   */
  @Override
  public int hashCode() {
    return slotDescription.hashCode() ^ manufacturerID.hashCode()
        ^ hardwareVersion.hashCode() ^ firmwareVersion.hashCode();
  }

}
