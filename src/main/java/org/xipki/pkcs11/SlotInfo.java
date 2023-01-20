// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

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
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
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
    this.slotDescription = new String(ckSlotInfo.slotDescription).trim();
    this.manufacturerID = new String(ckSlotInfo.manufacturerID).trim();
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
  @Override
  public String toString() {
    String text = "Slot Description: " + slotDescription + "\nManufacturer ID: " + manufacturerID +
        "\nHardware Version: " + hardwareVersion + "\nFirmware Version: " + firmwareVersion + "\n";
    return text + Functions.toStringFlags(Category.CKF_TOKEN, "Flags: ", flags,
        CKF_TOKEN_PRESENT, CKF_REMOVABLE_DEVICE, CKF_HW_SLOT);
  }

}
