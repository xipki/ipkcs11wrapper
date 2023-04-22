// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Objects of this class represent slots that can accept tokens. The application
 * can get a token object, if there is one present, by calling getToken.
 * This may look like this:
 * <pre><code>
 *   Token token = slot.getToken();
 *
 *   // to ensure that there is a token present in the slot
 *   if (token != null) {
 *     // ... work with the token
 *   }
 * </code></pre>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class Slot {

  /**
   * The module that created this slot object.
   */
  private final PKCS11Module module;

  /**
   * The identifier of the slot.
   */
  private final long slotID;

  /**
   * True, if UTF8 encoding is used as character encoding for character array
   * attributes and PINs.
   */
  private boolean useUtf8Encoding = true;

  /**
   * The constructor that takes a reference to the module and the slot ID.
   *
   * @param module
   *          The reference to the module of this slot.
   * @param slotID
   *           The identifier of the slot.
   */
  protected Slot(PKCS11Module module, long slotID) {
    this.module = Functions.requireNonNull("module", module);
    this.slotID = slotID;
  }

  /**
   * Specify, whether UTF8 character encoding shall be used for character
   * array attributes and PINs.
   * @param useUtf8Encoding
   *          true, if UTF8 shall be used
   */
  public void setUseUtf8Encoding(boolean useUtf8Encoding) {
    this.useUtf8Encoding = useUtf8Encoding;
  }

  /**
   * Returns whether UTF8 encoding is set.
   * @return true, if UTF8 is used as character encoding for character array
   *         attributes and PINs.
   */
  public boolean isUseUtf8Encoding() {
    return useUtf8Encoding;
  }

  /**
   * Get the module that created this Slot object.
   *
   * @return The module of this slot.
   */
  public PKCS11Module getModule() {
    return module;
  }

  /**
   * Get the ID of this slot. This is the ID returned by the PKCS#11 module.
   *
   * @return The ID of this slot.
   */
  public long getSlotID() {
    return slotID;
  }

  /**
   * Get information about this slot object.
   *
   * @return An object that contains information about this slot.
   * @exception PKCS11Exception
   *              If reading the information fails.
   */
  public SlotInfo getSlotInfo() throws PKCS11Exception {
    try {
      return new SlotInfo(module.getPKCS11Module().C_GetSlotInfo(slotID));
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      throw module.convertException(e);
    }
  }

  /**
   * Get an object for handling the token that is currently present in this
   * slot, or null, if there is no token present.
   *
   * @return The object for accessing the token. Or null, if none is present
   *         in this slot.
   * @exception PKCS11Exception
   *              If determining whether a token is present fails.
   */
  public Token getToken() throws PKCS11Exception {
    return getSlotInfo().isTokenPresent() ? new Token(this) : null;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Slot ID: 0x" + Long.toHexString(slotID) + "\nModule: " + module;
  }

}
