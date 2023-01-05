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
 * @see SlotInfo
 * @see Token
 * @author Karl Scheibelhofer
 * @version 1.0
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
   * @exception TokenException
   *              If reading the information fails.
   */
  public SlotInfo getSlotInfo() throws TokenException {
    return new SlotInfo(module.getPKCS11Module().C_GetSlotInfo(slotID));
  }

  /**
   * Get an object for handling the token that is currently present in this
   * slot, or null, if there is no token present.
   *
   * @return The object for accessing the token. Or null, if none is present
   *         in this slot.
   * @exception TokenException
   *              If determining whether a token is present fails.
   */
  public Token getToken() throws TokenException {
    return getSlotInfo().isTokenPresent() ? new Token(this) : null;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  public String toString() {
    return "Slot ID: 0x" + Long.toHexString(slotID) + "\nModule: " + module;
  }

}
