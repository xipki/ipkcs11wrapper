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

import iaik.pkcs.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Implementation;

import java.io.IOException;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * <p>
 * Objects of this class represent a PKCS#11 module. The application should
 * create an instance by calling getInstance and passing the name of the
 * PKCS#11 module of the desired token; e.g. "slbck.dll". The application
 * must give the full path of the PKCS#11 module unless the module is in the
 * system's search path or in the path of the java.library.path system
 * property.
 * <p>
 * According to the specification, the application must call the initialize
 * method before calling any other method of the module.
 * This class contains slot and token management functions as defined by the
 * PKCS#11 standard.
 *
 * All applications using this library will contain the following code.
 * <pre><code>
 *      PKCS11Module pkcs11Module = PKCS11Module.getInstance("cryptoki.dll");
 *      pkcs11Module.initialize(new DefaultInitializeArgs);
 *
 *      // ... work with the module
 *
 *      pkcs11Module.finalize(null);
 * </code></pre>
 * Instead of <code>cryptoki.dll</code>, the application will use the name of
 * the PKCS#11 module of the installed crypto hardware.
 * After the application initialized the module, it can get a list of all
 * available slots. A slot is an object that represents a physical or logical
 * device that can accept a cryptographic token; for instance, the card slot of
 * a smart card reader. The application can call
 * <pre><code>
 * Slot[] slots = pkcs11Module.getSlotList(false);
 * </code></pre>
 * to get a list of all available slots or
 * <pre><code>
 * Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
 * </code></pre>
 * to get a list of all those slots in which there is a currently a token
 * present.
 * <p>
 * To wait for the insertion of a token, the application can use the
 * <code>waitForSlotEvent</code> method. For example, the method call
 * <pre><code>
 * Slot eventSlot = pkcs11Module.waitForSlotEvent(true, null);
 * </code></pre>
 * will block until an event for any slot of this module occurred. Usually such
 * an event is the insertion of a token. However, the application should check
 * if the event occurred in the slot of interest and if there is really a token
 * present in the slot.
 *
 * @see iaik.pkcs.pkcs11.Info
 * @see iaik.pkcs.pkcs11.Slot
 * @author Karl Scheibelhofer
 * @version 1.0
 */

public class PKCS11Module {

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private final PKCS11 pkcs11;

  private final String pkcs11ModulePath;

  private VendorCode vendorCode;

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param pkcs11
   *          The PKCS#11 module to interact with the token.
   */
  protected PKCS11Module(PKCS11 pkcs11, String pkcs11ModulePath) {
    this.pkcs11 = Functions.requireNonNull("pkcs11", pkcs11);
    this.pkcs11ModulePath = pkcs11ModulePath;
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module; e.g. "slbck.dll". Tries
   * to load the PKCS#11 wrapper native library from the class path (jar file) or library path.
   *
   * @param pkcs11ModulePath
   *          The path of the module; e.g. "/path/to/slbck.dll".
   * @return An instance of Module that is connected to the given PKCS#11 module.
   * @exception IOException
   *              If connecting to the named module fails.
   * @preconditions (pkcs11ModuleName != null) and (pkcs11ModuleName is a valid PKCS#11 module name)
   *
   */
  public static PKCS11Module getInstance(String pkcs11ModulePath) throws IOException {
    Functions.requireNonNull("pkcs11ModulePath", pkcs11ModulePath);
    return new PKCS11Module(new PKCS11Implementation(pkcs11ModulePath), pkcs11ModulePath);
  }

  VendorCode getVendorCode() {
    return vendorCode;
  }

  public void setVendorCode(VendorCode vendorCode) {
    this.vendorCode = vendorCode;
  }

  /**
   * Gets information about the module; i.e. the PKCS#11 module behind.
   *
   * @return An object holding information about the module.
   * @exception TokenException
   *              If getting the information fails.
   */
  public Info getInfo() throws TokenException {
    return new Info(pkcs11.C_GetInfo());
  }

  /**
   * Initializes the module. The application must call this method before
   * calling any other method of the module.
   *
   * @param initArgs
   *          The initialization arguments for the module as defined in
   *          PKCS#11. May be null.
   * @exception TokenException
   *              If initialization fails.
   */
  public void initialize(InitializeArgs initArgs) throws TokenException {
    if (initArgs == null) {
      initArgs = new DefaultInitializeArgs();
    }

    final MutexHandler mutexHandler = initArgs.getMutexHandler();
    CK_C_INITIALIZE_ARGS wrapperInitArgs = new CK_C_INITIALIZE_ARGS();
    wrapperInitArgs.CreateMutex  = mutexHandler == null ? null : mutexHandler::createMutex;
    wrapperInitArgs.DestroyMutex = mutexHandler == null ? null : mutexHandler::destroyMutex;
    wrapperInitArgs.LockMutex    = mutexHandler == null ? null : mutexHandler::lockMutex;
    wrapperInitArgs.UnlockMutex  = mutexHandler == null ? null : mutexHandler::unlockMutex;

    if (initArgs.isLibraryCantCreateOsThreads()) {
      wrapperInitArgs.flags |= CKF_LIBRARY_CANT_CREATE_OS_THREADS;
    }
    if (initArgs.isOsLockingOk()) {
      wrapperInitArgs.flags |= CKF_OS_LOCKING_OK;
    }
    wrapperInitArgs.pReserved = initArgs.getReserved();

    // pReserved of CK_C_INITIALIZE_ARGS not used yet, just set to standard conform UTF8
    pkcs11.C_Initialize(wrapperInitArgs, true);

    Info info = getInfo();
    VendorCode vendorCode = null;
    try {
      vendorCode = VendorCode.getVendorCode(pkcs11ModulePath, info.getManufacturerID(),
          info.getLibraryDescription(), info.getLibraryVersion());
    } catch (IOException e) {
      System.err.println("Error loading vendorcode: " + e.getMessage());
    }
    setVendorCode(vendorCode);
  }

  /**
   * Finalizes this module. The application should call this method when it finished using the
   * module. Note that this method is different from the <code>finalize</code> method, which is the
   * reserved Java method called by the garbage collector. This method calls the
   * <code>C_Finalize(Object)</code> method of the underlying PKCS11 module.
   *
   * @param args
   *          Must be null in version 2.x of PKCS#11.
   * @exception TokenException
   *              If finalization fails.
   * @preconditions (args == null)
   *
   */
  public void finalize(Object args) throws TokenException {
    pkcs11.C_Finalize(args);
  }

  /**
   * Gets a list of slots that can accept tokens that are compatible with this
   * module; e.g. a list of PC/SC smart card readers. The parameter determines
   * if the method returns all compatible slots or only those in which there
   * is a compatible token present.
   *
   * @param tokenPresent
   *          Whether only slots with present token are returned.
   * @return An array of Slot objects, may be an empty array but not null.
   * @exception TokenException
   *              If error occurred.
   */
  public Slot[] getSlotList(boolean tokenPresent) throws TokenException {
    long[] slotIDs = pkcs11.C_GetSlotList(tokenPresent);
    Slot[] slots = new Slot[slotIDs.length];
    for (int i = 0; i < slots.length; i++) {
      slots[i] = new Slot(this, slotIDs[i]);
    }

    return slots;
  }

  /**
   * Waits for a slot event. That can be that a token was inserted or
   * removed. It returns the Slot for which an event occurred. The dontBlock
   * parameter can have the value false (BLOCK) or true (DONT_BLOCK).
   * If there is no event present and the method is called with true this
   * method throws an exception with the error code CKR_NO_EVENT (0x00000008).
   *
   * @param dontBlock
   *          Can false (BLOCK) or true (DONT_BLOCK).
   * @return The slot for which an event occurred.
   * @exception TokenException
   *              If the method was called with WaitingBehavior.DONT_BLOCK but
   *              there was no event available, or if an error occurred.
   */
  public Slot waitForSlotEvent(boolean dontBlock) throws TokenException {
    long slotID = pkcs11.C_WaitForSlotEvent(dontBlock ? CKF_DONT_BLOCK : 0L, null);
    return new Slot(this, slotID);
  }

  /**
   * Gets the PKCS#11 module of the wrapper package behind this object.
   *
   * @return The PKCS#11 module behind this object.
   */
  public PKCS11 getPKCS11Module() {
    return pkcs11;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  @Override
  public String toString() {
    return (pkcs11 != null) ? pkcs11.toString() : "null";
  }

}
