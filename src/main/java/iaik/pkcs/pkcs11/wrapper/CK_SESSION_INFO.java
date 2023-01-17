// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SESSION_INFO provides information about a session.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SESSION_INFO {&nbsp;&nbsp;
 *   CK_SLOT_ID slotID;&nbsp;&nbsp;
 *   CK_STATE state;&nbsp;&nbsp;
 *   CK_FLAGS flags;&nbsp;&nbsp;
 *   CK_ULONG ulDeviceError;&nbsp;&nbsp;
 * } CK_SESSION_INFO;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SESSION_INFO {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_SLOT_ID slotID;
   * </PRE>
   */
  public long slotID;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_STATE state;
   * </PRE>
   */
  public long state;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags; /* see below */

  /*
   * ulDeviceError was changed from CK_USHORT to CK_ULONG for v2.0
   */
  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulDeviceError;
   * </PRE>
   */
  public long ulDeviceError; /* device-dependent error code */

}
