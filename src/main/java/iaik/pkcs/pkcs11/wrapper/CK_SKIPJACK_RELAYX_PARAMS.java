// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the CKM_SKIPJACK_RELAYX mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SKIPJACK_RELAYX_PARAMS {
 *   CK_ULONG ulOldWrappedXLen;
 *   CK_BYTE_PTR pOldWrappedX;
 *   CK_ULONG ulOldPasswordLen;
 *   CK_BYTE_PTR pOldPassword;
 *   CK_ULONG ulOldPublicDataLen;
 *   CK_BYTE_PTR pOldPublicData;
 *   CK_ULONG ulOldRandomLen;
 *   CK_BYTE_PTR pOldRandomA;
 *   CK_ULONG ulNewPasswordLen;
 *   CK_BYTE_PTR pNewPassword;
 *   CK_ULONG ulNewPublicDataLen;
 *   CK_BYTE_PTR pNewPublicData;
 *   CK_ULONG ulNewRandomLen;
 *   CK_BYTE_PTR pNewRandomA;
 * } CK_SKIPJACK_RELAYX_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SKIPJACK_RELAYX_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pOldWrappedX;
   * CK_ULONG ulOldWrappedXLen;
   * </PRE>
   */
  public byte[] pOldWrappedX;

  /**
   * <B>PKCS#11:</B>
   *
   */
  public byte[] pOldPassword;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pOldPublicData;
   * CK_ULONG ulOldPublicDataLen;
   * </PRE>
   */
  public byte[] pOldPublicData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pOldRandomA;
   * CK_ULONG ulOldRandomLen;
   * </PRE>
   */
  public byte[] pOldRandomA;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pNewPassword;
   * CK_ULONG ulNewPasswordLen;
   * </PRE>
   */
  public byte[] pNewPassword;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pNewPublicData;
   * CK_ULONG ulNewPublicDataLen;
   * </PRE>
   */
  public byte[] pNewPublicData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pNewRandomA;
   * CK_ULONG ulNewRandomLen;
   * </PRE>
   */
  public byte[] pNewRandomA;

}
