// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_KEA_DERIVE_PARAMS provides the parameters to the CKM_KEA_DERIVE mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_KEA_DERIVE_PARAMS {
 *   CK_BBOOL     isSender;
 *   CK_ULONG     ulRandomLen;
 *   CK_BYTE_PTR  pRandomA;
 *   CK_BYTE_PTR  pRandomB;
 *   CK_ULONG     ulPublicDataLen;
 *   CK_BYTE_PTR  pPublicData;
 * } CK_KEA_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_KEA_DERIVE_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BBOOL isSender;
   * </PRE>
   */
  public boolean isSender;

  /**
   * ulRandomLen == pRandomA.length == pRandomB.length
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pRandomA;
   * CK_ULONG ulRandomLen;
   * </PRE>
   */
  public byte[] pRandomA;

  /**
   * ulRandomLen == pRandomA.length == pRandomB.length
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pRandomB;
   * CK_ULONG ulRandomLen;
   * </PRE>
   */
  public byte[] pRandomB;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pPublicData;
   * CK_ULONG ulPublicDataLen;
   * </PRE>
   */
  public byte[] pPublicData;

}
