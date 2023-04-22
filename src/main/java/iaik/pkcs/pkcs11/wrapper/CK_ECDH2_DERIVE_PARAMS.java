// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_ECDH2_DERIVE_PARAMS provides the parameters to the CKM_ECMQV_DERIVE mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ECDH2_DERIVE_PARAMS {
 *   CK_EC_KDF_TYPE    kdf;
 *   CK_ULONG          ulSharedDataLen;
 *   CK_BYTE_PTR       pSharedData;
 *   CK_ULONG          ulPublicDataLen;
 *   CK_BYTE_PTR       pPublicData;
 *   CK_ULONG          ulPrivateDataLen;
 *   CK_OBJECT_HANDLE  hPrivateData;
 *   CK_ULONG          ulPublicDataLen2;
 *   CK_BYTE_PTR       pPublicData2;
 * } CK_ECDH2_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_ECDH2_DERIVE_PARAMS extends KdfParams {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulSharedDataLen;
   * CK_BYTE_PTR pSharedData;
   * </PRE>
   */
  public byte[] pSharedData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen;
   * CK_BYTE_PTR pPublicData;
   * </PRE>
   */
  public byte[] pPublicData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPrivateDataLen;
   * </PRE>
   */
  public long ulPrivateDataLen;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hPrivateData;
   * </PRE>
   */
  public long hPrivateData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen2;
   * CK_BYTE_PTR pPublicData2;
   * </PRE>
   */
  public byte[] pPublicData2;

}
