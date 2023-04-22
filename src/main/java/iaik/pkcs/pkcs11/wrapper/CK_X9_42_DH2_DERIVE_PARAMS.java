// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_X9_42_DH2_DERIVE_PARAMS provides the parameters to the CKM_X9_42_DH_HYBRID_DERIVE and
 * CKM_X9_42_MQV_DERIVE mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
 *   CK_X9_42_DH_KDF_TYPE  kdf;
 *   CK_ULONG              ulOtherInfoLen;
 *   CK_BYTE_PTR           pOtherInfo;
 *   CK_ULONG              ulPublicDataLen;
 *   CK_BYTE_PTR           pPublicData;
 *   CK_ULONG              ulPrivateDataLen;
 *   CK_OBJECT_HANDLE      hPrivateData;
 *   CK_ULONG              ulPublicDataLen2;
 *   CK_BYTE_PTR           pPublicData2;
 * } CK_X9_42_DH2_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_X9_42_DH2_DERIVE_PARAMS extends KdfParams {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulOtherInfoLen;
   * CK_BYTE_PTR pOtherInfo;
   * </PRE>
   */
  public byte[] pOtherInfo;

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
