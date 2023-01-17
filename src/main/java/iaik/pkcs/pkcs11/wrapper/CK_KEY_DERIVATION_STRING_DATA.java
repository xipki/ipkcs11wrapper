// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_KEY_DERIVATION_STRING_DATA holds a byte string and the byte string's length. It provides
 * the parameters for the CKM_CONCATENATE_BASE_AND_DATA, CKM_CONCATENATE_DATA_AND_BASE, and
 * CKM_XOR_BASE_AND_DATA mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_KEY_DERIVATION_STRING_DATA {&nbsp;&nbsp;
 *    CK_BYTE_PTR pData;&nbsp;&nbsp;
 *    CK_ULONG ulLen;&nbsp;&nbsp;
 *  } CK_KEY_DERIVATION_STRING_DATA;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_KEY_DERIVATION_STRING_DATA {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pData;
   * CK_ULONG ulLen;
   * </PRE>
   */
  public byte[] pData;

  // CK_ULONG ulLen;
  // ulLen == pData.length

}
