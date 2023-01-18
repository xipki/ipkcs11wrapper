// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_CCM_PARAMS {
 *   CK_ULONG     ulDataLen; //plaintext or ciphertext
 *   CK_BYTE_PTR  pNonce;
 *   CK_ULONG     ulNonceLen;
 *   CK_BYTE_PTR  pAAD;
 *   CK_ULONG     ulAADLen;
 *   CK_ULONG     ulMACLen;
 * } CK_CCM_PARAMS;
 * </PRE>
 *
 * @author Otto Touzil (SIC)
 */
public class CK_CCM_PARAMS {

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulDataLen;
     * </PRE>
     */
    public long ulDataLen;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulNonceLen;
     * CK_BYTE_PTR nNonce;
     * </PRE>
     */
    public byte[] pNonce;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulADDLen;
     * CK_BYTE_PTR pAAD;
     * </PRE>
     */
    public byte[] pAAD;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulMACLen;
     * </PRE>
     */
    public long ulMacLen;

}

