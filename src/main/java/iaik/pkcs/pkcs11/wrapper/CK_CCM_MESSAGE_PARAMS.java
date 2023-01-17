// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 typedef struct CK_CCM_MESSAGE_PARAMS {
 CK_ULONG
        ulDataLen; plaintext or ciphertext
        CK_BYTE_PTR pNonce;
        CK_ULONG
        ulNonceLen;
        CK_ULONG
        ulNonceFixedBits;
        CK_GENERATOR_FUNCTION
        nonceGenerator;
        CK_BYTE_PTR pMAC;
        CK_ULONG
        ulMACLen;
        } CK_CCM_MESSAGE_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_CCM_MESSAGE_PARAMS {

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
     * CK_BYTE_PTR pNonce;
     * CK_ULONG ulNonceLen;
     * </PRE>
     */

    public byte[] pNonce;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulNonceFixedBits;
     * </PRE>
     */
    public long ulNonceFixedBits;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_GENERATOR_FUNCTION nonceGenerator;
     * </PRE>
     */
    public long nonceGenerator;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pMAC;
     * CK_ULONG ulMACLen;
     * </PRE>
     *
     */
    public byte[] pMAC;

}

