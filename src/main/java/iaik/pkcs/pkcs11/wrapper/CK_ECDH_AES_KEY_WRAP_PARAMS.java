// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_ECDH_AES_KEY_WRAP_PARAMS {
 *   CK_ULONG        ulAESKeyBits;
 *   CK_EC_KDF_TYPE  kdf;
 *   CK_ULONG        ulSharedDataLen;
 *   CK_BYTE_PTR     pSharedData;
 * } CK_ECDH_AES_KEY_WRAP_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_ECDH_AES_KEY_WRAP_PARAMS {
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulAESKeyBits
     * </PRE>
     */
    public long ulAESKeyBits;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_EC_KDF_TYPE     kdf;
     * </PRE>
     */
    public long kdf;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pSharedData;
     * CK_ULONG ulSharedDataLen;
     * </PRE>
     */
    public byte[] pSharedData;

}
