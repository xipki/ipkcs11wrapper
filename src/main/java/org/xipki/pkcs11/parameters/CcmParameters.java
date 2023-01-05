// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
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

package org.xipki.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_CCM_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-CCM en/decryption
 *
 * @author Otto Touzil
 * @version 1.0
 */
public class CcmParameters implements Parameters {

    private long dataLen;
    private byte[] nonce;
    private byte[] aad;
    private long macLen;

    /**
     * Create a new CCMParameters object with the given attributes.
     *
     * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^8L. This length should not include the length
     *                  of the MAC that is appended to the cipher text.
     *                  (where L is the size in bytes of the data length's length(2 &lt; L &lt; 8)
     * @param nonce    the nonce
     * @param aad      additional authentication data. This data is authenticated but not encrypted.
     * @param macLen  length of the MAC (output following cipher text) in bytes. Valid values are (4, 6, 8, 10, 12, 14 and 16)
     */
    public CcmParameters(long dataLen, byte[] nonce, byte[] aad, long macLen) {
        this.nonce = Functions.requireNonNull("nonce", nonce);
        Functions.requireRange("nonce.length", nonce.length, 7, 13);
        this.macLen = Functions.requireAmong("macLen", macLen, 4, 6, 8, 10, 12, 14, 16);
        this.dataLen = dataLen;
        this.aad = aad;
    }

    /**
     * Get this parameters object as an object of the CK_CCM_PARAMS class.
     *
     * @return This object as a CK_CCM_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {
        CK_CCM_PARAMS params = new CK_CCM_PARAMS();
        params.pNonce = nonce;
        params.pAAD = aad;
        params.ulMacLen = macLen;
        params.ulDataLen = dataLen;

        return params;
    }

    public void setDataLen(long dataLen) {
        this.dataLen = dataLen;
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
        return "Class: " + getClass().getName() + "\n  DataLen: " + dataLen + ", MacLen: " + macLen +
            "\n  Nonce: " + Functions.toHex(nonce) + "\n  AAD: " + (aad == null ? "null" : Functions.toHex(nonce));
    }

}
