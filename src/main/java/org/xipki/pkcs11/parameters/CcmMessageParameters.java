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

import iaik.pkcs.pkcs11.wrapper.CK_CCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM message en/decryption.
 *
 * @author Patrick Schuster
 * @author Lijun Liao (xipki)
 */
public class CcmMessageParameters implements MessageParameters {

    private int dataLen;
    private byte[] nonce;
    private long nonceFixedBits;
    private long nonceGenerator;
    private byte[] mac;

    /**
     * Create a new CcmMessageParameters object with the given attributes.
     *
     * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^(8L).
     * @param nonce the nonce. length: 7 &le; ulNonceLen &le; 13.
     * @param nonceFixedBits number of bits of the original nonce to preserve when generating a <br>
     *                     new nonce. These bits are counted from the Most significant bits (to the right).
     * @param nonceGenerator Function used to generate a new nonce. Each nonce must be
     *                          unique for a given session.
     * @param mac CCM MAC returned on MessageEncrypt, provided on MessageDecrypt
     */
    public CcmMessageParameters(int dataLen, byte[] nonce, long nonceFixedBits, long nonceGenerator, byte[] mac) {
        init(dataLen, nonce, nonceFixedBits, nonceGenerator, mac);
    }

    private void init(int dataLen, byte[] nonce, long nonceFixedBits, long nonceGenerator, byte[] mac) {
        this.dataLen = dataLen;
        this.nonce = nonce;
        this.nonceFixedBits = nonceFixedBits;
        this.nonceGenerator = nonceGenerator;
        this.mac = mac;
    }

    /**
     * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
     *
     * @return This object as a CK_CCM_MESSAGE_PARAMS object.
     */
    public CK_CCM_MESSAGE_PARAMS getPKCS11ParamsObject() {
        CK_CCM_MESSAGE_PARAMS params = new CK_CCM_MESSAGE_PARAMS();
        params.ulDataLen = dataLen;
        params.pNonce = nonce;
        params.ulNonceFixedBits = nonceFixedBits;
        params.nonceGenerator = nonceGenerator;
        params.pMAC = mac;

        return params;
    }

    /**
     * Read the parameters from the PKCS11Object and overwrite the values into this object.
     *
     * @param obj Object to read the parameters from
     */
    public void setValuesFromPKCS11Object(Object obj) {
        CK_CCM_MESSAGE_PARAMS params = (CK_CCM_MESSAGE_PARAMS) obj;
        init((int) params.ulDataLen, params.pNonce, params.ulNonceFixedBits, params.nonceGenerator, params.pMAC);
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
        return "Class: " + getClass().getName() + "\n  DataLen: " + dataLen + ", NonceFixedBits: " + nonceFixedBits +
            "\n  Nonce: " + Functions.toHex(nonce) + "\n  MAC: " + Functions.toHex(mac);
    }

}

