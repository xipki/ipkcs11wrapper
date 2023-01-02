/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.Util;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao
 */
public class OpaqueParameters implements Parameters {

  private byte[] bytes;

  public OpaqueParameters(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Get this parameters object as a byte array.
   *
   * @return This object as a byte array.
   */
  @Override
  public byte[] getPKCS11ParamsObject() {
    return bytes;
  }

  /**
   * Get the public value of the other party in the key agreement protocol.
   *
   * @return The public value of the other party in the key agreement
   *         protocol.
   */
  public byte[] getBytes() {
    return bytes;
  }

  public void setBytes(byte[] bytes) {
    this.bytes = Util.requireNonNull("bytes", bytes);
  }

  @Override
  public String toString() {
    return "  Bytes (hex): " + Util.toHex(bytes);
  }

}
