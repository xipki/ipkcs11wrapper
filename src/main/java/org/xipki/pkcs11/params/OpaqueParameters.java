/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
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

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters byte arrays.
 *
 * @author Lijun Liao (xipki)
 */
public class OpaqueParameters implements Parameters {

  private final byte[] bytes;

  public OpaqueParameters(byte[] bytes) {
    this.bytes = Functions.requireNonNull("bytes", bytes);
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

  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  Bytes (hex): " + Functions.toHex(bytes);
  }

}
