// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import java.util.Arrays;
import java.util.Objects;

/**
 * Identifier of a PKCS#11 key Object.
 *
 * @author Lijun Liao (xipki)
 */

public class PKCS11KeyId {

  private final long handle;

  private final long keyType;

  private final long objectCLass;

  private final byte[] id;

  private final String idHex;

  private final String label;

  private Long publicKeyHandle;

  /**
   * Constructor.
   *
   * @param handle The object handle.
   * @param objectClass The object handle.
   * @param keyType The key type.
   * @param id Identifier. Cannot be null or zero-length if label is {@code null} or blank.
   * @param label Label. Cannot be {@code null} and blank if id is null or zero-length.
   */
  public PKCS11KeyId(long handle, long objectClass, long keyType, byte[] id, String label) {
    this.handle = handle;
    this.objectCLass = objectClass;
    this.keyType = keyType;
    if (id == null || id.length == 0) {
      this.id = null;
      this.idHex = null;
      this.label = label;
    } else {
      this.id = id;
      this.idHex = Functions.toHex(id);
      this.label = label;
    }
  }

  public long getKeyType() {
    return keyType;
  }

  public long getObjectCLass() {
    return objectCLass;
  }

  public long getHandle() {
    return handle;
  }

  public byte[] getId() {
    return id;
  }

  public String getIdHex() {
    return idHex;
  }

  public String getLabel() {
    return label;
  }

  public Long getPublicKeyHandle() {
    return publicKeyHandle;
  }

  public void setPublicKeyHandle(Long publicKeyHandle) {
    this.publicKeyHandle = publicKeyHandle;
  }

  @Override
  public String toString() {
    return String.format("(handle = %d, id = %s, label = %s)", handle, idHex, label);
  }

  @Override
  public int hashCode() {
    return (int) handle;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    else if (!(obj instanceof PKCS11KeyId)) return false;

    PKCS11KeyId other = (PKCS11KeyId) obj;
    return handle == other.handle && Arrays.equals(id, other.id) && Objects.equals(label, other.label);
  }

}
