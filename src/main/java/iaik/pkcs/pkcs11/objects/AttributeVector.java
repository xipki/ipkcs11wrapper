package iaik.pkcs.pkcs11.objects;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

import java.util.*;

public class AttributeVector {

  private List<Attribute> attributes;

  public AttributeVector() {
    this.attributes = new LinkedList<>();
  }

  public AttributeVector(Attribute... attributes) {
    if (attributes == null || attributes.length == 0) {
      this.attributes = new LinkedList<>();
    } else {
      this.attributes = new ArrayList<>(attributes.length);
      for (Attribute attr : attributes) {
        if (attr != null) {
          attr(attr);
        }
      }
    }
  }

  public AttributeVector attr(long attrType, Object attrValue) {
    return attr(Attribute.getInstance(attrType, attrValue));
  }

  public AttributeVector attr(Attribute attr) {
    if (!attributes.isEmpty()) {
      long type = attr.getType();
      int oldAttrIdx = -1;
      for (int i = 0; i < attributes.size(); i++) {
        if (attributes.get(i).getType() == type) {
          oldAttrIdx = i;
          break;
        }
      }

      if (oldAttrIdx != -1) {
        attributes.remove(oldAttrIdx);
      }
    }

    attributes.add(attr);
    return this;
  }

  public List<Attribute> snapshot() {
    return Collections.unmodifiableList(attributes);
  }

  public CK_ATTRIBUTE[] toCkAttributes() {
    List<CK_ATTRIBUTE> attributeList = new ArrayList<>();
    for (Attribute attribute : attributes) {
      if (attribute.present) {
        attributeList.add(attribute.getCkAttribute());
      }
    }
    return attributeList.toArray(new CK_ATTRIBUTE[0]);
  }

  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    StringBuilder sb = new StringBuilder(32);
    sb.append(indent).append("Attribute Vector:");

    String indent2 = indent + "  ";
    for (Attribute attribute : attributes) {
      if (sb.length() > 0) {
        sb.append("\n");
      }
      sb.append(attribute.toString(true, indent2));
    }

    return sb.toString();
  }

  public Attribute getAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.getType() == type) {
        return attr;
      }
    }
    return null;
  }

}
