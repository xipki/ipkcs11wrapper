package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.Functions;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

class VendorCode {

  private static class ConfBlock {
    List<String> modulePaths;
    List<String> manufacturerIDs;
    List<String> descriptions;
    List<String> versions;
    final Map<String, String> nameToCodeMap = new HashMap<>();

    void validate() throws IOException {
      if (isEmpty(modulePaths) && isEmpty(manufacturerIDs) && isEmpty(descriptions)) {
        throw new IOException("invalid <vendorcode>-block");
      }
    }

    boolean matches(String modulePath, String manufacturerID, String libraryDescription, Version libraryVersion) {
      if (!isEmpty(modulePaths)) {
        if (!contains(modulePaths, Paths.get(modulePath).getFileName().toString())) {
          return false;
        }
      }

      if (!isEmpty(manufacturerIDs)) {
        if (!contains(manufacturerIDs, manufacturerID)) {
          return false;
        }
      }

      if (!isEmpty(descriptions)) {
        if (!contains(descriptions, libraryDescription)) {
          return false;
        }
      }

      if (isEmpty(versions)) {
        return true;
      }

      int iVersion = ((0xFF & libraryVersion.major) << 8) + (0xFF & libraryVersion.minor);
      boolean match = false;
      for (String t : versions) {
        int idx = t.indexOf("-");

        int from;
        int to;
        if (idx == -1) {
          from = toIntVersion(t);
          to = from;
        } else {
          from = toIntVersion(t.substring(0, idx));
          to = toIntVersion(t.substring(idx + 1));
        }

        if (iVersion >= from && iVersion <= to) {
          match = true;
          break;
        }
      }

      return match;
    }

    private static int toIntVersion(String version) {
      int idx = version.indexOf('.');
      return (Integer.parseInt(version.substring(0, idx)) << 8) +
              Integer.parseInt(version.substring(idx + 1));
    }

    private static boolean isEmpty(Collection<?> c) {
      return c == null || c.isEmpty();
    }

    private static boolean contains(List<String> list, String str) {
      str = str.toLowerCase(Locale.ROOT);
      for (String s : list) {
        if (str.contains(s)) {
          return true;
        }
      }
      return false;
    }
  }

  static VendorCode getVendorCode(
      String modulePath, String manufacturerID, String libraryDescription, Version libraryVersion)
      throws IOException {
    String confPath = System.getProperty("iaik.pkcs.pkcs11.wrapper.vendorcode.conf");
    InputStream in = (confPath != null)
        ? Files.newInputStream(Paths.get(modulePath))
        : VendorCode.class.getResourceAsStream("/iaik/pkcs/pkcs11/wrapper/vendorcode.conf");
    try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
      while (true) {
        ConfBlock block = readVendorCodeBlock(br);
        if (block == null) {
          break;
        }

        if (block.matches(modulePath, manufacturerID, libraryDescription, libraryVersion)) {
          return new VendorCode(block.nameToCodeMap);
        }
      }
    }

    return null;
  }

  private static ConfBlock readVendorCodeBlock(BufferedReader reader) throws IOException {
    boolean inBlock = false;
    String line;
    ConfBlock block = null;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (line.isEmpty() || line.charAt(0) == '#') {
        continue;
      }

      if (line.startsWith("<vendorcode>")) {
        block = new ConfBlock();
        inBlock = true;
      } else if (line.startsWith("</vendorcode>")) {
        block.validate();
        return block;
      } else if (inBlock) {
        if (line.startsWith("module.")) {
          int idx = line.indexOf(' ');
          if (idx == -1) {
            continue;
          }

          String name = line.substring(0, idx).trim();
          String value = line.substring(idx + 1).trim();
          if (value.isEmpty()) {
            continue;
          }

          if (name.equalsIgnoreCase("module.path")) {
            block.modulePaths = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          } else if (name.equalsIgnoreCase("module.mid")) {
            block.manufacturerIDs = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          } else if (name.equalsIgnoreCase("module.description")) {
            block.descriptions = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          } else if (name.equalsIgnoreCase("module.version")) {
            block.versions = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          } else {
            // do nothing
          }
        } else if (line.startsWith("CKK_") || line.startsWith("CKM_")) {
          int idx = line.indexOf(' ');
          if (idx == -1) {
            continue;
          }

          block.nameToCodeMap.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
        }
      }
    }

    return block;
  }

  private final Map<Long, Long> ckkGenericToVendorMap = new HashMap<>();

  private final Map<Long, Long> ckkVendorToGenericMap = new HashMap<>();

  private final Map<Long, Long> ckmGenericToVendorMap = new HashMap<>();

  private final Map<Long, Long> ckmVendorToGenericMap = new HashMap<>();

  private VendorCode(Map<String, String> nameToCodeMap) {
    for (Map.Entry<String, String> entry : nameToCodeMap.entrySet()) {
      String name = entry.getKey().toUpperCase(Locale.ROOT);
      String valueStr = entry.getValue().toUpperCase(Locale.ROOT);
      boolean hex = valueStr.startsWith("0X");
      if (hex) {
        valueStr = valueStr.substring(2);
      }

      long vendorCode = hex ? Long.parseLong(valueStr, 16) : Long.parseLong(valueStr);

      if (name.startsWith("CKK_VENDOR_")) {
        long genericCode = Functions.ckkNameToCode(name);
        if (genericCode == -1) {
          throw new IllegalArgumentException("unknown name in vendorcode block: " + name);
        }
        ckkGenericToVendorMap.put(genericCode, vendorCode);
      } else if (name.startsWith("CKM_VENDOR_")) {
        long genericCode = Functions.ckmNameToCode(name);
        if (genericCode == -1) {
          throw new IllegalArgumentException("unknown name in vendorcode block: " + name);
        }
        ckmGenericToVendorMap.put(genericCode, vendorCode);
      } else {
        throw new IllegalArgumentException("Unknown name in vendorcode block: " + name);
      }
    }

    for (Map.Entry<Long, Long> m : ckkGenericToVendorMap.entrySet()) {
      ckkVendorToGenericMap.put(m.getValue(), m.getKey());
    }

    for (Map.Entry<Long, Long> m : ckmGenericToVendorMap.entrySet()) {
      ckmVendorToGenericMap.put(m.getValue(), m.getKey());
    }
  }

  long ckkGenericToVendor(long genericCode) {
    Long ret = ckkGenericToVendorMap.get(genericCode);
    return ret == null ? genericCode : ret;
  }

  long ckkVendorToGeneric(long vendorCode) {
    Long ret = ckkVendorToGenericMap.get(vendorCode);
    return ret == null ? vendorCode : ret;
  }

  long ckmGenericToVendor(long genericCode) {
    Long ret = ckmGenericToVendorMap.get(genericCode);
    return ret == null ? genericCode : ret;
  }

  long ckmVendorToGeneric(long vendorCode) {
    Long ret = ckmVendorToGenericMap.get(vendorCode);
    return ret == null ? vendorCode : ret;
  }

}
