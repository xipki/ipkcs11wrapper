// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Implementation;
import org.xipki.pkcs11.wrapper.PKCS11Constants.Category;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <p>
 * Objects of this class represent a PKCS#11 module. The application should
 * create an instance by calling getInstance and passing the name of the
 * PKCS#11 module of the desired token; e.g. "slbck.dll". The application
 * must give the full path of the PKCS#11 module unless the module is in the
 * system's search path or in the path of the java.library.path system
 * property.
 * <p>
 * According to the specification, the application must call the initialize
 * method before calling any other method of the module.
 * This class contains slot and token management functions as defined by the
 * PKCS#11 standard.
 * <p>
 * All applications using this library will contain the following code.
 * <pre><code>
 *      PKCS11Module pkcs11Module = PKCS11Module.getInstance("cryptoki.dll");
 *      pkcs11Module.initialize();
 *
 *      // ... work with the module
 *
 *      pkcs11Module.finalize(null);
 * </code></pre>
 * Instead of <code>cryptoki.dll</code>, the application will use the name of
 * the PKCS#11 module of the installed crypto hardware.
 * After the application initialized the module, it can get a list of all
 * available slots. A slot is an object that represents a physical or logical
 * device that can accept a cryptographic token; for instance, the card slot of
 * a smart card reader. The application can call
 * <pre><code>
 * Slot[] slots = pkcs11Module.getSlotList(false);
 * </code></pre>
 * to get a list of all available slots or
 * <pre><code>
 * Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
 * </code></pre>
 * to get a list of all those slots in which there is a currently a token
 * present.
 * <p>
 * To wait for the insertion of a token, the application can use the
 * <code>waitForSlotEvent</code> method. For example, the method call
 * <pre><code>
 * Slot eventSlot = pkcs11Module.waitForSlotEvent(true);
 * </code></pre>
 * will block until an event for any slot of this module occurred. Usually such
 * an event is the insertion of a token. However, the application should check
 * if the event occurred in the slot of interest and if there is really a token
 * present in the slot.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */

public class PKCS11Module {

  /**
   * The ECDSA signature is in X9.62 format.
   */
  static final int BEHAVIOUR_ECDSA_SIGNATURE_X962 = 1;

  /**
   * The SM2 signature is in X9.62 format.
   */
  static final int BEHAVIOUR_SM2_SIGNATURE_X962 = 2;

  /**
   * The private key of type CKK_EC has the attribute CKA_EC_POINT.
   */
  static final int BEHAVIOUR_EC_PRIVATEKEY_ECPOINT = 3;

  /**
   * The private key of type CKK_VENDOR_SM2 has the attribute CKA_EC_POINT.
   */
  static final int BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT = 4;

  /**
   * Ignore the non-zero ulDeviceError in the SessionInfo.
   */
  static final int BEHAVIOUR_IGNORE_DEVICE_ERROR = 5;

  /**
   * The CKA_EC_PARAMS for CKK_EC_EDWARDS accepts only name instead OID.
   */
  static final int BEHAVIOUR_EC_PARAMS_NAME_ONLY_EDWARDS = 6;

  /**
   * The CKA_EC_PARAMS for CKK_EC_EDWARDS accepts only name instead OID.
   */
  static final int BEHAVIOUR_EC_PARAMS_NAME_ONLY_MONTGOMERY = 7;

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private final PKCS11Implementation pkcs11;

  /**
   * Indicates, if the static linking and initialization of the library is already done.
   */
  private static boolean linkedAndInitialized;

  private ModuleInfo moduleInfo;

  private Boolean ecPointFixNeeded;

  private Boolean ecdsaSignatureFixNeeded;

  private Boolean sm2SignatureFixNeeded;

  private final Map<Category, VendorMap> vendorMaps = new HashMap<>();

  private final Set<Integer> vendorBehaviours = new HashSet<>();

  private static final AtomicBoolean licensePrinted = new AtomicBoolean(false);

  static {
    String version = null;
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(Objects.requireNonNull(PKCS11Module.class.getResourceAsStream("version"))))) {
      version = reader.readLine();
    } catch (Exception ex) {
    }

    if (version == null) {
      version = "UNKNOWN";
    } else {
      version = version.trim();
    }

    StaticLogger.info("ipkcs11wrapper " + version);
  }

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param pkcs11
   *          The PKCS#11 module to interact with the token.
   */
  protected PKCS11Module(PKCS11Implementation pkcs11) {
    this.pkcs11 = Functions.requireNonNull("pkcs11", pkcs11);
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module; e.g. "slbck.dll". Tries
   * to load the PKCS#11 wrapper native library from the class path (jar file) or library path.
   *
   * @param pkcs11ModulePath
   *          The path of the module; e.g. "/path/to/slbck.dll".
   * @return An instance of Module that is connected to the given PKCS#11 module.
   * @exception IOException
   *              If connecting to the named module fails.
   *
   */
  public static PKCS11Module getInstance(String pkcs11ModulePath) throws IOException {
    synchronized (licensePrinted) {
      if (!licensePrinted.get()) {
        StaticLogger.info(
                "This product (ipkcs11wrapper) includes software (IAIK PKCS#11 wrapper version 1.6.8)\n"
                + "developed by Stiftung SIC which is licensed under \"IAIK PKCS#11 Wrapper License\"- \n"
                + "A copy of this license is downloadable under \n"
                + "https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/#License.\n"
                + "All other parts are licensed under Apache License, version 2.");
        licensePrinted.set(true);
      }
    }

    ensureLinkedAndInitialized();
    StaticLogger.info("PKCS11Module.getInstance: pkcs11ModulePath={}", pkcs11ModulePath);
    return new PKCS11Module(new PKCS11Implementation(Functions.requireNonNull("pkcs11ModulePath", pkcs11ModulePath)));
  }

  /**
   * This method ensures that the library is linked to this class and that it is initialized. Tries
   * to load the PKCS#11 wrapper native library from the library or the class path (jar file).
   *
   */
  private static synchronized void ensureLinkedAndInitialized() {
    if (!linkedAndInitialized) {
      try {
        System.loadLibrary("pkcs11wrapper");
      } catch (UnsatisfiedLinkError e) {
        try {
          loadWrapperFromJar();
        } catch (IOException ioe) {
          throw new UnsatisfiedLinkError("no pkcs11wrapper in library path or jar file. " + ioe.getMessage());
        }
      }
      PKCS11Implementation.initializeLibrary();
      linkedAndInitialized = true;
    }
  }

  Boolean getEcPointFixNeeded() {
    return ecPointFixNeeded;
  }

  void setEcPointFixNeeded(Boolean ecPointFixNeeded) {
    this.ecPointFixNeeded = ecPointFixNeeded;
  }

  Boolean getEcdsaSignatureFixNeeded() {
    return ecdsaSignatureFixNeeded;
  }

  void setEcdsaSignatureFixNeeded(Boolean ecdsaSignatureFixNeeded) {
    this.ecdsaSignatureFixNeeded = ecdsaSignatureFixNeeded;
  }

  Boolean getSm2SignatureFixNeeded() {
    return sm2SignatureFixNeeded;
  }

  void setSm2SignatureFixNeeded(Boolean sm2SignatureFixNeeded) {
    this.sm2SignatureFixNeeded = sm2SignatureFixNeeded;
  }

  /**
   * Gets information about the module; i.e. the PKCS#11 module behind.
   *
   * @return An object holding information about the module.
   */
  public ModuleInfo getInfo() throws TokenException {
    if (moduleInfo == null) {
      throw new TokenException("moduleInfo not available");
    }
    return moduleInfo;
  }

  /**
   * Initializes the module. The application must call this method before
   * calling any other method of the module.
   *
   * @exception PKCS11Exception
   *              If initialization fails.
   */
  public void initialize() throws PKCS11Exception {
    CK_C_INITIALIZE_ARGS wrapperInitArgs = new CK_C_INITIALIZE_ARGS();
    wrapperInitArgs.flags |= PKCS11Constants.CKF_OS_LOCKING_OK;

    // pReserved of CK_C_INITIALIZE_ARGS not used yet, just set to standard conform UTF8
    StaticLogger.info("C_Initialize: flags=0x{}", Functions.toFullHex(wrapperInitArgs.flags));
    try {
      pkcs11.C_Initialize(wrapperInitArgs, true);
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      throw convertException(e);
    }

    try {
      moduleInfo = new ModuleInfo(pkcs11.C_GetInfo());
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      StaticLogger.error("error calling C_GetInfo {}", e.getMessage());
    }

    // Vendor code
    initVendor();
  }

  /**
   * Finalizes this module. The application should call this method when it finished using the
   * module. Note that this method is different from the <code>finalize</code> method, which is the
   * reserved Java method called by the garbage collector. This method calls the
   * <code>C_Finalize(Object)</code> method of the underlying PKCS11 module.
   *
   * @param args
   *          Must be null in version 2.x of PKCS#11.
   * @exception PKCS11Exception
   *              If finalization fails.
   *
   */
  public void finalize(Object args) throws PKCS11Exception {
    try {
      pkcs11.C_Finalize(args);
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      throw convertException(e);
    }
  }

  /**
   * Gets a list of slots that can accept tokens that are compatible with this
   * module; e.g. a list of PC/SC smart card readers. The parameter determines
   * if the method returns all compatible slots or only those in which there
   * is a compatible token present.
   *
   * @param tokenPresent
   *          Whether only slots with present token are returned.
   * @return An array of Slot objects, may be an empty array but not null.
   * @exception PKCS11Exception
   *              If error occurred.
   */
  public Slot[] getSlotList(boolean tokenPresent) throws PKCS11Exception {
    long[] slotIDs;
    try {
      slotIDs = pkcs11.C_GetSlotList(tokenPresent);
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      throw convertException(e);
    }

    Slot[] slots = new Slot[slotIDs.length];
    for (int i = 0; i < slots.length; i++) {
      slots[i] = new Slot(this, slotIDs[i]);
    }

    return slots;
  }

  /**
   * Waits for a slot event. That can be that a token was inserted or
   * removed. It returns the Slot for which an event occurred. The dontBlock
   * parameter can have the value false (BLOCK) or true (DONT_BLOCK).
   * If there is no event present and the method is called with true this
   * method throws an exception with the error code CKR_NO_EVENT (0x00000008).
   *
   * @param dontBlock
   *          Can false (BLOCK) or true (DONT_BLOCK).
   * @return The slot for which an event occurred.
   * @exception PKCS11Exception
   *              If the method was called with WaitingBehavior.DONT_BLOCK but
   *              there was no event available, or if an error occurred.
   */
  public Slot waitForSlotEvent(boolean dontBlock) throws PKCS11Exception {
    long slotId;
    try {
      slotId = pkcs11.C_WaitForSlotEvent(dontBlock ? PKCS11Constants.CKF_DONT_BLOCK : 0L, null);
    } catch (iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
      throw convertException(e);
    }
    return new Slot(this, slotId);
  }

  /**
   * Gets the PKCS#11 module of the wrapper package behind this object.
   *
   * @return The PKCS#11 module behind this object.
   */
  public PKCS11 getPKCS11Module() {
    return pkcs11;
  }

  boolean hasVendorBehaviour(int vendorBehavior) {
    return vendorBehaviours.contains(vendorBehavior);
  }

  public long genericToVendorCode(Category category, long genericCode) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.genericToVendor(genericCode) : genericCode;
  }

  public long vendorToGenericCode(Category category, long vendorCode) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.vendorToGeneric(vendorCode) : vendorCode;
  }

  public String codeToName(Category category, long code) {
    if ((code & PKCS11Constants.CKM_VENDOR_DEFINED) != 0 && vendorMaps != null) {
      VendorMap map = vendorMaps.get(category);
      return map != null ? map.codeToName(code) : PKCS11Constants.codeToName(category, code);
    } else {
      return PKCS11Constants.codeToName(category, code);
    }
  }

  public Long nameToCode(Category category, String name) {
    VendorMap map = vendorMaps.get(category);
    return map != null ? map.nameToCode(name) : PKCS11Constants.nameToCode(category, name);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  @Override
  public String toString() {
    return (pkcs11 != null) ? pkcs11.toString() : "null";
  }

  public PKCS11Exception convertException(iaik.pkcs.pkcs11.wrapper.PKCS11Exception e) {
    return new PKCS11Exception(e.getErrorCode());
  }

  /**
   * Tries to load the PKCS#11 wrapper native library included in the class path (jar file). If
   * loaded from the jar file and wrapperDebugVersion is true, uses the included debug version. The
   * found native library is copied to the temporary-file directory and loaded from there.
   *
   * @throws IOException
   *           if the wrapper native library for the system's architecture can't be found in the jar
   *           file or if corresponding native library can't be written to temporary directory
   */
   private static void loadWrapperFromJar() throws IOException {
    final String PKCS11_TEMP_DIR = "PKCS11_TEMP_DIR";
    final int LINUX_INDEX = 0;
    final int WIN_INDEX = 1;
    final int MAC_INDEX = 2;

    // subdirectories per OS.
    final String[] WRAPPER_OS_PATH = {"unix/linux-", "windows/win-", "unix/macosx_universal/"};

    // file suffix per OS.
    final String[] WRAPPER_FILE_SUFFIX = {".so", ".dll", ".jnilib"};

    // file prefix per OS.
    final String[] WRAPPER_FILE_PREFIX = {"lib", "", "lib", "lib"};

    // index constants per architecture as used in below array.
    final int X64_INDEX = 0;
    final int X86_INDEX = 1;
    final int ARM_INDEX = 2;
    final int AARCH64_INDEX = 3;

    // subdirectories per architecture.
    final String[] WRAPPER_ARCH_PATH = {"x86_64/", "x86/", "arm/", "aarch64/"};

    int trialCounter = 0;

    String osName = System.getProperty("os.name");
    osName = osName.toLowerCase(Locale.ROOT);
    int osIndex = osName.contains("win") ? WIN_INDEX
        : osName.contains("linux") ? LINUX_INDEX
        : osName.contains("mac") ? MAC_INDEX : 0; // it may be some Linux - try it

    String archName = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

    int archIndex;
    if (archName.contains("aarch64")) {
      archIndex = AARCH64_INDEX;
    } else if (archName.contains("arm")) {
      archIndex = ARM_INDEX;
    } else if (archName.contains("64")) {
      archIndex = X64_INDEX;
    } else if (archName.contains("32") || archName.contains("86")){
      archIndex = X86_INDEX;
    } else {
       archIndex = -1;
     }

    if (archIndex == -1) {
      archIndex = 0;
      trialCounter++;
    }

    ClassLoader classLoader = PKCS11Module.class.getClassLoader();
    boolean isRelease = null != classLoader.getResource("natives/unix/linux-x86/release/libpkcs11wrapper.so");
    String releaseOrDebugDir = isRelease ? "release/" : "debug/";

    String system = "natives/" + WRAPPER_OS_PATH[osIndex];

    String architecture = (osIndex == MAC_INDEX) ? "" : WRAPPER_ARCH_PATH[archIndex];

    String libName = WRAPPER_FILE_PREFIX[osIndex] + "pkcs11wrapper";
    String osFileEnding = WRAPPER_FILE_SUFFIX[osIndex];

    boolean success = false;
    do {
      String jarFilePath = system + architecture + releaseOrDebugDir + libName + osFileEnding;
      InputStream wrapperLibrary = classLoader.getResourceAsStream(jarFilePath);

      if (wrapperLibrary == null) {
        if (trialCounter < WRAPPER_ARCH_PATH.length) {
          archIndex = trialCounter++;
          architecture = WRAPPER_ARCH_PATH[archIndex];
          continue;
        } else {
          throw new IOException("No suitable wrapper native library for " + osName + " "
              + archName + " found in jar file.");
        }
      }

      File tempWrapperFile = null;
      try {
        String directory = System.getProperty(PKCS11_TEMP_DIR, null);
        if (directory != null && !directory.isEmpty()) {
          File tempWrapperDirectory = new File(directory);
          if (tempWrapperDirectory.exists()) {
            tempWrapperFile = File.createTempFile(libName, osFileEnding, tempWrapperDirectory);
          } else {
            throw new IOException("Specified local temp directory '" + directory + "' does not exist!");
          }
        } else {
          tempWrapperFile = File.createTempFile(libName, osFileEnding);
        }
        if (!tempWrapperFile.canWrite()) {
          throw new IOException("Can't copy wrapper native library to local temporary directory - " +
              "no write permission in " + tempWrapperFile.getAbsolutePath());
        }
        tempWrapperFile.deleteOnExit();

        StaticLogger.info("PKCS11oModule.loadWrapperFromJar: copy file {} to a temporary file", jarFilePath);
        try {
          Files.copy(wrapperLibrary, tempWrapperFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally {
          wrapperLibrary.close();
        }
      } catch (IOException e) {
        // error writing found library, other architecture would not change this
        if (tempWrapperFile != null) {
          tempWrapperFile.delete();
        }
        throw new IOException("Can't copy wrapper native library to local temporary directory. " + e.getMessage());
      } catch (RuntimeException e) {
        if (tempWrapperFile != null) {
          tempWrapperFile.delete();
        }
        throw e;
      }

      try {
        System.load(tempWrapperFile.getAbsolutePath());
        success = true;
      } catch (UnsatisfiedLinkError e) {
        tempWrapperFile.delete();
        if (trialCounter < WRAPPER_ARCH_PATH.length) {
          archIndex = trialCounter++;
          architecture = WRAPPER_ARCH_PATH[archIndex];
        } else {
          throw new IOException("No suitable wrapper native library found in jar file. "
              + osName + " " + archName + " not supported.");
        }
      }
    } while (!success);

  }

  private static VendorConfBlock readVendorBlock(BufferedReader reader) throws IOException {
    boolean inBlock = false;
    String line;
    VendorConfBlock block = null;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (line.isEmpty() || line.charAt(0) == '#') {
        continue;
      }

      if (line.startsWith("<vendor>")) {
        block = new VendorConfBlock();
        inBlock = true;
      } else if (line.startsWith("</vendor>")) {
        if (block != null) {
          block.validate();
        }
        return block;
      } else if (inBlock) {
        if (line.startsWith("module.")) {
          int idx = line.indexOf(' ');
          if (idx == -1) {
            continue;
          }

          String value = line.substring(idx + 1).trim();
          if (value.isEmpty()) {
            continue;
          }

          String name = line.substring(0, idx).trim();
          List<String> textList = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          if (name.equalsIgnoreCase("module.path")) {
            block.modulePaths = textList;
          } else if (name.equalsIgnoreCase("module.mid")) {
            block.manufacturerIDs = textList;
          } else if (name.equalsIgnoreCase("module.description")) {
            block.descriptions = textList;
          } else if (name.equalsIgnoreCase("module.version")) {
            block.versions = textList;
          }
        } else if (line.startsWith("CKD_") || line.startsWith("CKG_") || line.startsWith("CKU_") ||
            line.startsWith("CKK_") || line.startsWith("CKM_") || line.startsWith("CKR_")) {
          int idx = line.indexOf(' ');
          if (idx != -1) {
            block.nameToCodeMap.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
          }
        } else if (line.startsWith("VENDOR_BEHAVIORS ")) {
          int idx = line.indexOf(' ');
          String value = line.substring(idx + 1).trim();
          if (!value.isEmpty()) {
            block.vendorBehaviours = value;
          }
        } else {
          StaticLogger.warn("vendor.conf: ignore line " + line);
        }
      }
    }

    return block;
  }

  private void initVendor() {
    try {
      String modulePath = pkcs11.getPkcs11ModulePath();
      ModuleInfo moduleInfo = getInfo();
      String manufacturerID = moduleInfo.getManufacturerID();
      String libraryDescription = moduleInfo.getLibraryDescription();
      Version libraryVersion = moduleInfo.getLibraryVersion();

      String confPath = System.getProperty("org.xipki.pkcs11.vendor.conf");
      InputStream in = (confPath != null) ? Files.newInputStream(Paths.get(confPath))
          : PKCS11Module.class.getClassLoader().getResourceAsStream("org/xipki/pkcs11/wrapper/vendor.conf");
      if (in == null) {
        throw new IOException("found no file org/xipki/pkcs11/wrapper/vendor.conf");
      }

      try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
        while (true) {
          VendorConfBlock block = readVendorBlock(br);
          if (block == null) {
            break;
          }

          if (!block.matches(modulePath, manufacturerID, libraryDescription, libraryVersion)) {
            continue;
          }

          StaticLogger.info("found <vendor> configuration: {}", block);
          // vendor behaviours
          if (block.vendorBehaviours != null) {
            StringTokenizer tokenizer = new StringTokenizer(block.vendorBehaviours, ":, \t");
            while (tokenizer.hasMoreTokens()) {
              String token = tokenizer.nextToken();
              if ("SM2_SIGNATURE_X962".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_SM2_SIGNATURE_X962);
              } else if ("ECDSA_SIGNATURE_X962".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_ECDSA_SIGNATURE_X962);
              } else if ("SM2_PRIVATEKEY_ECPOINT".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT);
              } else if ("EC_PRIVATEKEY_ECPOINT".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_EC_PRIVATEKEY_ECPOINT);
              } else if ("IGNORE_DEVICE_ERROR".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_IGNORE_DEVICE_ERROR);
              } else if ("EC_PARAMS_NAME_ONLY_EDWARDS".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_EC_PARAMS_NAME_ONLY_EDWARDS);
              } else if ("EC_PARAMS_NAME_ONLY_MONTGOMERY".equalsIgnoreCase(token)) {
                vendorBehaviours.add(BEHAVIOUR_EC_PARAMS_NAME_ONLY_MONTGOMERY);
              } else {
                StaticLogger.warn("Ignored unknown vendor behaviour '" + token + "'.");
              }
            }
          }

          Category[] categories = {Category.CKD, Category.CKG_MGF, Category.CKK,
              Category.CKM, Category.CKP_PRF, Category.CKR, Category.CKU};
          for (Category category : categories) {
            vendorMaps.put(category, new VendorMap(category));
          }

          for (Map.Entry<String, String> entry : block.nameToCodeMap.entrySet()) {
            String name = entry.getKey().toUpperCase(Locale.ROOT);
            Category category = name.startsWith("CKD_") ? Category.CKD
                : name.startsWith("CKG_") ? Category.CKG_MGF
                : name.startsWith("CKK_") ? Category.CKK
                : name.startsWith("CKM_") ? Category.CKM
                : name.startsWith("CKP_") ? Category.CKP_PRF
                : name.startsWith("CKR_") ? Category.CKR
                : name.startsWith("CKU_") ? Category.CKU : null;

            if (category == null) {
              throw new IllegalStateException("Unknown name in vendor block: " + name);
            }

            vendorMaps.get(category).addNameCode(name, entry.getValue().toUpperCase(Locale.ROOT));
          } // end for

          break;
        } // end while
      }
    } catch (Exception e) {
      StaticLogger.warn("error reading VENDOR code mapping, ignore it.");
    }
  }

  private static long parseCode(String str) {
    boolean hex = str.startsWith("0X");
    return hex ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str);
  }

  private static final class VendorMap {

    private final Map<Long, Long> genericToVendorMap = new HashMap<>();

    private final Map<Long, Long> vendorToGenericMap = new HashMap<>();

    private final Map<Long, String> codeNameMap      = new HashMap<>();

    private final Map<String, Long> nameCodeMap      = new HashMap<>();

    private final Category category;

    VendorMap(Category category) {
      this.category = category;
    }

    void addNameCode(String name, String code) {
      long lCode = parseCode(code);
      Long genericCode = PKCS11Constants.nameToCode(category, name);
      if (genericCode != null) {
        // only vendor code is allowed to be overwritten.
        if ((genericCode & PKCS11Constants.CKM_VENDOR_DEFINED) != 0 && genericCode != lCode) {
          genericToVendorMap.put(genericCode, lCode);
          vendorToGenericMap.put(lCode, genericCode);
        }
      } else {
        codeNameMap.put(lCode, name);
        nameCodeMap.put(name, lCode);
      }
    }

    boolean isEmpty() {
      return codeNameMap.isEmpty();
    }

    long genericToVendor(long genericCode) {
      return genericToVendorMap.getOrDefault(genericCode, genericCode);
    }

    long vendorToGeneric(long vendorCode) {
      return vendorToGenericMap.getOrDefault(vendorCode, vendorCode);
    }

    public String codeToName(long code) {
      String name = codeNameMap.get(code);
      if (name == null) {
        name = PKCS11Constants.codeToName(category, code);
      }
      return name;
    }

    public Long nameToCode(String name) {
      Long code = nameCodeMap.get(name);
      if (code == null) {
        code = PKCS11Constants.nameToCode(category, name);
      }
      return code;
    }

  }

  private static final class VendorConfBlock {
    private List<String> modulePaths;
    private List<String> manufacturerIDs;
    private List<String> descriptions;
    private List<String> versions;
    private String vendorBehaviours;
    private final Map<String, String> nameToCodeMap = new HashMap<>();

    void validate() throws IOException {
      if (isEmpty(modulePaths) && isEmpty(manufacturerIDs) && isEmpty(descriptions)) {
        throw new IOException("invalid <vendor>-block");
      }
    }

    boolean matches(String modulePath, String manufacturerID, String libraryDescription, Version libraryVersion) {
      if ((!isEmpty(modulePaths)     && notContains(modulePaths,     Paths.get(modulePath).getFileName().toString())) ||
          (!isEmpty(manufacturerIDs) && notContains(manufacturerIDs, manufacturerID)) ||
          (!isEmpty(descriptions)    && notContains(descriptions,    libraryDescription))) {
        return false;
      }

      if (isEmpty(versions)) {
        return true;
      }

      int iVersion = ((0xFF & libraryVersion.getMajor()) << 8) + (0xFF & libraryVersion.getMinor());
      boolean match = false;
      for (String t : versions) {
        int idx = t.indexOf("-");
        int from = (idx == -1) ? toIntVersion(t) : toIntVersion(t.substring(0, idx));
        int to   = (idx == -1) ? from            : toIntVersion(t.substring(idx + 1));

        if (iVersion >= from && iVersion <= to) {
          match = true;
          break;
        }
      }

      return match;
    }

    private static int toIntVersion(String version) {
      StringTokenizer st = new StringTokenizer(version, ".");
      return (Integer.parseInt(st.nextToken()) << 8) + Integer.parseInt(st.nextToken());
    }

    private static boolean isEmpty(Collection<?> c) {
      return c == null || c.isEmpty();
    }

    private static boolean notContains(List<String> list, String str) {
      str = str.toLowerCase(Locale.ROOT);
      for (String s : list) {
        if (str.contains(s)) {
          return false;
        }
      }
      return true;
    }

    @Override
    public String toString() {
      return "VendorConfBlock" +
          "\n  modulePaths:      " + modulePaths +
          "\n  manufacturerIDs:  " + manufacturerIDs +
          "\n  descriptions:     " + descriptions +
          "\n  versions:         " + versions +
          "\n  vendorBehaviours: " + vendorBehaviours +
          "\n  nameToCodeMap:    " + nameToCodeMap;
    }
  } // class VendorConfBlock

}
