package org.xipki.pkcs11.wrapper;

public class StaticLogger {

  private static Logger logger;

  public static void setLogger(Logger logger_) {
    logger = logger_;
  }

  public static void info(String message) {
    if (logger != null) {
      logger.info(message);
    } else {
      System.out.println("[INFO] " + message);
    }
  }

  public static void warn(String message) {
    if (logger != null) {
      logger.warn(message);
    } else {
      System.out.println("[WARN] " + message);
    }
  }

  public static void error(String message) {
    if (logger != null) {
      logger.error(message);
    } else {
      System.out.println("[ERROR] " + message);
    }
  }

}
