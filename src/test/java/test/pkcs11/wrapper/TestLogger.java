package test.pkcs11.wrapper;

import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Logger;

public class TestLogger implements Logger {

  static final Logger INSTANCE = new TestLogger();

  private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Logger.class);

  @Override
  public void info(String format, Object... arguments) {
    LOG.info(format, arguments);
  }

  @Override
  public void warn(String format, Object... arguments) {
    LOG.warn(format, arguments);
  }

  @Override
  public void error(String format, Object... arguments) {
    LOG.error(format, arguments);
  }

  @Override
  public void debug(String format, Object... arguments) {
    LOG.debug(format, arguments);
  }

  @Override
  public boolean isDebugEnabled() {
    return LOG.isDebugEnabled();
  }

  @Override
  public boolean isInfoEnabled() {
    return LOG.isInfoEnabled();
  }

  @Override
  public boolean isWarnEnabled() {
    return LOG.isWarnEnabled();
  }

}
