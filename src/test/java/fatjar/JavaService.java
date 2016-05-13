package fatjar;

import com.google.common.base.Joiner;
import io.vertx.core.AbstractVerticle;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class JavaService extends AbstractVerticle {

  @Override
  public void start() throws Exception {
    String s = Joiner.on(", ").join("Hello", "World");
  }
}
