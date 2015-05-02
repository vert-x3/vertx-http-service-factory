package io.vertx.ext.httpservicefactory;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class HttpSecureServiceFactory extends HttpServiceFactory {

  @Override
  public String prefix() {
    return "https";
  }

}
