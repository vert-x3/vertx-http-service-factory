package io.vertx.ext.httpservicefactory;

import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class HttpSecureServiceFactory extends HttpServiceFactory {

  @Override
  public String prefix() {
    return "https";
  }

  @Override
  protected HttpClientOptions configOptions() {
    String optionsJson = System.getProperty(HTTPS_CLIENT_OPTIONS_PROPERTY);
    HttpClientOptions options;
    if (optionsJson != null) {
      options = new HttpClientOptions(new JsonObject(optionsJson));
    } else {
      options = super.configOptions();
    }
    options.setSsl(true);
    return options;
  }
}
