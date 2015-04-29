package io.vertx.ext.httpservicefactory;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.streams.Pump;
import io.vertx.service.ServiceVerticleFactory;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Collections;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class HttpServiceFactory extends ServiceVerticleFactory {

  public static final String CACHE_DIR_PROPERTY = "vertx.httpServiceFactory.cacheDir";
  public static final String HTTP_CLIENT_OPTIONS_PROPERTY = "vertx.httpServiceFactory.httpClientOptions";
  public static final String HTTPS_CLIENT_OPTIONS_PROPERTY = "vertx.httpServiceFactory.httpsClientOptions";
  public static final String AUTH_USERNAME_PROPERTY = "vertx.httpServiceFactory.authUsername";
  public static final String AUTH_PASSWORD_PROPERTY = "vertx.httpServiceFactory.authPassword";

  private static final String FILE_SEP = System.getProperty("file.separator");
  private static final String FILE_CACHE_DIR = ".vertx" + FILE_SEP + "vertx-http-service-factory";

  private Vertx vertx;
  private File cacheDir;
  private String username;
  private String password;
  private HttpClientOptions options;

  @Override
  public void init(Vertx vertx) {
    String path = System.getProperty(CACHE_DIR_PROPERTY, FILE_CACHE_DIR);
    cacheDir = new File(path);
    cacheDir.mkdirs();
    options = configOptions();
    username = System.getProperty(AUTH_USERNAME_PROPERTY);
    password = System.getProperty(AUTH_PASSWORD_PROPERTY);
    this.vertx = vertx;
  }

  protected HttpClientOptions configOptions() {
    String optionsJson = System.getProperty(HTTP_CLIENT_OPTIONS_PROPERTY);
    return optionsJson != null ? new HttpClientOptions(new JsonObject(optionsJson)) : new HttpClientOptions();
  }

  @Override
  public String prefix() {
    return "http";
  }

  @Override
  public void resolve(String identifier, DeploymentOptions deploymentOptions, ClassLoader classLoader, Future<String> resolution) {

    int pos = identifier.lastIndexOf("::");
    String serviceName;
    String stringURL;
    if (pos != -1) {
      stringURL = identifier.substring(0, pos);
      serviceName = identifier.substring(pos + 2);
    } else {
      serviceName = null;
      stringURL = identifier;
    }

    URL url;
    String key;
    try {
      url = new URL(stringURL);
      key = URLEncoder.encode(identifier, "UTF-8");
    } catch (Exception e) {
      resolution.fail(e);
      return;
    }

    // Lookup in cache first
    File file = new File(cacheDir, key);
    if (file.exists() && file.isFile()) {
      deploy(file, identifier, serviceName, deploymentOptions, classLoader, resolution);
      return;
    }

    HttpClient client = vertx.createHttpClient(options);
    doRequest(client, identifier, serviceName, deploymentOptions, classLoader, file, url, stringURL, false, resolution);
  }

  protected void doRequest(
      HttpClient client,
      String identifier,
      String serviceName,
      DeploymentOptions deploymentOptions,
      ClassLoader classLoader,
      File file,
      URL url,
      String stringURL,
      boolean auth,
      Future<String> resolution) {
    // Get file from remote server
    HttpClientRequest req = client.get(url.getPort(), url.getHost(), url.getPath());
    if (auth && username != null && password != null) {
      req.putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
    }
    req.exceptionHandler(err -> {
      client.close();
      resolution.fail(err);
    });
    req.handler(resp -> {
      int status = resp.statusCode();
      if (status == 200) {
        String disposition = resp.getHeader("Content-Disposition");
        String contentType = resp.getHeader("Content-Type");
        String filename = null;
        if (disposition != null) {
          int index = disposition.indexOf("filename=");
          if (index > 0) {
            filename = disposition.substring(index + 10, disposition.length() - 1);
          }
        }
        if (filename == null) {
          filename = stringURL.substring(stringURL.lastIndexOf("/") + 1, stringURL.length());
        }
        resp.pause();
        vertx.fileSystem().open(file.getPath(), new OpenOptions().setCreate(true), ar -> {
          if (ar.succeeded()) {
            resp.resume();
            AsyncFile result = ar.result();
            Pump pump = Pump.pump(resp, ar.result());
            pump.start();
            resp.exceptionHandler(err -> {
              client.close();
              resolution.fail(ar.cause());
            });
            resp.endHandler(v1 -> {
              result.close(v2 -> {
                deploy(file, identifier, serviceName, deploymentOptions, classLoader, resolution);
              });
              client.close();
            });
          } else {
            client.close();
            resolution.fail(ar.cause());
          }
        });
      } else if (status == 401) {
        if (prefix().equals("https") && resp.getHeader("WWW-Authenticate") != null && username != null && password != null) {
          doRequest(client, identifier, serviceName, deploymentOptions, classLoader, file, url, stringURL, true, resolution);
          return;
        }
        client.close();
        resolution.fail(new Exception("Unauthorized"));
      } else {
        client.close();
        resolution.fail(new Exception("Cannot get file status:" + status));
      }
    });
    req.end();
  }

  private void deploy(File file, String identifier, String serviceName, DeploymentOptions deploymentOptions, ClassLoader classLoader, Future<String> resolution) {
    try {
      String serviceIdentifer = null;
      if (serviceName == null) {
        JarFile jarFile = new JarFile(file);
        Manifest manifest = jarFile.getManifest();
        if (manifest != null) {
          serviceIdentifer = (String) manifest.getMainAttributes().get(new Attributes.Name("Main-Verticle"));
        }
      } else {
        serviceIdentifer = "service:" + serviceName;
      }
      if (serviceIdentifer == null) {
        throw new IllegalArgumentException("Invalid service identifier, missing service name: " + identifier);
      }
      deploymentOptions.setExtraClasspath(Collections.singletonList(file.getAbsolutePath()));
      deploymentOptions.setIsolationGroup("__vertx_maven_" + file.getName());
      URLClassLoader urlc = new URLClassLoader(new URL[]{file.toURI().toURL()}, classLoader);
      super.resolve(serviceIdentifer, deploymentOptions, urlc, resolution);
    } catch (Exception e) {
      resolution.fail(e);
    }
  }
}
