package io.vertx.ext.httpservicefactory;

import io.vertx.core.AsyncResult;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.streams.Pump;
import io.vertx.service.ServiceVerticleFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLEncoder;
import java.nio.file.Files;
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
  public static final String KEYSERVER_URI_TEMPLATE = "vertx.httpServiceFactory.keyserverURITemplate";
  public static final String VALIDATION_POLICY = "vertx.httpServiceFactory.validationPolicy";

  private static final String FILE_SEP = System.getProperty("file.separator");
  private static final String FILE_CACHE_DIR = ".vertx" + FILE_SEP + "vertx-http-service-factory";

  private Vertx vertx;
  private File cacheDir;
  private String username;
  private String password;
  private String keyserverURITemplate;
  private ValidationPolicy validationPolicy;
  private HttpClientOptions options;

  @Override
  public void init(Vertx vertx) {
    String path = System.getProperty(CACHE_DIR_PROPERTY, FILE_CACHE_DIR);
    cacheDir = new File(path);
    cacheDir.mkdirs();
    options = configOptions();
    validationPolicy = ValidationPolicy.valueOf(System.getProperty(VALIDATION_POLICY).toUpperCase());
    username = System.getProperty(AUTH_USERNAME_PROPERTY);
    password = System.getProperty(AUTH_PASSWORD_PROPERTY);
    keyserverURITemplate = System.getProperty(KEYSERVER_URI_TEMPLATE, "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&options=mr&search=0x%016X");
    this.vertx = vertx;
  }

  protected HttpClientOptions createHttpClientOptions(String scheme) {
    if ("https".equals(scheme)) {
      String optionsJson = System.getProperty(HTTPS_CLIENT_OPTIONS_PROPERTY);
      HttpClientOptions options;
      if (optionsJson != null) {
        options = new HttpClientOptions(new JsonObject(optionsJson));
      } else {
        options = createHttpClientOptions("http");
      }
      options.setSsl(true);
      return options;
    } else {
      String optionsJson = System.getProperty(HTTP_CLIENT_OPTIONS_PROPERTY);
      return optionsJson != null ? new HttpClientOptions(new JsonObject(optionsJson)) : new HttpClientOptions();
    }
  }

  protected HttpClientOptions configOptions() {
    return createHttpClientOptions(prefix());
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

    URI url;
    URI signatureURL;
    String deploymentKey;
    String signatureKey;
    try {
      url = new URI(stringURL);
      signatureURL = new URI(url.getScheme(), url.getUserInfo(), url.getHost(), url.getPort(), url.getPath() + ".asc", url.getQuery(), url.getFragment());
      deploymentKey = URLEncoder.encode(url.toString(), "UTF-8");
      signatureKey = URLEncoder.encode(signatureURL.toString(), "UTF-8");
    } catch (Exception e) {
      resolution.fail(e);
      return;
    }
    File deploymentFile = new File(cacheDir, deploymentKey);
    File signatureFile = new File(cacheDir, signatureKey);

    //
    HttpClient client = vertx.createHttpClient(options);
    doRequest(client, deploymentFile, url, signatureFile, signatureURL, ar -> {
      if (ar.succeeded()) {
        if (ar.result().signature != null) {
          PGPSignature signature;
          URI publicKeyURI;
          File publicKeyFile;
          try {
            signature = PGPHelper.getSignature(Files.readAllBytes(ar.result().signature.toPath()));
            String uri = String.format(keyserverURITemplate, signature.getKeyID());
            publicKeyURI = new URI(uri);
            publicKeyFile = new File(cacheDir, URLEncoder.encode(publicKeyURI.toString(), "UTF-8"));
          } catch (Exception e) {
            client.close();
            resolution.fail(e);
            return;
          }
          HttpClient keyserverClient;
          if (!publicKeyURI.getScheme().equals(prefix())) {
            client.close();
            keyserverClient = vertx.createHttpClient(createHttpClientOptions(publicKeyURI.getScheme()));
          } else {
            keyserverClient = client;
          }
          doRequest(keyserverClient, publicKeyFile, publicKeyURI, null, null, false, ar2 -> {
            if (ar2.succeeded()) {
              try {
                PGPPublicKey publicKey = PGPHelper.getPublicKey(Files.readAllBytes(ar2.result().toPath()), signature.getKeyID());
                if (publicKey != null) {
                  FileInputStream f = new FileInputStream(ar.result().deployment);
                  boolean verified = PGPHelper.verifySignature(f, new FileInputStream(ar.result().signature), publicKey);
                  if (verified) {
                    deploy(deploymentFile, identifier, serviceName, deploymentOptions, classLoader, resolution);
                    return;
                  }
                }
                resolution.fail(new Exception("Signature verification failed"));
              } catch (Exception e) {
                resolution.fail(e);
              } finally {
                keyserverClient.close();
              }
            } else {
              keyserverClient.close();
              resolution.fail(ar2.cause());
            }
          });
        } else {
          client.close();
          deploy(deploymentFile, identifier, serviceName, deploymentOptions, classLoader, resolution);
        }
      } else {
        resolution.fail(ar.cause());
      }
    });
  }

  private void doRequest(HttpClient client, File file, URI url, String username, String password, boolean auth, Handler<AsyncResult<File>> handler) {
    if (file.exists() && file.isFile()) {
      handler.handle(Future.succeededFuture(file));
      return;
    }
    String requestURI = url.getPath();
    if (url.getQuery() != null) {
      requestURI += "?" + url.getQuery();
    }
    HttpClientRequest req = client.get(url.getPort(), url.getHost(), requestURI);
    if (auth && username != null && password != null) {
      req.putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
    }
    req.exceptionHandler(err -> {
      handler.handle(Future.failedFuture(err));
    });
    req.handler(resp -> {
      int status = resp.statusCode();
      if (status == 200) {
        resp.pause();
        vertx.fileSystem().open(file.getPath(), new OpenOptions().setCreate(true), ar2 -> {
          if (ar2.succeeded()) {
            resp.resume();
            AsyncFile result = ar2.result();
            Pump pump = Pump.pump(resp, ar2.result());
            pump.start();
            resp.exceptionHandler(err -> {
              handler.handle(Future.failedFuture(ar2.cause()));
            });
            resp.endHandler(v1 -> {
              result.close(v2 -> {
                if (v2.succeeded()) {
                  handler.handle(Future.succeededFuture(file));
                } else {
                  handler.handle(Future.failedFuture(v2.cause()));
                }
              });
            });
          } else {
            handler.handle(Future.failedFuture(ar2.cause()));
          }
        });
      } else if (status == 401) {
        if (prefix().equals("https") && resp.getHeader("WWW-Authenticate") != null && username != null && password != null) {
          doRequest(client, file, url, username, password, true, handler);
          return;
        }
        handler.handle(Future.failedFuture(new Exception("Unauthorized")));
      } else {
        handler.handle(Future.failedFuture(new Exception("Cannot get file status:" + status)));
      }
    });
    req.end();
  }

  private static class Result {

    final File deployment;
    final File signature;

    public Result(File deployment, File signature) {
      this.deployment = deployment;
      this.signature = signature;
    }
  }

  protected void doRequest(HttpClient client, File file, URI url, File signatureFile, URI signatureURL, Handler<AsyncResult<Result>> handler) {
    doRequest(client, file, url, username, password, false, ar1 -> {
      if (ar1.succeeded()) {
        // Now get the signature if any
        if (validationPolicy != ValidationPolicy.NEVER) {
          doRequest(client, signatureFile, signatureURL, username, password, false, ar3 -> {
            if (ar3.succeeded()) {
              handler.handle(Future.succeededFuture(new Result(ar1.result(), ar3.result())));
            } else {
              if (validationPolicy == ValidationPolicy.ALWAYS) {
                handler.handle(Future.failedFuture(ar3.cause()));
              } else {
                handler.handle(Future.succeededFuture(new Result(ar1.result(), null)));
              }
            }
          });
        } else {
          handler.handle(Future.succeededFuture(new Result(file, null)));
        }
      } else {
        handler.handle(Future.failedFuture(ar1.cause()));
      }
    });
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
