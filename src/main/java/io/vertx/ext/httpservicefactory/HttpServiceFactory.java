package io.vertx.ext.httpservicefactory;

import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import io.vertx.service.ServiceVerticleFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

import java.io.File;
import java.io.FileInputStream;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
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
  public static final String PROXY_HOST_PROPERTY = "vertx.httpServiceFactory.proxyHost";
  public static final String PROXY_PORT_PROPERTY = "vertx.httpServiceFactory.proxyPort";
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
    cacheDir = new File(System.getProperty(CACHE_DIR_PROPERTY, FILE_CACHE_DIR));
    validationPolicy = ValidationPolicy.valueOf(System.getProperty(VALIDATION_POLICY, ValidationPolicy.VERIFY.toString()).toUpperCase());
    username = System.getProperty(AUTH_USERNAME_PROPERTY);
    password = System.getProperty(AUTH_PASSWORD_PROPERTY);
    options = configOptions();
    keyserverURITemplate = System.getProperty(KEYSERVER_URI_TEMPLATE, "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&options=mr&search=0x%016X");
    this.vertx = vertx;
  }

  protected HttpClientOptions createHttpClientOptions(String scheme) {
    HttpClientOptions options;
    if ("https".equals(scheme)) {
      String optionsJson = System.getProperty(HTTPS_CLIENT_OPTIONS_PROPERTY);
      if (optionsJson != null) {
        options = new HttpClientOptions(new JsonObject(optionsJson));
      } else {
        options = createHttpClientOptions("http").setTrustAll(true);
      }
      options.setSsl(true);
    } else {
      String optionsJson = System.getProperty(HTTP_CLIENT_OPTIONS_PROPERTY);
      options = optionsJson != null ? new HttpClientOptions(new JsonObject(optionsJson)) : new HttpClientOptions();
    }
    String proxyHost = System.getProperty(PROXY_HOST_PROPERTY);
    int proxyPort = Integer.parseInt(System.getProperty(PROXY_PORT_PROPERTY, "-1"));
    if (proxyHost != null) {
      ProxyOptions proxyOptions = new ProxyOptions().setHost(proxyHost).setType(ProxyType.HTTP);
      if (proxyPort > 0) {
        proxyOptions.setPort(proxyPort);
      }
      options.setProxyOptions(proxyOptions);
    }
    return options;
  }

  protected HttpClientOptions configOptions() {
    return createHttpClientOptions(prefix());
  }

  @Override
  public String prefix() {
    return "http";
  }

  @Override
  public void resolve(String identifier, DeploymentOptions deploymentOptions, ClassLoader classLoader, Promise<String> resolution) {

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
            closeQuietly(client);
            resolution.fail(e);
            return;
          }
          HttpClient keyserverClient;
          if (!publicKeyURI.getScheme().equals(prefix())) {
            closeQuietly(client);
            keyserverClient = vertx.createHttpClient(createHttpClientOptions(publicKeyURI.getScheme()));
          } else {
            keyserverClient = client;
          }

          BiFunction<String, Buffer, Buffer> unmarshallerFactory = (mediaType, buf) -> {
            switch (mediaType) {
              case "application/json":
                JsonObject json = new JsonObject(buf.toString());
                return Buffer.buffer(json.getJsonArray("keys").getJsonObject(0).getString("bundle"));
              case "application/pgp-keys":
              default:
                return buf;
            }
          };

          doRequest(keyserverClient, publicKeyFile, publicKeyURI, null, null, false, unmarshallerFactory, ar2 -> {
            if (ar2.succeeded()) {
              try {
                long keyID = signature.getKeyID();
                File file = ar2.result();
                Path path = file.toPath();
                PGPPublicKey publicKey = PGPHelper.getPublicKey(Files.readAllBytes(path), keyID);
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
                closeQuietly(keyserverClient);
              }
            } else {
              closeQuietly(keyserverClient);
              resolution.fail(ar2.cause());
            }
          });
        } else {
          closeQuietly(client);
          deploy(deploymentFile, identifier, serviceName, deploymentOptions, classLoader, resolution);
        }
      } else {
        resolution.fail(ar.cause());
      }
    });
  }

  /**
   * The {@code unmarshallerFactory} argument is a function that returns an {@code Function<Buffer, Buffer>} unmarshaller
   * function for a given media type value. The returned function unmarshaller function will be called with the buffers
   * to unmarshall and finally with a null buffer to signal the end of the unmarshalled data. It can return a buffer
   * or a null value.
   *  @param client       the http client
   * @param file         the file where to save the content
   * @param url          the resource url
   * @param username     the optional username used for basic auth
   * @param password     the optional password used for basic auth
   * @param doAuth       whether to perform authentication or not
   * @param unmarshaller the unmarshaller
   * @param handler      the result handler
   */
  private void doRequest(
    HttpClient client,
    File file,
    URI url,
    String username,
    String password,
    boolean doAuth,
    BiFunction<String, Buffer, Buffer> unmarshaller,
    Handler<AsyncResult<File>> handler) {
    if (file.exists() && file.isFile()) {
      handler.handle(Future.succeededFuture(file));
      return;
    }
    String requestURI = url.getPath();
    if (url.getQuery() != null) {
      requestURI += "?" + url.getQuery();
    }
    int port = url.getPort();
    if (port == -1) {
      if ("http".equals(url.getScheme())) {
        port = 80;
      } else {
        port = 443;
      }
    }
    HttpClientRequest req = client.get(port, url.getHost(), requestURI, ar -> {
      if (ar.succeeded()) {
        HttpClientResponse resp = ar.result();
        int status = resp.statusCode();
        switch (resp.statusCode()) {
          case 200: {
            String contentType = resp.getHeader("Content-Type");
            int index = contentType.indexOf(";");
            String mediaType = index > -1 ? contentType.substring(0, index) : contentType;
            AtomicBoolean done = new AtomicBoolean();
            resp.exceptionHandler(err -> {
              if (done.compareAndSet(false, true)) {
                handler.handle(Future.failedFuture(err));
              }
            });
            resp.bodyHandler(body -> {
              if (!done.compareAndSet(false, true)) {
                return;
              }
              File parentFile = file.getParentFile();
              if (!parentFile.exists()) {
                parentFile.mkdirs(); // Handle that
              }
              Buffer data;
              try {
                data = unmarshaller.apply(mediaType, body);
              } catch (Exception e) {
                handler.handle(Future.failedFuture(e));
                return;
              }
              vertx.fileSystem().open(file.getPath(), new OpenOptions().setCreate(true), ar2 -> {
                if (ar2.succeeded()) {
                  AsyncFile result = ar2.result();
                  result.write(data);
                  result.close(v2 -> {
                    if (v2.succeeded()) {
                      handler.handle(Future.succeededFuture(file));
                    } else {
                      handler.handle(Future.failedFuture(v2.cause()));
                    }
                  });
                } else {
                  handler.handle(Future.failedFuture(ar2.cause()));
                }
              });
            });
            break;
          }
          case 401: {
            if (prefix().equals("https") && resp.getHeader("WWW-Authenticate") != null && username != null && password != null) {
              doRequest(client, file, url, username, password, true, unmarshaller, handler);
              return;
            }
            handler.handle(Future.failedFuture(new Exception("Unauthorized")));
            break;
          }
          default: {
            handler.handle(Future.failedFuture(new Exception("Cannot get file status:" + status)));
            break;
          }
        }
      } else {
        handler.handle(Future.failedFuture(ar.cause()));
      }
    });
    req.setFollowRedirects(true);
    if (doAuth && username != null && password != null) {
      req.putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
    }
    req.putHeader("user-agent", "Vert.x Http Service Factory");
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

  protected void doRequest(HttpClient client, File file, URI url, File signatureFile,
                           URI signatureURL, Handler<AsyncResult<Result>> handler) {
    doRequest(client, file, url, username, password, false, (mediatype, buf) -> buf, ar1 -> {
      if (ar1.succeeded()) {
        // Now get the signature if any
        if (validationPolicy != ValidationPolicy.NONE) {
          doRequest(client, signatureFile, signatureURL, username, password, false, (mediatype, buf) -> buf, ar3 -> {
            if (ar3.succeeded()) {
              handler.handle(Future.succeededFuture(new Result(ar1.result(), ar3.result())));
            } else {
              if (validationPolicy == ValidationPolicy.MANDATORY) {
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

  private void deploy(File file, String identifier, String serviceName, DeploymentOptions deploymentOptions, ClassLoader classLoader, Promise<String> resolution) {
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

  private void closeQuietly(HttpClient client) {
    try {
      client.close();
    } catch (Exception e) {
      // We ignore the exceptions.
      // If the client was already closed, it throws an IllegalStateException.
    }
  }
}
