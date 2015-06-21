package io.vertx.ext.httpservicefactory;

import io.vertx.core.AsyncResult;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.streams.Pump;
import io.vertx.core.streams.WriteStream;
import io.vertx.service.ServiceVerticleFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
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
  private String proxyHost;
  private int proxyPort;
  private String keyserverURITemplate;
  private ValidationPolicy validationPolicy;
  private HttpClientOptions options;

  @Override
  public void init(Vertx vertx) {
    cacheDir = new File(System.getProperty(CACHE_DIR_PROPERTY, FILE_CACHE_DIR));
    options = configOptions();
    validationPolicy = ValidationPolicy.valueOf(System.getProperty(VALIDATION_POLICY, ValidationPolicy.VERIFY.toString()).toUpperCase());
    username = System.getProperty(AUTH_USERNAME_PROPERTY);
    password = System.getProperty(AUTH_PASSWORD_PROPERTY);
    proxyHost = System.getProperty(PROXY_HOST_PROPERTY);
    proxyPort = Integer.parseInt(System.getProperty(PROXY_PORT_PROPERTY, "-1"));
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
        options = createHttpClientOptions("http").setTrustAll(true);
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

          Function<String, Function<Buffer, Buffer>> unmarshallerFactory = mediaType -> {
            switch (mediaType) {
              case "application/json":
                Buffer buffer = Buffer.buffer();
                return buf -> {
                  if (buf == null) {
                    JsonObject json = new JsonObject(buffer.toString());
                    return Buffer.buffer(json.getJsonArray("keys").getJsonObject(0).getString("bundle"));
                  } else {
                    buffer.appendBuffer(buf);
                    return null;
                  }
                };
              case "application/pgp-keys":
              default:
                return Function.identity();
            }
          };

          doRequest(keyserverClient, publicKeyFile, publicKeyURI, null, null, false, unmarshallerFactory, new HashSet<>(), ar2 -> {
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

  /**
   * The {@code unmarshallerFactory} argument is a function that returns an {@code Function<Buffer, Buffer>} unmarshaller
   * function for a given media type value. The returned function unmarshaller function will be called with the buffers
   * to unmarshall and finally with a null buffer to signal the end of the unmarshalled data. It can return a buffer
   * or a null value.
   *
   * @param client the http client
   * @param file the file where to save the content
   * @param url the resource url
   * @param username the optional username used for basic auth
   * @param password the optional password used for basic auth
   * @param doAuth whether to perform authentication or not
   * @param unmarshallerFactory the unmarshaller factory
   * @param history the previous urls for detecting redirection loops
   * @param handler the result handler
   */
  private void doRequest(
      HttpClient client,
      File file,
      URI url,
      String username,
      String password,
      boolean doAuth,
      Function<String, Function<Buffer, Buffer>> unmarshallerFactory,
      Set<URI> history,
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
    HttpClientRequest req;
    if (proxyHost == null) {
      req = client.get(port, url.getHost(), requestURI);
    } else {
      req = client.get(proxyPort, proxyHost, url.toString());
      req.putHeader("host", url.getHost());
    }
    if (doAuth && username != null && password != null) {
      req.putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
    }
    req.putHeader("user-agent", "Vert.x Http Service Factory");
    req.exceptionHandler(err -> {
      handler.handle(Future.failedFuture(err));
    });
    req.handler(resp -> {
      int status = resp.statusCode();
      switch (resp.statusCode()) {
        case 200: {
          resp.pause();
          File parentFile = file.getParentFile();
          if (!parentFile.exists()) {
            parentFile.mkdirs();
          }
          vertx.fileSystem().open(file.getPath(), new OpenOptions().setCreate(true), ar2 -> {
            if (ar2.succeeded()) {
              resp.resume();
              AsyncFile result = ar2.result();
              String contentType = resp.getHeader("Content-Type");
              int index = contentType.indexOf(";");
              String mediaType = index > -1 ? contentType.substring(0, index) : contentType;
              Function<Buffer, Buffer> unmarshaller = unmarshallerFactory.apply(mediaType);
              Pump pump = Pump.pump(resp, new WriteStream<Buffer>() {
                @Override
                public WriteStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
                  result.exceptionHandler(handler);
                  return this;
                }
                @Override
                public WriteStream<Buffer> write(Buffer data) {
                  data = unmarshaller.apply(data);
                  if (data != null) {
                    result.write(data);
                  }
                  return this;
                }
                @Override
                public WriteStream<Buffer> setWriteQueueMaxSize(int maxSize) {
                  result.setWriteQueueMaxSize(maxSize);
                  return this;
                }
                @Override
                public boolean writeQueueFull() {
                  return result.writeQueueFull();
                }
                @Override
                public WriteStream<Buffer> drainHandler(Handler<Void> handler) {
                  result.drainHandler(handler);
                  return this;
                }
              });
              pump.start();
              resp.exceptionHandler(err -> {
                handler.handle(Future.failedFuture(ar2.cause()));
              });
              resp.endHandler(v1 -> {
                Buffer last = unmarshaller.apply(null);
                if (last != null) {
                  result.write(last);
                }
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
          break;
        }
        case 301:
        case 302:
        case 303:
        case 308: {
          // Redirect
          String location = resp.headers().get("location");
          if (location == null) {
            handler.handle(Future.failedFuture("HTTP redirect with no location header"));
          } else {
            URI redirectURI;
            try {
              redirectURI = new URI(location);
            } catch (URISyntaxException e) {
              handler.handle(Future.failedFuture("Invalid redirect URI: " + location));
              return;
            }
            if (history.contains(redirectURI)) {
              handler.handle(Future.failedFuture(new Exception("Server redirected to a previous uri " + redirectURI)));
              return;
            }
            Set<URI> nextHistory = new HashSet<>(history);
            nextHistory.add(url);
            doRequest(client, file, redirectURI, username, password, doAuth, unmarshallerFactory, nextHistory, handler);
          }
          break;
        }
        case 401: {
          if (prefix().equals("https") && resp.getHeader("WWW-Authenticate") != null && username != null && password != null) {
            doRequest(client, file, url, username, password, true, unmarshallerFactory, history, handler);
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

  protected void doRequest(HttpClient client, File file, URI url, File signatureFile,
                           URI signatureURL, Handler<AsyncResult<Result>> handler) {
    doRequest(client, file, url, username, password, false, ct -> Function.identity(), new HashSet<>(), ar1 -> {
      if (ar1.succeeded()) {
        // Now get the signature if any
        if (validationPolicy != ValidationPolicy.NONE) {
          doRequest(client, signatureFile, signatureURL, username, password, false, ct -> Function.identity(), new HashSet<>(), ar3 -> {
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
