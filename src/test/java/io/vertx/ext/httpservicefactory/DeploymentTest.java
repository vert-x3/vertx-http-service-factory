package io.vertx.ext.httpservicefactory;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.eclipse.jetty.proxy.ProxyServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.util.Base64;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@RunWith(VertxUnitRunner.class)
public class DeploymentTest {

  @Rule
  public TestName name = new TestName();
  private final String auth = "Basic " + Base64.getEncoder().encodeToString("the_username:the_password".getBytes());
  private String cachePath;
  private static Buffer verticleWithMain;
  private static Buffer verticle;
  private static Buffer verticleSignature;
  private static Buffer validatingKey_asc;
  private static Buffer validatingKey_json;
  private static Buffer anotherKey;
  private Vertx vertx;
  private Server proxyServer;

  @BeforeClass
  public static void init() throws Exception {
    verticle = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/test-verticle.zip").toPath()));
    verticleWithMain = Buffer.buffer(Files.readAllBytes(new File("target/test-verticle-with-main.zip").toPath()));
    verticleSignature = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/test-verticle.asc").toPath()));
    validatingKey_asc = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/validating_key.asc").toPath()));
    validatingKey_json = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/validating_key.json").toPath()));
    anotherKey = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/another_key.asc").toPath()));
  }

  @Before
  public void before() {
    cachePath = "target" + File.separator + "file-cache-" + name.getMethodName();
    System.setProperty(HttpServiceFactory.CACHE_DIR_PROPERTY, cachePath);
    System.setProperty(HttpServiceFactory.VALIDATION_POLICY, "" + ValidationPolicy.NONE);
  }

  @Test
  public void testDeployWithNoConfig(TestContext context) {
    testDeploy(context, "http://localhost:8080/the_verticle.zip", verticleWithMain);
  }

  @Test
  public void testDeployFromRepoWithMain(TestContext context) {
    testDeploy(context, "http://localhost:8080/the_verticle.zip", verticleWithMain);
  }

  @Test
  public void testDeployFromRepoWithService(TestContext context) {
    testDeploy(context, "http://localhost:8080/the_verticle.zip::main", verticle);
  }

  private void testDeploy(TestContext context, String url, Buffer verticle) {
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticle).build();
    Async async = context.async();
    vertx.eventBus().consumer("the_test", msg -> {
      context.assertEquals("pass", msg.body());
      async.complete();
    });
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle(url, context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testFailDeployMissingServiceName(TestContext context) {
    testFailDeploy(context, "http://localhost:8080/the_verticle.zip");
  }

  @Test
  public void testFailDeployCannotConnect(TestContext context) {
    testFailDeploy(context, "http://localhost:8081/the_verticle.zip");
  }

  @Test
  public void testFailDeployMalformedURL(TestContext context) {
    testFailDeploy(context, "http://localhost:0/the_verticle.zip");
  }

  @Test
  public void testFailDeployNotFound(TestContext context) {
    testFailDeploy(context, "http://localhost:8080/not_found.zip");
  }

  private void testFailDeploy(TestContext context, String url) {
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticle).build();
    Async async = context.async();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle(url, ar -> {
            context.assertTrue(ar.failed());
            async.complete();
          });
        })
    );
  }

  @Test
  public void testDeployFromSecureRepoDefault(TestContext context) {
    testDeployFromSecureRepo(context);
  }

  @Test
  public void testDeployFromSecureRepoWithTrustStore(TestContext context) {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY,
        "{\"trustStoreOptions\":{\"path\":\"src/test/resources/client-truststore.jks\",\"password\":\"wibble\"}}");
    testDeployFromSecureRepo(context);
  }

  private void testDeployFromSecureRepo(TestContext context) {
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setSecure(true).setVerticle(verticleWithMain).build();
    Async async = context.async();
    vertx.eventBus().consumer("the_test", msg -> {
      context.assertEquals("pass", msg.body());
      async.complete();
    });
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("https://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testDeployFromAuthenticatedRepo(TestContext context) {
    System.setProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY, "the_username");
    System.setProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY, "the_password");
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticleWithMain).setAuthenticated(true).build();
    Async async = context.async();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("http://localhost:8080/the_verticle.zip", ar -> {
            context.assertTrue(ar.failed());
            async.complete();
          });
        })
    );
  }

  @Test
  public void testDeployFromAuthenticatedSecureRepo(TestContext context) {
    System.setProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY, "the_username");
    System.setProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY, "the_password");
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY, "{\"trustAll\":true}");
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticleWithMain).setSecure(true).setAuthenticated(true).build();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("https://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testFailDeployFromAuthenticatedRepo(TestContext context) {
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticleWithMain).setAuthenticated(true).build();
    Async async = context.async();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("http://localhost:8080/the_verticle.zip", ar -> {
            context.assertTrue(ar.failed());
            async.complete();
          });
        })
    );
  }

  @Test
  public void testDeployUsingProxy(TestContext context) throws Exception {
    proxyServer = new Server(8081);
    ServletHandler handler = new ServletHandler();
    proxyServer.setHandler(handler);
    handler.addServletWithMapping(ProxyServlet.class, "/*").setInitParameter("maxThreads", "10");
    proxyServer.start();
    System.setProperty(HttpServiceFactory.PROXY_HOST_PROPERTY, "localhost");
    System.setProperty(HttpServiceFactory.PROXY_PORT_PROPERTY, "8081");
    vertx = Vertx.vertx();
    HttpServer server = new RepoBuilder().setVerticle(verticleWithMain).build();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("http://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testDeployFromCache(TestContext context) throws Exception {
    vertx = Vertx.vertx();
    String key = URLEncoder.encode("http://localhost:8080/the_verticle.zip", "UTF-8");
    File cacheDir = new File(cachePath);
    cacheDir.mkdirs();
    Files.copy(new ByteArrayInputStream(verticleWithMain.getBytes()), new File(cacheDir, key).toPath());
    Async async = context.async();
    vertx.eventBus().consumer("the_test", msg -> {
      context.assertEquals("pass", msg.body());
      async.complete();
    });
    vertx.deployVerticle("http://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
  }

  @Test
  public void testSignedValidationMandatoryDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.MANDATORY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedValidationVerifyDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.VERIFY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedValidationNoneDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.NONE,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedMissingSignatureValidationMandatoryFails(TestContext context) throws Exception {
    testValidationDeploymentFailed(context, ValidationPolicy.MANDATORY, new RepoBuilder().setVerticle(verticle), new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedMissingSignatureValidationVerifyDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.VERIFY,
        new RepoBuilder().setVerticle(verticle),
        new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedMissingSignatureValidationNoneDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.NONE,
        new RepoBuilder().setVerticle(verticle),
        new KeyServerBuilder().setKey(validatingKey_asc));
  }

  @Test
  public void testSignedMissingPublicKeyValidationMandatoryFails(TestContext context) throws Exception {
    testValidationDeploymentFailed(
        context,
        ValidationPolicy.MANDATORY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder());
  }

  @Test
  public void testSignedMissingPublicKeyValidationVerifyFails(TestContext context) throws Exception {
    testValidationDeploymentFailed(
        context,
        ValidationPolicy.VERIFY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder());
  }

  @Test
  public void testSignedMissingPublicKeyValidationNoneDeploys(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.NONE,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder());
  }

  @Test
  public void testSignedInvalidPublicKeyValidationMandatoryFails(TestContext context) throws Exception {
    testValidationDeploymentFailed(
        context,
        ValidationPolicy.MANDATORY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(anotherKey));
  }

  @Test
  public void testSignedInvalidPublicKeyValidationVerifyFails(TestContext context) throws Exception {
    testValidationDeploymentFailed(
        context,
        ValidationPolicy.VERIFY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(anotherKey));
  }

  @Test
  public void testSignedInvalidPublicKeyValidationNoneFails(TestContext context) throws Exception {
    testValidateDeployment(
        context,
        ValidationPolicy.NONE,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setKey(anotherKey));
  }

  @Test
  public void testSignedFromSecureKeyserver(TestContext context) throws Exception {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY,
        "{\"trustStoreOptions\":{\"path\":\"src/test/resources/client-truststore.jks\",\"password\":\"wibble\"}}");
    testValidateDeployment(
        context,
        ValidationPolicy.MANDATORY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setSecure(true).setKey(validatingKey_asc),
        "https://localhost:8081/pks/lookup?op=get&options=mr&search=0x%016X");
  }

  @Test
  public void testKeybaseIO(TestContext context) throws Exception {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY,
        "{\"trustStoreOptions\":{\"path\":\"src/test/resources/client-truststore.jks\",\"password\":\"wibble\"}}");
    testValidateDeployment(
        context,
        ValidationPolicy.MANDATORY,
        new RepoBuilder().setVerticle(verticle).setSignature(verticleSignature),
        new KeyServerBuilder().setSecure(true).setKey(validatingKey_asc).setHandler(req -> {
          if (req.path().equals("/_/api/1.0/key/fetch.json") && req.getParam("pgp_key_ids").equals("9F9358A769793D09")) {
            req.response().
                setStatusCode(200).
                putHeader("Content-Length", "" + validatingKey_json.length()).
                putHeader("Content-type", "application/json").
                write(validatingKey_json).
                end();
          } else {
            req.response().setStatusCode(404).end();
          }
        }),
        "https://localhost:8081/_/api/1.0/key/fetch.json?pgp_key_ids=%016X");
  }

  private void testValidateDeployment(
      TestContext context,
      ValidationPolicy validationPolicy,
      RepoBuilder repo,
      KeyServerBuilder keyServer) throws Exception {
    testValidateDeployment(context, validationPolicy, repo, keyServer, "http://localhost:8081/pks/lookup?op=get&options=mr&search=0x%016X");
  }

  private void testValidateDeployment(
      TestContext context,
      ValidationPolicy validationPolicy,
      RepoBuilder repo,
      KeyServerBuilder keyServer,
      String keyServerUriTemplate) throws Exception {
    System.setProperty(HttpServiceFactory.VALIDATION_POLICY, validationPolicy.name());
    System.setProperty(HttpServiceFactory.KEYSERVER_URI_TEMPLATE, keyServerUriTemplate);
    vertx = Vertx.vertx();
    repo.build().listen(8080, context.asyncAssertSuccess(s ->
        keyServer.build().listen(8081, context.asyncAssertSuccess(ss -> vertx.
                deployVerticle("http://localhost:8080/the_verticle.zip::main", context.asyncAssertSuccess()))
        )));
  }

  private void testValidationDeploymentFailed(
      TestContext context,
      ValidationPolicy validationPolicy,
      RepoBuilder repo,
      KeyServerBuilder keyServer) throws Exception {
    System.setProperty(HttpServiceFactory.VALIDATION_POLICY, validationPolicy.name());
    System.setProperty(HttpServiceFactory.KEYSERVER_URI_TEMPLATE, "http://localhost:8081/pks/lookup?op=get&options=mr&search=0x%016X");
    vertx = Vertx.vertx();
    repo.build().listen(8080, context.asyncAssertSuccess(s ->
        keyServer.build().listen(8081, context.asyncAssertSuccess(ss -> vertx.
                deployVerticle("http://localhost:8080/the_verticle.zip::main", context.asyncAssertFailure()))
        )));
  }

  @After
  public void after(TestContext context) {
    System.clearProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.HTTP_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.CACHE_DIR_PROPERTY);
    System.clearProperty(HttpServiceFactory.KEYSERVER_URI_TEMPLATE);
    System.clearProperty(HttpServiceFactory.VALIDATION_POLICY);
    System.clearProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY);
    System.clearProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY);
    System.clearProperty(HttpServiceFactory.PROXY_HOST_PROPERTY);
    System.clearProperty(HttpServiceFactory.PROXY_PORT_PROPERTY);
    if (vertx != null) {
      vertx.close(context.asyncAssertSuccess());
    }
    if (proxyServer != null) {
      try {
        proxyServer.stop();
      } catch (Exception ignore) {
      }
    }
  }

  class RepoBuilder {

    Buffer verticle;
    Buffer signature;
    boolean authenticated;
    boolean secure;

    RepoBuilder setVerticle(Buffer verticle) {
      this.verticle = verticle;
      return this;
    }

    RepoBuilder setSignature(Buffer signature) {
      this.signature = signature;
      return this;
    }

    RepoBuilder setAuthenticated(boolean authenticated) {
      this.authenticated = authenticated;
      return this;
    }

    RepoBuilder setSecure(boolean secure) {
      this.secure = secure;
      return this;
    }

    HttpServer build() {
      HttpServerOptions options = new HttpServerOptions();
      if (secure) {
        options.
            setSsl(true).
            setKeyStoreOptions(
                new JksOptions().
                    setPath("src/test/resources/server-keystore.jks").
                    setPassword("wibble"));
      }
      return vertx.createHttpServer(options).requestHandler(req -> {
        if (authenticated && !auth.equals(req.getHeader("Authorization"))) {
          req.response().
              setStatusCode(401).
              putHeader("WWW-Authenticate", "Basic realm=\"TheRealm\"").
              end();
          return;
        }
        if (req.path().equals("/the_verticle.zip")) {
          req.response().
              putHeader("Content-Length", "" + verticle.length()).
              putHeader("Content-type", "application/octet-stream").
              write(verticle).
              end();
          return;
        } else if (req.path().equals("/the_verticle.zip.asc") && signature != null) {
          req.response().
              putHeader("Content-Length", "" + signature.length()).
              putHeader("Content-type", "application/octet-stream").
              write(signature).
              end();
          return;
        }
        req.response().setStatusCode(404).end();
      });
    }
  }

  class KeyServerBuilder {

    Buffer key;
    boolean authenticated;
    boolean secure;
    Handler<HttpServerRequest> handler = req -> {
      if (key != null &&
          req.path().equals("/pks/lookup") &&
          "get".equals(req.getParam("op")) &&
          "mr".equals(req.getParam("options")) &&
          "0x9F9358A769793D09".equals(req.getParam("search"))) {
        req.response().putHeader("Content-Type", "application/pgp-keys; charset=UTF-8").setChunked(true).setStatusCode(200).write(key).end();
      } else {
        req.response().setStatusCode(404).end();
      }
    };

    KeyServerBuilder setKey(Buffer key) {
      this.key = key;
      return this;
    }

    KeyServerBuilder setAuthenticated(boolean authenticated) {
      this.authenticated = authenticated;
      return this;
    }

    KeyServerBuilder setSecure(boolean secure) {
      this.secure = secure;
      return this;
    }

    KeyServerBuilder setHandler(Handler<HttpServerRequest> handler) {
      this.handler = handler;
      return this;
    }

    HttpServer build() {
      HttpServerOptions options = new HttpServerOptions();
      if (secure) {
        options.
            setSsl(true).
            setKeyStoreOptions(
                new JksOptions().
                    setPath("src/test/resources/server-keystore.jks").
                    setPassword("wibble"));
      }
      return vertx.createHttpServer(options).requestHandler(handler);
    }
  }

/*
  @Test
  public void testFoo() throws Exception {
    vertx = Vertx.vertx();
    HttpClient client = vertx.createHttpClient();
    HttpClientRequest req = client.get(11371, "pool.sks-keyservers.net", "/pks/lookup?op=get&options=mr&search=0x9F9358A769793D09");
    req.handler(resp -> {
      System.out.println(resp.statusCode());
      MultiMap headers = resp.headers();
      for (Map.Entry<String, String> entry : headers) {
        System.out.println(entry.getKey() + " -> " + entry.getValue());
      }
    });
    req.end();
    Thread.sleep(10000);
  }
*/
}
