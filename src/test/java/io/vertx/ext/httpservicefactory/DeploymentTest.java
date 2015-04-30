package io.vertx.ext.httpservicefactory;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
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
  private String cacheDir;
  private static Buffer verticleWithMain;
  private static Buffer verticle;
  private static Buffer verticleSignature;
  private static Buffer publicKey;
  private Vertx vertx;

  @BeforeClass
  public static void init() throws Exception {
    verticle = Buffer.buffer(Files.readAllBytes(new File("target/test-verticle.zip").toPath()));
    verticleWithMain = Buffer.buffer(Files.readAllBytes(new File("target/test-verticle-with-main.zip").toPath()));
    verticleSignature = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/test-verticle.asc").toPath()));
    publicKey = Buffer.buffer(Files.readAllBytes(new File("src/test/resources/public.key").toPath()));
  }

  @Before
  public void before() {
    cacheDir = "target" + File.separator + "file-cache-" + name.getMethodName();
    System.setProperty(HttpServiceFactory.CACHE_DIR_PROPERTY, cacheDir);
  }

  private void configureServer(HttpServer server, Buffer verticle) {
    configureServer(server, verticle, null, false);
  }

  private void configureServer(HttpServer server, Buffer verticle, Buffer verticleSignature, boolean authenticated) {
    server.requestHandler(req -> {
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
      } else if (req.path().equals("/the_verticle.zip.asc") && verticleSignature != null) {
        req.response().
            putHeader("Content-Length", "" + verticleSignature.length()).
            putHeader("Content-type", "application/octet-stream").
            write(verticleSignature).
            end();
        return;
      }
      req.response().setStatusCode(404).end();
    });
  }

  @Test
  public void testDeployFromServerWithMain(TestContext context) {
    testDeployFromServer(context, "http://localhost:8080/the_verticle.zip", verticleWithMain);
  }

  @Test
  public void testDeployFromServerWithService(TestContext context) {
    testDeployFromServer(context, "http://localhost:8080/the_verticle.zip::main", verticle);
  }

  private void testDeployFromServer(TestContext context, String url, Buffer verticle) {
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    configureServer(server, verticle);
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
    testFailDeploy(context, "http://localhost:8080/the_verticle.zip", "Invalid service identifier, missing service name");
  }

  @Test
  public void testFailDeployCannotConnect(TestContext context) {
    testFailDeploy(context, "http://localhost:8081/the_verticle.zip", "Connection refused");
  }

  @Test
  public void testFailDeployMalformedURL(TestContext context) {
    testFailDeploy(context, "http://localhost:0/the_verticle.zip", "Can't assign requested address");
  }

  @Test
  public void testFailDeployNotFound(TestContext context) {
    testFailDeploy(context, "http://localhost:8080/not_found.zip", "404");
  }

  private void testFailDeploy(TestContext context, String url, String msgMatch) {
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    configureServer(server, verticle);
    Async async = context.async();
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle(url, ar -> {
            context.assertTrue(ar.failed());
            context.assertTrue(ar.cause().getMessage().contains(msgMatch),
                "Was expecting <" + ar.cause().getMessage() + "> to contain " + msgMatch);
            async.complete();
          });
        })
    );
  }

  @Test
  public void testDeployFromSecureServerWithTrustAll(TestContext context) {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY, "{\"trustAll\":true}");
    testDeployFromSecureServer(context);
  }

  @Test
  public void testDeployFromSecureServerWithTrustStore(TestContext context) {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY,
        "{\"trustStoreOptions\":{\"path\":\"src/test/resources/client-truststore.jks\",\"password\":\"wibble\"}}");
    testDeployFromSecureServer(context);
  }

  private void testDeployFromSecureServer(TestContext context) {
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer(new HttpServerOptions().
        setSsl(true).
        setKeyStoreOptions(new JksOptions().setPath("src/test/resources/server-keystore.jks").setPassword("wibble")));
    configureServer(server, verticleWithMain);
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
  public void testDeployFromAuthenticatedServer(TestContext context) {
    System.setProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY, "the_username");
    System.setProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY, "the_password");
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    configureServer(server, verticleWithMain, null, true);
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
  public void testDeployFromAuthenticatedSecureServer(TestContext context) {
    System.setProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY, "the_username");
    System.setProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY, "the_password");
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY, "{\"trustAll\":true}");
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer(new HttpServerOptions().
        setSsl(true).
        setKeyStoreOptions(new JksOptions().setPath("src/test/resources/server-keystore.jks").setPassword("wibble")));
    configureServer(server, verticleWithMain, null, true);
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("https://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testFailDeployFromAuthenticatedServer(TestContext context) {
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    configureServer(server, verticleWithMain, null, true);
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
  public void testDeployFromCache(TestContext context) throws Exception {
    vertx = Vertx.vertx();
    String key = URLEncoder.encode("http://localhost:8080/the_verticle.zip", "UTF-8");
    Files.copy(new ByteArrayInputStream(verticleWithMain.getBytes()), new File(new File(cacheDir), key).toPath());
    Async async = context.async();
    vertx.eventBus().consumer("the_test", msg -> {
      context.assertEquals("pass", msg.body());
      async.complete();
    });
    vertx.deployVerticle("http://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
  }

  @Test
  public void testDeploySigned(TestContext context) throws Exception {
    System.setProperty(HttpServiceFactory.KEYSERVER_HOST, "localhost");
    System.setProperty(HttpServiceFactory.KEYSERVER_PORT, "8081");
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    HttpServer keyServer = vertx.createHttpServer();
    keyServer.requestHandler(req -> {
      if (req.path().equals("/pks/lookup") &&
          "get".equals(req.getParam("op")) &&
          "mr".equals(req.getParam("options")) &&
          "0x9F9358A769793D09".equals(req.getParam("search"))) {
        req.response().setChunked(true).setStatusCode(200).write(publicKey).end();
      } else {
        req.response().setStatusCode(404).end();
      }
    });
    configureServer(server, verticle, verticleSignature, false);
    server.listen(8080, context.asyncAssertSuccess(s ->
        keyServer.listen(8081, context.asyncAssertSuccess(ss ->vertx.
          deployVerticle("http://localhost:8080/the_verticle.zip::main", context.asyncAssertSuccess(id -> {})))
    )));
  }

  @After
  public void after(TestContext context) {
    System.clearProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.HTTP_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.CACHE_DIR_PROPERTY);
    System.clearProperty(HttpServiceFactory.KEYSERVER_HOST);
    System.clearProperty(HttpServiceFactory.KEYSERVER_PORT);
    System.clearProperty(HttpServiceFactory.AUTH_PASSWORD_PROPERTY);
    System.clearProperty(HttpServiceFactory.AUTH_USERNAME_PROPERTY);
    if (vertx != null) {
      vertx.close(context.asyncAssertSuccess());
    }
  }
}
