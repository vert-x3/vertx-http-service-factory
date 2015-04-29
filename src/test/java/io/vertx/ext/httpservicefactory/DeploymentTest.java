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
  private Vertx vertx;

  @BeforeClass
  public static void init() throws Exception {
    verticle = Buffer.buffer(Files.readAllBytes(new File("target/test-verticle.zip").toPath()));
    verticleWithMain = Buffer.buffer(Files.readAllBytes(new File("target/test-verticle-with-main.zip").toPath()));
  }

  @Before
  public void before() {
    cacheDir = "target" + File.separator + "file-cache-" + name.getMethodName();
    System.setProperty(HttpServiceFactory.CACHE_DIR_PROPERTY, cacheDir);
  }

  private void configureServer(HttpServer server, Buffer verticle) {
    configureServer(server, verticle, false);
  }

  private void configureServer(HttpServer server, Buffer verticle, boolean authenticated) {
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
      } else {
        req.response().setStatusCode(404).end();
      }
    });
  }

  @Test
  public void testDeployFromHttpServerWithMain(TestContext context) {
    testDeployFromHttpServer(context, "http://localhost:8080/the_verticle.zip", verticleWithMain);
  }

  @Test
  public void testDeployFromHttpServerWithService(TestContext context) {
    testDeployFromHttpServer(context, "http://localhost:8080/the_verticle.zip::main", verticle);
  }

  private void testDeployFromHttpServer(TestContext context, String url, Buffer verticle) {
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
    testFailDeploy(context, "http://localhost:foo/the_verticle.zip", "For input string");
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
  public void testDeployFromHttpSecureServerWithTrustAll(TestContext context) {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY, "{\"trustAll\":true}");
    testDeployFromHttpSecureServer(context);
  }

  @Test
  public void testDeployFromHttpSecureServerWithTrustStore(TestContext context) {
    System.setProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY,
        "{\"trustStoreOptions\":{\"path\":\"src/test/resources/client-truststore.jks\",\"password\":\"wibble\"}}");
    testDeployFromHttpSecureServer(context);
  }

  private void testDeployFromHttpSecureServer(TestContext context) {
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
    configureServer(server, verticleWithMain, true);
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
    configureServer(server, verticleWithMain, true);
    server.listen(
        8080,
        context.asyncAssertSuccess(s -> {
          vertx.deployVerticle("https://localhost:8080/the_verticle.zip", context.asyncAssertSuccess());
        })
    );
  }

  @Test
  public void testFailDeployFromAuthenticatedHttpServer(TestContext context) {
    vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    configureServer(server, verticleWithMain, true);
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

  @After
  public void after(TestContext context) {
    System.clearProperty(HttpServiceFactory.HTTPS_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.HTTP_CLIENT_OPTIONS_PROPERTY);
    System.clearProperty(HttpServiceFactory.CACHE_DIR_PROPERTY);
    if (vertx != null) {
      vertx.close(context.asyncAssertSuccess());
    }
  }
}
