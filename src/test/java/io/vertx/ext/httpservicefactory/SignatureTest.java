package io.vertx.ext.httpservicefactory;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class SignatureTest {

  @Test
  public void testVerify() throws Exception {
    // Generate test-verticle.asc with
    // gpg -ab --output doc.asc --sign target/test-verticle.zip
    File key = new File("src/test/resources/public.key");
    File file = new File("target/test-verticle.zip");
    File signature = new File("src/test/resources/test-verticle.asc");
    Assert.assertTrue(file.exists());
    Assert.assertTrue(signature.exists());
    PGPSignature pgpSignature = PGPHelper.getSignature(Files.readAllBytes(signature.toPath()));
    PGPPublicKey publicKey = PGPHelper.getPublicKey(Files.readAllBytes(key.toPath()), pgpSignature.getKeyID());
    boolean verified = PGPHelper.verifySignature(new FileInputStream(file), new FileInputStream(signature), publicKey);
    Assert.assertTrue(verified);
  }
}
