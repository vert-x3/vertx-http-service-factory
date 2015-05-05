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
  public void testVerified() throws Exception {
    // Generate test-verticle.asc with
    // gpg -ab --output src/test/resources/test-verticle.asc --sign src/test/resources/test-verticle.zip
    verify("src/test/resources/validating_key.asc", true);
  }

  @Test
  public void testNotVerified() throws Exception {
    verify("src/test/resources/another_key.asc", false);
  }

  private void verify(String keyPath, boolean expected) throws Exception {
    File key = new File(keyPath);
    File file = new File("src/test/resources/test-verticle.zip");
    File signature = new File("src/test/resources/test-verticle.asc");
    Assert.assertTrue(file.exists());
    Assert.assertTrue(signature.exists());
    PGPSignature pgpSignature = PGPHelper.getSignature(Files.readAllBytes(signature.toPath()));
    PGPPublicKey publicKey = PGPHelper.getPublicKey(Files.readAllBytes(key.toPath()), pgpSignature.getKeyID());
    boolean verified = false;
    if (publicKey != null) {
      verified = PGPHelper.verifySignature(new FileInputStream(file), new FileInputStream(signature), publicKey);
    }
    Assert.assertEquals(expected, verified);
  }
}
