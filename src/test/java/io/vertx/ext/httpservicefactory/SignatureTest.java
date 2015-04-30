package io.vertx.ext.httpservicefactory;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class SignatureTest {

/*
  static {
    java.security.Security.addProvider(new BouncyCastleProvider());
  }
*/

//  @Test
  public void testBar() throws Exception {

    PGPKeyRingGenerator generator = generateKeyRingGenerator("julien", "the_password".toCharArray());

    PGPSecretKeyRing keyRing = generator.generateSecretKeyRing();

    File file = new File("vertx-core-3.0.0-milestone4.pom");

    ByteArrayOutputStream signature = new ByteArrayOutputStream();
    signFile(file, keyRing.getSecretKey(), signature, "the_password".toCharArray(), true);

    System.out.println("signature = " + signature.toString());


  }

  public static PGPKeyRingGenerator generateKeyRingGenerator
      (String id, char[] pass)
      throws Exception {
    return generateKeyRingGenerator(id, pass, 0xc0);
  }

  // Note: s2kcount is a number between 0 and 0xff that controls the
  // number of times to iterate the password hash before use. More
  // iterations are useful against offline attacks, as it takes more
  // time to check each password. The actual number of iterations is
  // rather complex, and also depends on the hash function in use.
  // Refer to Section 3.7.1.3 in rfc4880.txt. Bigger numbers give
  // you more iterations.  As a rough rule of thumb, when using
  // SHA256 as the hashing function, 0x10 gives you about 64
  // iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0,
  // or about 1 million iterations. The maximum you can go to is
  // 0xff, or about 2 million iterations.  I'll use 0xc0 as a
  // default -- about 130,000 iterations.

  public static PGPKeyRingGenerator generateKeyRingGenerator(String id, char[] pass, int s2kcount) throws Exception {
    // This object generates individual key-pairs.
    RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

    // Boilerplate RSA parameters, no need to change anything
    // except for the RSA key-size (2048). You can use whatever
    // key-size makes sense for you -- 4096, etc.
    kpg.init
        (new RSAKeyGenerationParameters
            (BigInteger.valueOf(0x10001),
                new SecureRandom(), 2048, 12));

    // First create the master (signing) key with the generator.
    PGPKeyPair rsakp_sign =
        new BcPGPKeyPair
            (PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
    // Then an encryption subkey.
    PGPKeyPair rsakp_enc =
        new BcPGPKeyPair
            (PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

    // Add a self-signature on the id
    PGPSignatureSubpacketGenerator signhashgen =
        new PGPSignatureSubpacketGenerator();

    // Add signed metadata on the signature.
    // 1) Declare its purpose
    signhashgen.setKeyFlags
        (false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
    // 2) Set preferences for secondary crypto algorithms to use
    //    when sending messages to this key.
    signhashgen.setPreferredSymmetricAlgorithms
        (false, new int[]{
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128
        });
    signhashgen.setPreferredHashAlgorithms
        (false, new int[]{
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA1,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA224,
        });
    // 3) Request senders add additional checksums to the
    //    message (useful when verifying unsigned messages.)
    signhashgen.setFeature
        (false, Features.FEATURE_MODIFICATION_DETECTION);

    // Create a signature on the encryption subkey.
    PGPSignatureSubpacketGenerator enchashgen =
        new PGPSignatureSubpacketGenerator();
    // Add metadata to declare its purpose
    enchashgen.setKeyFlags
        (false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

    // Objects used to encrypt the secret key.
    PGPDigestCalculator sha1Calc =
        new BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA1);
    PGPDigestCalculator sha256Calc =
        new BcPGPDigestCalculatorProvider()
            .get(HashAlgorithmTags.SHA256);

    // bcpg 1.48 exposes this API that includes s2kcount. Earlier
    // versions use a default of 0x60.
    PBESecretKeyEncryptor pske =
        (new BcPBESecretKeyEncryptorBuilder
            (PGPEncryptedData.AES_256, sha256Calc, s2kcount))
            .build(pass);

    // Finally, create the keyring itself. The constructor
    // takes parameters that allow it to generate the self
    // signature.
    PGPKeyRingGenerator keyRingGen =
        new PGPKeyRingGenerator
            (PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                id, sha1Calc, signhashgen.generate(), null,
                new BcPGPContentSignerBuilder
                    (rsakp_sign.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA1),
                pske);

    // Add our encryption subkey, together with its signature.
    keyRingGen.addSubKey
        (rsakp_enc, enchashgen.generate(), null);
    return keyRingGen;
  }

  private static void signFile(
      File file,
      PGPSecretKey pgpSec,
      OutputStream out,
      char[] pass,
      boolean armor)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
    signFile(file.getName(), Files.readAllBytes(file.toPath()), new Date(file.lastModified()), pgpSec, out, pass, armor);
  }

  private static void signFile(
      String fileName,
      byte[] fileData,
      Date fileLastModified,
      PGPSecretKey pgpSec,
      OutputStream out,
      char[] pass,
      boolean armor)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
    if (armor) {
      out = new ArmoredOutputStream(out);
    }

    PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

    sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

    Iterator it = pgpSec.getPublicKey().getUserIDs();
    if (it.hasNext()) {
      PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

      spGen.setSignerUserID(false, (String) it.next());
      sGen.setHashedSubpackets(spGen.generate());
    }

    PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
        PGPCompressedData.ZLIB);

    BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

    sGen.generateOnePassVersion(false).encode(bOut);

    PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
    OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, fileName, fileData.length, fileLastModified);
    InputStream fIn = new ByteArrayInputStream(fileData);
    int ch;

    while ((ch = fIn.read()) >= 0) {
      lOut.write(ch);
      sGen.update((byte) ch);
    }

    lGen.close();

    sGen.generate().encode(bOut);

    cGen.close();

    if (armor) {
      out.close();
    }
  }

//  @Test
  public void testFoo() throws Exception {

    // Generate test-verticle.asc with
    // gpg -ab --output doc.asc --sign target/test-verticle.zip

    File file = new File("target/test-verticle.zip");
    File signature = new File("src/test/resources/test-verticle.asc");
    Assert.assertTrue(file.exists());
    Assert.assertTrue(signature.exists());

    InputStream sigInputStream = PGPUtil.getDecoderStream(new FileInputStream(signature));
    PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
    PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
    PGPSignature pgpSignature = sigList.get(0);

    String keyServer = "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&options=mr&search=0x%016X";

    URL keyUrl = URI.create(String.format(keyServer, pgpSignature.getKeyID())).toURL();

    System.out.println("keyUrl = " + keyUrl);

    Vertx vertx = Vertx.vertx();
    HttpClient client = vertx.createHttpClient();
    HttpClientRequest req = client.get(11371, "pool.sks-keyservers.net",
        String.format("/pks/lookup?op=get&options=mr&search=0x%016X", pgpSignature.getKeyID()));
    req.handler(resp -> {
      System.out.println(resp.statusCode());
      Buffer buf = Buffer.buffer();
      resp.handler(buf::appendBuffer);
      resp.endHandler(v -> {
        try {
          PGPPublicKey publicKey = PGPHelper.getPublicKey(buf.getBytes(), pgpSignature.getKeyID());
          boolean verified = PGPHelper.verifySignature(new FileInputStream(file), new FileInputStream(signature), publicKey);
          System.out.println("verified = " + verified);
        } catch (Exception e) {
          e.printStackTrace();
        }
      });
    });
    req.end();
    Thread.sleep(10000);

  }


  @Test
  public void testVerify() throws Exception {
    // Generate test-verticle.asc with
    // gpg -ab --output doc.asc --sign target/test-verticle.zip
    File key = new File("src/test/resources/public.key");
    File file = new File("target/test-verticle.zip");
    File signature = new File("src/test/resources/test-verticle.asc");
    Assert.assertTrue(file.exists());
    Assert.assertTrue(signature.exists());

//    InputStream sigInputStream = PGPUtil.getDecoderStream(new FileInputStream(signature));
//    PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
//    PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
    PGPSignature pgpSignature = PGPHelper.getSignature(Files.readAllBytes(signature.toPath()));
    PGPPublicKey publicKey = PGPHelper.getPublicKey(Files.readAllBytes(key.toPath()), pgpSignature.getKeyID());
    boolean verified = PGPHelper.verifySignature(new FileInputStream(file), new FileInputStream(signature), publicKey);
    Assert.assertTrue(verified);
  }
}
