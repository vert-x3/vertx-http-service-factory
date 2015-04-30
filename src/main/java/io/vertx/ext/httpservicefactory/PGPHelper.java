package io.vertx.ext.httpservicefactory;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class PGPHelper {

  /**
   * Get a signature from its bytes
   *
   * @param signature the bytes
   * @return the pgp signature object
   * @throws Exception
   */
  public static PGPSignature getSignature(byte[] signature) throws Exception {
    InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(signature));
    PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
    PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
    return sigList.get(0);
  }

  /**
   * Get a public key from a public key block.
   *
   * @param block the public key block
   * @param keyID the key id
   * @return the public key
   * @throws Exception anything that would prevent to obtain the key
   */
  public static PGPPublicKey getPublicKey(byte[] block, long keyID) throws Exception {
    InputStream keyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(block));
    PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(keyIn, new BcKeyFingerprintCalculator());
    return pgpRing.getPublicKey(keyID);
  }

  /**
   * Verify a PGP signature.
   *
   * @param file the file
   * @param signature the signature
   * @param key the public key
   * @return true if the signature is verified
   * @throws Exception anything preventing the verification to happen
   */
  public static boolean verifySignature(
      InputStream file,
      InputStream signature,
      PGPPublicKey key)
      throws Exception {
    InputStream sigInputStream = PGPUtil.getDecoderStream(signature);
    PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
    PGPSignatureList sigList = (PGPSignatureList) pgpObjectFactory.nextObject();
    PGPSignature pgpSignature = sigList.get(0);
    pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), key);
    try (InputStream inArtifact = new BufferedInputStream(file)) {

      int t;
      while ((t = inArtifact.read()) >= 0) {
        pgpSignature.update((byte) t);
      }
    }
    return pgpSignature.verify();
  }

}
