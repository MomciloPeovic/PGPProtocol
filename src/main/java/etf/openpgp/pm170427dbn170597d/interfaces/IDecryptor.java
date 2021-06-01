package etf.openpgp.pm170427dbn170597d.interfaces;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface IDecryptor
{
	boolean decrypt(InputStream encryptedData, OutputStream output, PGPPublicKeyRingCollection publicKeyRingCollection,
				 PGPSecretKeyRingCollection secretKeyRingCollection, String passphrase) throws IOException, PGPException;
}
