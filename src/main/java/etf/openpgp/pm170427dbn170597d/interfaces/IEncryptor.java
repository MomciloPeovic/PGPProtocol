package etf.openpgp.pm170427dbn170597d.interfaces;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface IEncryptor
{
	void encrypt(InputStream data, OutputStream output, PGPSecretKeyRing senderSecretKeyRing, String passphraseForPrivateKey) throws PGPException, IOException;
	IEncryptor addReceiver(PGPPublicKeyRing receiverPublicKeys);
}
