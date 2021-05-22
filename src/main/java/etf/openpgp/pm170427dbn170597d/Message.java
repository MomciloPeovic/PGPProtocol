package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.openpgp.PGPSignature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

public class Message
{
	private byte[] buffer;

	public Message(String plaintext) {
		this.buffer = plaintext.getBytes();
	}

	public void sign(DSAPrivateKey privateKey) throws Exception
	{
		Signature dsa = Signature.getInstance("SHA256withDSA");
		dsa.initSign(privateKey);
		dsa.update(buffer);

		byte[] signature = dsa.sign();
		System.out.println(signature.length);
		byte[] b = new byte[buffer.length + signature.length];
		System.arraycopy(signature, 0, b, 0, signature.length);
		System.arraycopy(buffer, 0, b, signature.length, buffer.length);

		this.buffer = b;
	}

	public boolean verify(DSAPublicKey publicKey, int signatureLength) throws Exception {
		Signature dsa = Signature.getInstance("SHA256withDSA");

		dsa.initVerify(publicKey);
		byte[] signature = new byte[signatureLength];
		byte[] plaintext = new byte[buffer.length - signatureLength];
		System.arraycopy(buffer, 0, signature, 0, signatureLength);
		System.arraycopy(buffer, signatureLength, plaintext, 0, buffer.length - signatureLength);
		dsa.update(plaintext);
		return dsa.verify(signature);
	}
}
