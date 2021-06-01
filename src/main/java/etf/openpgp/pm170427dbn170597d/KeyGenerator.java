package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;


public class KeyGenerator
{
	private final PGPKeyRingGenerator keyRingGenerator;

	public KeyGenerator(String identity, String passphrase, int strength) throws PGPException
	{
		keyRingGenerator = generateKeyRingGenerator(identity, passphrase, strength);
	}

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		String pass = "hello";

		KeyGenerator generator = new KeyGenerator("mpeovic@telenor.rs", pass, 2048);

		// Generate public key ring, dump to file.
		PGPPublicKeyRing publicKeyRing = generator.getPublicKeyRing();
		Util.saveKeyRingToFile(publicKeyRing, "public_key.asc");

		// Generate private key, dump to file.
		PGPSecretKeyRing secretKeyRing = generator.getSecretKeyRing();
		Util.saveKeyRingToFile(secretKeyRing, "private_key.asc");

	}

	public PGPSecretKeyRing getSecretKeyRing() {
		return keyRingGenerator.generateSecretKeyRing();
	}

	public PGPPublicKeyRing getPublicKeyRing() {
		return keyRingGenerator.generatePublicKeyRing();
	}


	private final PGPKeyRingGenerator generateKeyRingGenerator(String id, String pass, int strength) throws PGPException
	{

		ElGamalKeyPairGenerator elGamalKeyPairGenerator = new ElGamalKeyPairGenerator();
		ElGamalParametersGenerator elGamalParametersGenerator = new ElGamalParametersGenerator();
		elGamalParametersGenerator.init(strength, 10, new SecureRandom());
		elGamalKeyPairGenerator.init(new ElGamalKeyGenerationParameters(new SecureRandom(), elGamalParametersGenerator.generateParameters()));


		DSAKeyPairGenerator dsaKeyPairGenerator = new DSAKeyPairGenerator();
		DSAParametersGenerator parametersGenerator = new DSAParametersGenerator();
		parametersGenerator.init(strength, 10, new SecureRandom());
		dsaKeyPairGenerator.init(new DSAKeyGenerationParameters(new SecureRandom(), parametersGenerator.generateParameters()));


		// First create the master (signing) key with the generator.
		PGPKeyPair dsakp_sign =
				new BcPGPKeyPair
						(PGPPublicKey.DSA, dsaKeyPairGenerator.generateKeyPair(), new Date());
		// Then an encryption subkey.
		PGPKeyPair rsakp_enc =
				new BcPGPKeyPair
						(PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPairGenerator.generateKeyPair(), new Date());

		// Add a self-signature on the id
		PGPSignatureSubpacketGenerator signhashgen =
				new PGPSignatureSubpacketGenerator();

		// Add signed metadata on the signature.
		// 1) Declare its purpose
		signhashgen.setKeyFlags
				(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER | KeyFlags.AUTHENTICATION);
		// 2) Set preferences for secondary crypto algorithms to use
		//    when sending messages to this key.
		signhashgen.setPreferredSymmetricAlgorithms
				(false, new int[] {
						SymmetricKeyAlgorithmTags.AES_256,
						SymmetricKeyAlgorithmTags.AES_192,
						SymmetricKeyAlgorithmTags.AES_128
				});
		signhashgen.setPreferredHashAlgorithms
				(false, new int[] {
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
				(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE);

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
						(PGPEncryptedData.AES_256, sha1Calc, 0xc0))
						.build(pass.toCharArray());

		// Finally, create the keyring itself. The constructor
		// takes parameters that allow it to generate the self
		// signature.
		PGPKeyRingGenerator keyRingGen =
				new PGPKeyRingGenerator
						(PGPSignature.POSITIVE_CERTIFICATION, dsakp_sign,
								id, sha1Calc, signhashgen.generate(), null,
								new BcPGPContentSignerBuilder
										(dsakp_sign.getPublicKey().getAlgorithm(),
												HashAlgorithmTags.SHA1),
								pske);

		// Add our encryption subkey, together with its signature.
		keyRingGen.addSubKey
				(rsakp_enc, enchashgen.generate(), null);
		return keyRingGen;
	}
}
