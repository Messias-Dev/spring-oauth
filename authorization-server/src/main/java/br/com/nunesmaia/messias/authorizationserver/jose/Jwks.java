package br.com.nunesmaia.messias.authorizationserver.jose;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public final class Jwks {

	private final String KEYSTORE_FILE;
	private final String ALIAS;
	private final String KEYSTORE_PASSWORD;

	private Jwks(
			@Value("${security.jwt.keystore-file}") String keystoreFile,
			@Value("${security.jwt.alias}") String alias,
			@Value("${security.jwt.keystore-password}") String keystorePassword
	) {
		this.KEYSTORE_FILE = keystoreFile;
		this.ALIAS = alias;
		this.KEYSTORE_PASSWORD = keystorePassword;
	}

	public RSAKey generateRsa() {
		KeyPair keyPair = this.generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID("auth")
				.build();
	}

	private KeyPair generateRsaKey() {
		KeyPair keyPair;

		try {
			var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(new ClassPathResource(this.KEYSTORE_FILE).getInputStream(), this.KEYSTORE_PASSWORD.toCharArray());

			var privateKey = (PrivateKey) keyStore.getKey(this.ALIAS, this.KEYSTORE_PASSWORD.toCharArray());

			Certificate certificate = keyStore.getCertificate(this.ALIAS);
			PublicKey publicKey = certificate.getPublicKey();

			keyPair = new KeyPair(publicKey, privateKey);
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
				 UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		}

		return keyPair;
	}
}
