package br.com.nunesmaia.messias.authorizationserver.jose;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.*;

public class JwtCustomEncoder implements JwtEncoder {

    @Autowired
    Jwks jwks;

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {

        JwtClaimsSet claims = parameters.getClaims();

        try {
            var header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
            var payload = new Payload(claims.getClaims().toString());
            var jweObject = new JWEObject(header, payload);

            jweObject.encrypt(new RSAEncrypter(this.jwks.generateRsa().toRSAPublicKey()));
            String jwe = jweObject.serialize();

            return new Jwt(jwe, claims.getIssuedAt(), claims.getExpiresAt(), header.toJSONObject(), claims.getClaims());
        } catch (JOSEException e) {
            throw new RuntimeException("Unexpected JOSE exception");
        }
    }

}
