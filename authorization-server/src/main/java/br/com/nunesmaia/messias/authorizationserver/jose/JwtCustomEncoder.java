package br.com.nunesmaia.messias.authorizationserver.jose;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.*;

import java.util.Date;

public class JwtCustomEncoder implements JwtEncoder {

    @Autowired
    Jwks jwks;

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {

        JwtClaimsSet claims = parameters.getClaims();

        try {
            var header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

            var jwtClaimsSet = new JWTClaimsSet.Builder()
                    .subject(claims.getSubject())
                    .claim("client", "client")
                    .expirationTime(Date.from(claims.getExpiresAt()))
                    .build();

            var encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
            encryptedJWT.encrypt(new RSAEncrypter(this.jwks.generateRsa().toRSAPublicKey()));

            String jwe = encryptedJWT.serialize();

            return new Jwt(jwe, claims.getIssuedAt(), claims.getExpiresAt(), header.toJSONObject(), jwtClaimsSet.getClaims());
        } catch (JOSEException e) {
            throw new RuntimeException("Unexpected JOSE exception");
        }
    }

}
