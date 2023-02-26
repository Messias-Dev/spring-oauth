package br.com.nunesmaia.messias.authorizationserver.jose;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.*;

import java.text.ParseException;

public class JwtCustomEncoder implements JwtEncoder {

    @Autowired
    private Jwks jwks;
    private final JWKSource<SecurityContext> jwkSource;

    public JwtCustomEncoder(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        var nimbusJwtEncoder = new NimbusJwtEncoder(this.jwkSource);
        var nimbusJwt = nimbusJwtEncoder.encode(parameters);
        var nimbusJwtValue = nimbusJwt.getTokenValue();

        JwtClaimsSet claims = parameters.getClaims();

        try {
            SignedJWT parsed = SignedJWT.parse(nimbusJwtValue);

            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
                    new Payload(parsed)
            );

            jweObject.encrypt(new RSAEncrypter(this.jwks.generateRsa()));
            String jweString = jweObject.serialize();

            return new Jwt(jweString, claims.getIssuedAt(), claims.getExpiresAt(), nimbusJwt.getHeaders(), nimbusJwt.getClaims());
        } catch (ParseException e) {
            throw new RuntimeException("Unexpected parse exception");
        } catch (JOSEException e) {
            throw new RuntimeException("Unexpected JOSE exception");
        }
    }

}
