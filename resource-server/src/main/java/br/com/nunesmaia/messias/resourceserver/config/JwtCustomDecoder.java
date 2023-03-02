package br.com.nunesmaia.messias.resourceserver.config;

import br.com.nunesmaia.messias.resourceserver.exception.InvalidJwtException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

public class JwtCustomDecoder implements JwtDecoder {

    @Autowired
    Jwks jwks;

    @Override
    public Jwt decode(String token) throws JwtException {
        EncryptedJWT parse = null;
        try {
            parse = EncryptedJWT.parse(token);

            RSADecrypter decrypter = new RSADecrypter(this.jwks.generateRsa());
            parse.decrypt(decrypter);

            Map<String, Object> jwtPayload = parse.getPayload().toJSONObject();
            Long milliSeconds = (Long) jwtPayload.get("exp");
            Instant exp = Instant.ofEpochMilli(milliSeconds);

            if (exp.isBefore(Instant.now())) {
                throw new InvalidJwtException();
            }

            return new Jwt(token, null, Instant.ofEpochMilli(milliSeconds), parse.getHeader().toJSONObject(), jwtPayload);
        } catch (ParseException | JOSEException | InvalidJwtException e) {
            // returns HTTP status 401
            throw new RuntimeException("Invalid JWT");
        }
    }
}
