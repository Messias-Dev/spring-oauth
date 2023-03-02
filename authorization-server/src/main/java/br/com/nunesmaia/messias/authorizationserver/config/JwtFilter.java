package br.com.nunesmaia.messias.authorizationserver.config;

import br.com.nunesmaia.messias.authorizationserver.exception.InvalidJwtException;
import br.com.nunesmaia.messias.authorizationserver.jose.Jwks;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    Jwks jwks;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            this.authorize(request);
            filterChain.doFilter(request, response);
        } catch (InvalidJwtException e) {
            response.sendError(401);
        }
        filterChain.doFilter(request, response);
    }

    private void authorize(HttpServletRequest request) throws InvalidJwtException {
        String authorization = request.getHeader("Authorization");
        String jwt;

        if (StringUtils.hasText(authorization) && authorization.startsWith("Bearer ") && authorization.length() > 7) {
            jwt = authorization.substring(7);
            // TODO validate token
        }

        throw new InvalidJwtException();
    }
}
