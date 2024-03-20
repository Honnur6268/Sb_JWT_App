package com.security.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {
    @Value("${app.secret}")
    private String secret;

    //1. Generate Token
    public String generateToken(String subject){
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer("Ali")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15)))
                .signWith(SignatureAlgorithm.HS512, secret.getBytes())
                .compact();
    }

    //2. Read Token
    public Claims getClaims(String token){
        return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
    }

    //3. Read Expiration Date
    public Date getExpirationDate(String token){
        return getClaims(token).getExpiration();
    }

    //4. Read username/subject
    public String getUsername(String token){
        return getClaims(token).getSubject();
    }

    //5. Validate Expiration Date
    public boolean isTokenExpired(String token){
        Date expirationDate = getExpirationDate(token);
        return expirationDate.before(new Date(System.currentTimeMillis()));
    }

    //6. validate username in token with database, and token expiration
    public boolean validateToken(String token, String username){
        String tokenUsername = getUsername(token);
        return (username.equals(tokenUsername)) && !isTokenExpired(token);
    }


}
