package com.dbiswa.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    private static final String SECRET_KEY= "9fC3xLqP8mVtR2zW7nHkY4sJdQ6bA1eXgU5oZrN0pIiSsTtV"

    public String extractUsername(String token){
        return null;
    }
    public Claims extractAllClaims(String token){
        return Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token).getPayload();
    }
}
