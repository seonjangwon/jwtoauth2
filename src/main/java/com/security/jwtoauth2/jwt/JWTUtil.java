package com.security.jwtoauth2.jwt;

import com.security.jwtoauth2.dto.UserDTO;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret){

        //application에서 secret키를 가져와서 암호화?
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }


    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }


    public String createJwt(String category,String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("category",category)
                .claim("username", username) // 토큰에 들어갈 정보
                .claim("role", role) // 토큰에 들어갈 정보
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰 발생 시간
                .expiration(new Date(System.currentTimeMillis()+ expiredMs)) // 토큰 만료 = 토큰 발생 시간 + 기간(토큰 만들 때 정함)
                .signWith(secretKey) // 암호화
                .compact();
    }

    public UserDTO getUser(HttpServletRequest request){
        UserDTO userDTO = new UserDTO();

        // get refresh token
        String  refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies){
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            return null;
        }

        try {
            isExpired(refresh);
        } catch (ExpiredJwtException e){
            return null;
        }

        // 토큰이 refresh 인지 확인 (발급 시 페이로드에 명시)
        String category = getCategory(refresh);
        System.out.println("category = " + category);
        if (!category.equals("refresh")) {
            return null;
        }

        // DB 저장되어 있는지 확인
//        Boolean isExist = refreshRepository.existsByRefresh(refresh);
//        if (!isExist) {
//            return null;
//        }

        String username = getUsername(refresh);
        String role = getRole(refresh);

        userDTO.setName(username);
        userDTO.setRole(role);

        return userDTO;
    }


}
