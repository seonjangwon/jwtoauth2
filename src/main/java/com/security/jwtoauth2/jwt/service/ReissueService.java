package com.security.jwtoauth2.jwt.service;


import com.security.jwtoauth2.entity.RefreshEntity;
import com.security.jwtoauth2.jwt.JWTUtil;
import com.security.jwtoauth2.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // get refresh token
        String  refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies){
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e){
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh 인지 확인 (발급 시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        System.out.println("category = " + category);
        if (!category.equals("refresh")) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // DB 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT
        String newAccess = jwtUtil.createJwt("access",username,role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh",username,role, 86400000L);

        // Refresh 토큰 저장 DB에 기존 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, refresh, 86400000L);

        response.setHeader("access", newAccess);
        response.addCookie(creteCookie("refresh" ,newRefresh));


        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie creteCookie(String key, String value){
        Cookie cookie = new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        cookie.setSecure(true); // 이거는 https 로 진행 시 넣어준다
        cookie.setPath("/"); // 사용될 범위 지정?
        cookie.setHttpOnly(true); // 자바 스크립트에서 사용 못하도록 설정

        return cookie;
    }


    private void addRefreshEntity(String username, String refresh, Long expireMs){

        Date date = new Date(System.currentTimeMillis() + expireMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }


}
