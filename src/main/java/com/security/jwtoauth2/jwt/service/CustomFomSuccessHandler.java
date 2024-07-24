package com.security.jwtoauth2.jwt.service;

import com.security.jwtoauth2.entity.RefreshEntity;
import com.security.jwtoauth2.jwt.JWTUtil;
import com.security.jwtoauth2.repository.RefreshRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomFomSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        // 토큰 생성
        String access = jwtUtil.createJwt("access",username,role, 600000L);
        String refresh = jwtUtil.createJwt("refresh",username,role, 600000L);

        // refresh 토큰 저장
        addRefreshEntity(username, refresh, 86400000L);

        response.setHeader("access",access); // 로컬스토리지 저장
        response.addCookie(createCookie("refresh",refresh)); // httpOnly 쿠키 저장
        response.setStatus(HttpStatus.OK.value());
        response.sendRedirect("/"); // 인증이 성공한 후에는 root로 이동
    }

    private void addRefreshEntity(String username, String refresh, Long expireMs){

        Date date = new Date(System.currentTimeMillis() + expireMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value){

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60*60*60);
        //cookie.setSecure(true); // https
        cookie.setPath("/");
        cookie.setHttpOnly(true); // javascript 사용 금지

        return cookie;
    }
}
