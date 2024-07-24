package com.security.jwtoauth2.controller;


import com.security.jwtoauth2.jwt.JWTUtil;
import com.security.jwtoauth2.jwt.service.ReissueService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;
    private final ReissueService reissueService;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response){
        return reissueService.reissue(request, response);
    }

    @GetMapping("/reissue")
    public ResponseEntity<?> reissueG(HttpServletRequest request, HttpServletResponse response){
        return reissueService.reissue(request, response);
    }
}
