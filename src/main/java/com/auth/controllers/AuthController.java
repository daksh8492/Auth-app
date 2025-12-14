package com.auth.controllers;

import com.auth.dto.LoginRequest;
import com.auth.dto.RefreshTokenFromRequest;
import com.auth.dto.TokenResponse;
import com.auth.dto.UserDto;
import com.auth.entities.RefreshToken;
import com.auth.entities.User;
import com.auth.repositories.RefreshTokenRepository;
import com.auth.repositories.UserRepo;
import com.auth.security.CookieService;
import com.auth.security.JwtService;
import com.auth.service.AuthService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){

        Authentication authentication = authentication(loginRequest);
        User user = userRepo.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("Invalid Username or Passowrd"));
        if (!user.isEnabled())
            throw new DisabledException("User is disabled");
        String jti = UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTTLSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenOb);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());
        cookieService.attachRefreshCookie(response, refreshToken, jwtService.getRefreshTTLSeconds().intValue());

        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTTLSeconds(), modelMapper.map(user, UserDto.class));
        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody UserDto userDto){
        return new ResponseEntity<>(authService.register(userDto), HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenFromRequest body, HttpServletResponse response, HttpServletRequest request){

        String refreshToken = readRefreshTokenFromRequest(body, request).orElseThrow(()-> new BadCredentialsException("Invalid Refresh Token"));

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);

        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(()-> new BadCredentialsException("Invalid Refresh Token JTI"));

        if (storedRefreshToken.isRevoked()){
            throw new BadCredentialsException("Refresh Token is Revoked");
        }

        if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
            throw new BadCredentialsException("Refresh Token is Expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Refresh Token does not belog to this user");
        }

        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setRevoked(true);
        storedRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedRefreshToken);

        User user = storedRefreshToken.getUser();

        var newRefreshTokenOb = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTTLSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenOb);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user, newJti);
        cookieService.attachRefreshCookie(response, newRefreshToken, jwtService.getRefreshTTLSeconds().intValue());
        TokenResponse tokenResponse = TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTTLSeconds(), modelMapper.map(user, UserDto.class));

        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response){
        readRefreshTokenFromRequest(null, request).ifPresent(token -> {
            try {
                if (jwtService.isRefresh(token)){
                    String jti = jwtService.getJti(token);
                    refreshTokenRepository.findByJti(jti).ifPresent(rt -> {
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                    });

                }
            }catch (JwtException ignored){
            }
        });
        cookieService.clearRefreshToken(response);
        SecurityContextHolder.clearContext();
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    private Authentication authentication(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid Username or Passowrd");
        }
    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenFromRequest body, HttpServletRequest request) {

        if (request.getCookies() != null){

            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookieService.getRefreshTokenCookieName().equals(cookie.getName()))
                    .map(cookie -> cookie.getValue())
                    .filter(s -> !s.isBlank())
                    .findFirst();

            if (fromCookie.isPresent()){
                return fromCookie;
            }
        }

        if (body != null && body.refreshToken()!=null && !body.refreshToken().isBlank()){
            return Optional.of(body.refreshToken());
        }

        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader!=null && !refreshHeader.isBlank()){
            return Optional.of(refreshHeader.trim());
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader!=null && authHeader.startsWith("Bearer ")){
            String candidate = authHeader.substring(7).trim();
            if (!candidate.isBlank()){
                if (jwtService.isRefresh(candidate)){
                    return Optional.of(candidate);
                }
            }
        }

        return Optional.empty();

    }


}
