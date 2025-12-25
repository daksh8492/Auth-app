package com.auth.security;

import com.auth.repositories.UserRepo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserRepo userRepo;

//    @Autowired
    private Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        logger.info("Authorization token  {}", header);
        if (header != null && header.startsWith("Bearer ")){
            String token = header.substring(7);

            if (jwtService.isAccess(token)){
                Jws<Claims> parse = jwtService.parse(token);
                Claims payload = parse.getPayload();
                String id = payload.getSubject();
                UUID userUuid = UUID.fromString(id);

                userRepo.findById(userUuid)
                        .ifPresent(user -> {
                            if (user.isEnabled()){
                                List<GrantedAuthority> authorities = user.getRoles() == null || user.getRoles().isEmpty() ? List.of():
                                        user.getRoles().stream().map(
                                                role -> new SimpleGrantedAuthority(role.getName())
                                        ).collect(Collectors.toList());

                                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                        user.getEmail(),
                                        null,
                                        List.of()
                                );

                                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                                if (SecurityContextHolder.getContext().getAuthentication()==null)
                                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                            }

                        });
            }


        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
