package com.devglan.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;

import javax.servlet.http.HttpSession;
import java.util.Map;

@Component
public class WebSocketHandshakeInterceptor extends HttpSessionHandshakeInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(WebSocketHandshakeInterceptor.class);

    /**
     * 握手前的拦截处理
     * <p>
     * 1. 注册用户信息
     * 2. 绑定 WebSocketSession, 随后在控制器中可以访问
     *
     * @param request
     * @param response
     * @param wsHandler
     * @param attributes
     * @return
     * @throws Exception
     */
    @Override
    public boolean beforeHandshake(
        ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes
    ) throws Exception {
        if (request instanceof ServletServerHttpRequest) {
            ServletServerHttpRequest servletRequest = (ServletServerHttpRequest) request;
            HttpSession session = servletRequest.getServletRequest().getSession();
            // 获取令牌
            String token = session.getAttribute("token").toString();
            logger.info("Handshake connection from {}", servletRequest.getRemoteAddress().toString());
            // 存储会话ID
            attributes.put("sessionId", session.getId());
            return super.beforeHandshake(request, response, wsHandler, attributes);
        } else {

            // 认证失败
            logger.error("Authentication failed");
            return false;
        }
    }

    /**
     * 握手后
     *
     * @param request
     * @param response
     * @param wsHandler
     * @param ex
     */
    @Override
    public void afterHandshake(
        ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception ex
    ) {
        //握手成功后，通常用来注册用户信息
        logger.info("握手后");
        super.afterHandshake(request, response, wsHandler, ex);
    }
}
