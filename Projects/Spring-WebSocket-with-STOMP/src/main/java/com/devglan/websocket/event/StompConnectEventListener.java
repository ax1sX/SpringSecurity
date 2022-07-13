package com.devglan.websocket.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.SessionConnectEvent;

@Component
public class StompConnectEventListener implements ApplicationListener<SessionConnectEvent> {
    private static final Logger logger = LoggerFactory.getLogger(StompConnectEventListener.class);

    @Override
    public void onApplicationEvent(SessionConnectEvent event) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(event.getMessage());
        logger.info("Accept connection request from client: {}", accessor.getHost());
    }
}
