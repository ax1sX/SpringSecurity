package com.devglan.websocket.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.SessionConnectedEvent;

@Component
public class StompConnectedEventListener implements ApplicationListener<SessionConnectedEvent> {
    private static final Logger logger = LoggerFactory.getLogger(StompConnectedEventListener.class);

    @Override
    public void onApplicationEvent(SessionConnectedEvent event) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(event.getMessage());
        logger.info("Connection build successfully: {}", accessor.getUser());
    }
}
