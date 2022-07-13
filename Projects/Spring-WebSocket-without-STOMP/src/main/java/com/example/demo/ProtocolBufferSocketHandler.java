package com.example.demo;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.BinaryWebSocketHandler;

/**
 * 不支持非二进制的消息, 具体可以参考 BinaryWebSocketHandler 中的 handleTextMessage 方法.
 * 也可以覆盖 BinaryWebSocketHandler.handleTextMessage 方法来自定义错误消息.
 */
@Component
public class ProtocolBufferSocketHandler extends BinaryWebSocketHandler {
    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
        super.handleBinaryMessage(session, message);
    }
}
