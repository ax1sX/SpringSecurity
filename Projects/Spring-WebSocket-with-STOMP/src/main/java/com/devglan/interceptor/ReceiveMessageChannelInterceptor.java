package com.devglan.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptorAdapter;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class ReceiveMessageChannelInterceptor extends ChannelInterceptorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(ReceiveMessageChannelInterceptor.class);

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    /**
     * 在消息发送前,可以对消息进行修改
     *
     * @param message
     * @param channel
     * @return
     */
    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {

        logger.info("Message received: {}", message);

        // 通过消息对象获取 StompHeaderAccessor
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        StompCommand command = accessor.getCommand();
        // 处理订阅命令
        if (command.equals(StompCommand.SUBSCRIBE)) {
            // 从数据库获取用户订阅频道进行对比
            // (这里为了演示直接使用set集合代替)
            Set<String> subscribedChannels = new HashSet<>();
            subscribedChannels.add("/topic/group");
            subscribedChannels.add("/topic/online_user");

            // 如果用户要订阅的目标通道是允许的
            if (subscribedChannels.contains(accessor.getDestination())) {
                //该用户订阅的频道合法
                return super.preSend(message, channel);
            } else {
                //该用户订阅的频道不合法直接返回null前端用户就接受不到该频道信息。
                return null;
            }
        }
        return super.preSend(message, channel);
    }

    @Override
    public boolean preReceive(MessageChannel channel) {
        return super.preReceive(channel);
    }
}
