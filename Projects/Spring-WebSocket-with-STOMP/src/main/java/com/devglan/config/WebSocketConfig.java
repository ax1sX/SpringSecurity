package com.devglan.config;

import com.devglan.interceptor.WebSocketHandshakeInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptorAdapter;
import org.springframework.web.socket.config.annotation.AbstractWebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig extends AbstractWebSocketMessageBrokerConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(WebSocketConfig.class);

    @Autowired
    private WebSocketHandshakeInterceptor handshakeInterceptor;

//    @Autowired
//    private WebSocketMessageBrokerStats webSocketMessageBrokerStats;
//    @PostConstruct
//    public void init() {
//        webSocketMessageBrokerStats.setLoggingPeriod(10 * 1000);
//    }
//    @Bean
//    public ServletServerContainerFactoryBean createWebSocketContainer() {
//        ServletServerContainerFactoryBean container = new ServletServerContainerFactoryBean();
//        container.setMaxTextMessageBufferSize(8192);
//        container.setMaxBinaryMessageBufferSize(8192);
//        return container;
//    }

    /**
     * 配置消息代理
     *
     * @param config
     */
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        /**
         * 使用Spring内置的基于内存的简单消息代理
         *
         * 内存消息代理只能在当前应用程序实例中有效, 不能跨多个应用程序, 要能够跨多个应用程序实例收发消息, 需要
         * 使用全功能的消息代理, 比如RabbitMQ, ActiveMQ等.
         */
        config.enableSimpleBroker("/topic/", "/queue/");

        /**
         * 应用前缀, 所有 STOMP 消息目标都只能以配置的前缀开始
         * 在STOMP应用中, 客户端只能发送到前缀为"app"开头的目标
         */
        config.setApplicationDestinationPrefixes("/app");
    }

    /**
     * 注册WebSocket端点
     *
     * @param registry
     */
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry
            .addEndpoint("/greeting");
    }

    /**
     * 配置WebSocket传输参数
     * 消息大小, 虽然理论上Websocket支持无限制大小的消息, 但实际的实现是有限制的
     * 比如Tomcat是8K, Netty 是 64K, 因此,类似 Stomp.js 这种客户端会把大的消息
     * 切分为 16K 大小的消息片段, 以多个消息发送给服务器, 所以要求服务器缓冲并且重新组装消息.
     *
     * @param registration
     */
    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration registration) {
        // 发送缓冲区   512K
        registration.setSendBufferSizeLimit(512 * 1024);
        // 发送时间限制 15秒
        registration.setSendTimeLimit(15 * 1000);
        // 最大消息大小 128K
        registration.setMessageSizeLimit(128 * 1024);

    }

    /**
     * 配置客户端消息通道, 该通道是接受客户端消息的通道
     *
     * @param registration
     */
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new ChannelInterceptorAdapter() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                logger.info("Message received: {}", message);
                return super.preSend(message, channel);
            }
        });

    }

    @Override
    public void configureClientOutboundChannel(ChannelRegistration registration) {
        registration.interceptors(new ChannelInterceptorAdapter() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                logger.info("Send message: {}", message);
                return super.preSend(message, channel);
            }
        });
    }
}
