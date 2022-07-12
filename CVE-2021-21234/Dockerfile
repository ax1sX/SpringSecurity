FROM openjdk:8-jdk-alpine
MAINTAINER baeldung.com
COPY target/spring-boot-hello-world-example-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
EXPOSE 8887
RUN mkdir -p ~/sping.log