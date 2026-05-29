FROM ghcr.io/petadoption-project/pet-adoption-spring-base:21
EXPOSE 8080
COPY target/*.jar app.jar
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
