# ---------- Build Stage ----------
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# ---------- Run Stage ----------
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY --from=builder /app/target/household-line-bot-1.0-SNAPSHOT.jar app.jar

ENV PORT=10000
EXPOSE 10000

CMD ["java", "-cp", "app.jar", "com.pam.bot.BotApp"]
