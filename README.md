Nai-baan - Household LINE Bot (Java / Spark)

Files:
- pom.xml
- src/main/java/com/pam/bot/BotApp.java
- .env.example

Quick start (local):
1. Install Java 17 and Maven.
2. Copy .env.example to .env and fill LINE_CHANNEL_TOKEN & LINE_CHANNEL_SECRET.
3. mvn clean package
4. java -cp target/household-line-bot-1.0-SNAPSHOT.jar com.pam.bot.BotApp
5. Use ngrok to expose local port: ngrok http 10000
6. Set LINE Developers webhook to https://<ngrok-url>/webhook

Deploying to Render:
1. Create a GitHub repo and push this project.
2. On Render, create New → Web Service → Connect GitHub → select repo.
3. Build Command: mvn clean package
4. Start Command: java -cp target/household-line-bot-1.0-SNAPSHOT.jar com.pam.bot.BotApp
5. Add ENV vars on Render: LINE_CHANNEL_TOKEN, LINE_CHANNEL_SECRET, PORT

Security:
- Never commit .env with secrets to a public repository.
- If you accidentally exposed tokens, re-issue them on LINE Developers and update env.
