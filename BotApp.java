package com.pam.bot;

import static spark.Spark.*;

import com.google.gson.*;
import okhttp3.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import java.sql.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

public class BotApp {
    static final String LINE_TOKEN = System.getenv("LINE_CHANNEL_TOKEN");
    static final String LINE_SECRET = System.getenv("LINE_CHANNEL_SECRET");
    static final String PORT_ENV = System.getenv("PORT");
    static final int PORT_NUM = (PORT_ENV != null) ? Integer.parseInt(PORT_ENV) : 10000;

    static final Gson gson = new GsonBuilder().create();
    static final OkHttpClient httpClient = new OkHttpClient();

    static Connection conn;

    public static void main(String[] args) throws Exception {
        port(PORT_NUM);
        initDB();

        get("/", (req, res) -> "Household LINE Bot is running");

        post("/webhook", (req, res) -> {
            String signature = req.headers("X-Line-Signature");
            String body = req.body();

            if (!verifySignature(LINE_SECRET, body, signature)) {
                res.status(401);
                return "Invalid signature";
            }

            JsonObject payload = gson.fromJson(body, JsonObject.class);
            JsonArray events = payload.getAsJsonArray("events");
            if (events != null) {
                for (JsonElement evEl : events) {
                    JsonObject ev = evEl.getAsJsonObject();
                    handleEvent(ev);
                }
            }
            res.status(200);
            return "OK";
        });

        System.out.println("Bot started on port " + PORT_NUM);
    }

    static boolean verifySignature(String secret, String body, String signature) {
        try {
            if (secret == null || secret.isEmpty()) return false;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] digest = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            String encoded = Base64.getEncoder().encodeToString(digest);
            return encoded.equals(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    static void handleEvent(JsonObject event) {
        try {
            String type = event.get("type").getAsString();
            if (!"message".equals(type)) return;
            JsonObject message = event.getAsJsonObject("message");
            if (!"text".equals(message.get("type").getAsString())) return;

            String text = message.get("text").getAsString();
            String replyToken = event.get("replyToken").getAsString();
            ParsedResult p = parseMessageFlexible(text);

            if ("purchase".equals(p.cmd) || "consume".equals(p.cmd)) {
                int itemId = ensureItem("house1", p.name);
                storeTransaction("house1", itemId, p.cmd.equals("purchase") ? "purchase" : "consume",
                        p.quantity_raw, p.unit != null ? p.unit : (p.unit_raw != null ? p.unit_raw : "g"),
                        p.price != null ? p.price : 0.0, p.source, p.date);

                Inventory inv = computeInventoryForItem("house1", itemId);
                String remain = inv.asDisplay();
                String humanCmd = p.cmd.equals("purchase") ? "บันทึกการซื้อเรียบร้อย" : "บันทึกการใช้เรียบร้อย";
                String reply = String.format("%s: %s %s (จาก: %s)\nคงเหลือ: %s",
                        humanCmd, p.name, displayQty(p), p.source == null ? "-" : p.source, remain);
                replyToLine(replyToken, reply);
            } else if ("check".equals(p.cmd)) {
                if (p.name != null && !p.name.isEmpty() && !"all".equalsIgnoreCase(p.name)) {
                    Integer id = getItemId("house1", p.name);
                    if (id == null) {
                        replyToLine(p.rawText, "ไม่พบรายการ " + p.name + " ในสต็อก");
                    } else {
                        Inventory inv = computeInventoryForItem("house1", id);
                        replyToLine(p.rawText, p.name + ": " + inv.asDisplay());
                    }
                } else {
                    List<String> lines = listInventory("house1");
                    String resp = lines.isEmpty() ? "ยังไม่มีรายการในสต็อก" : String.join("\n", lines);
                    replyToLine(p.rawText, resp);
                }
            } else {
                String help = "สวัสดี Pam 😊\nตัวอย่างคำสั่ง (พิมพ์เป็นประโยคเดียวได้):\n- ซื้อ 17/10 แมคโคร หมูสับ 400g 67\n- ใช้ หมูสับ 200 g\n- เช็ค หรือ เช็ค หมูสับ";
                replyToLine(p.rawText, help);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void replyToLine(String replyToken, String text) {
        try {
            if (LINE_TOKEN == null) {
                System.err.println("LINE_CHANNEL_TOKEN not set");
                return;
            }
            JsonObject message = new JsonObject();
            message.addProperty("type", "text");
            message.addProperty("text", text);

            JsonObject body = new JsonObject();
            body.addProperty("replyToken", replyToken);
            JsonArray arr = new JsonArray(); arr.add(message);
            body.add("messages", arr);

            Request req = new Request.Builder()
                    .url("https://api.line.me/v2/bot/message/reply")
                    .addHeader("Authorization", "Bearer " + LINE_TOKEN)
                    .post(RequestBody.create(body.toString(), MediaType.parse("application/json; charset=utf-8")))
                    .build();
            try (Response resp = httpClient.newCall(req).execute()) {
                System.out.println("LINE reply status: " + resp.code());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void initDB() throws SQLException {
        String dbFile = System.getenv("DB_FILE");
        if (dbFile == null || dbFile.isBlank()) dbFile = "inventory.db";
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
        try (Statement s = conn.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL;");
            s.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY AUTOINCREMENT, household_id TEXT DEFAULT 'house1', name TEXT NOT NULL, unit_default TEXT DEFAULT 'g', category TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);");
            s.execute("CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, household_id TEXT DEFAULT 'house1', item_id INTEGER, type TEXT, quantity REAL, unit TEXT, price REAL DEFAULT 0, source TEXT, note TEXT, tx_date DATE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);");
        }
    }

    static int ensureItem(String householdId, String name) throws SQLException {
        Integer id = getItemId(householdId, name);
        if (id != null) return id;
        try (PreparedStatement p = conn.prepareStatement("INSERT INTO items (household_id, name, unit_default) VALUES (?, ?, ?);", Statement.RETURN_GENERATED_KEYS)) {
            p.setString(1, householdId);
            p.setString(2, name);
            p.setString(3, "g");
            p.executeUpdate();
            try (ResultSet rs = p.getGeneratedKeys()) {
                if (rs.next()) return rs.getInt(1);
            }
        }
        throw new SQLException("Failed to insert item");
    }

    static Integer getItemId(String householdId, String name) throws SQLException {
        try (PreparedStatement p = conn.prepareStatement("SELECT id FROM items WHERE household_id = ? AND name = ? LIMIT 1")) {
            p.setString(1, householdId);
            p.setString(2, name);
            try (ResultSet r = p.executeQuery()) {
                if (r.next()) return r.getInt("id");
            }
        }
        return null;
    }

    static void storeTransaction(String householdId, int itemId, String type, Double quantity, String unit, Double price, String source, String txDate) throws SQLException {
        if (quantity == null) quantity = 0.0;
        if (unit == null || unit.isEmpty()) unit = "g";
        if (txDate == null || txDate.isEmpty()) {
            txDate = LocalDate.now().format(DateTimeFormatter.ISO_DATE);
        } else {
            txDate = normalizeDate(txDate);
        }
        try (PreparedStatement p = conn.prepareStatement("INSERT INTO transactions (household_id,item_id,type,quantity,unit,price,source,tx_date) VALUES (?,?,?,?,?,?,?,?);")) {
            p.setString(1, householdId);
            p.setInt(2, itemId);
            p.setString(3, type);
            p.setDouble(4, quantity);
            p.setString(5, unit);
            p.setDouble(6, price);
            p.setString(7, source);
            p.setString(8, txDate);
            p.executeUpdate();
        }
    }

    static String normalizeDate(String raw) {
        try {
            raw = raw.trim();
            if (raw.matches("\\d{1,2}\\/\\d{1,2}(?:\\/\\d{2,4})?")) {
                String[] parts = raw.split("[\\/]");

                int d = Integer.parseInt(parts[0]);
                int m = Integer.parseInt(parts[1]);
                int y = (parts.length == 3) ? Integer.parseInt(parts[2]) : LocalDate.now().getYear();
                if (y < 100) y += 2000;
                LocalDate dt = LocalDate.of(y, m, d);
                return dt.format(DateTimeFormatter.ISO_DATE);
            }
        } catch (Exception e) {
            // ignore fallback to today
        }
        return LocalDate.now().format(DateTimeFormatter.ISO_DATE);
    }

    static Inventory computeInventoryForItem(String householdId, int itemId) throws SQLException {
        try (PreparedStatement p = conn.prepareStatement("SELECT type, quantity, unit FROM transactions WHERE household_id=? AND item_id=?")) {
            p.setString(1, householdId);
            p.setInt(2, itemId);
            try (ResultSet r = p.executeQuery()) {
                double g = 0;
                double pcs = 0;
                while (r.next()) {
                    String type = r.getString("type");
                    double qty = r.getDouble("quantity");
                    String unit = r.getString("unit");
                    String normalized = normalizeUnitForCalc(unit);
                    if ("g".equals(normalized)) {
                        double v = toGrams(qty, unit);
                        if ("purchase".equals(type)) g += v;
                        else if ("consume".equals(type)) g -= v;
                    } else if ("pcs".equals(normalized)) {
                        if ("purchase".equals(type)) pcs += qty;
                        else if ("consume".equals(type)) pcs -= qty;
                    } else {
                        if ("purchase".equals(type)) pcs += qty;
                        else if ("consume".equals(type)) pcs -= qty;
                    }
                }
                return new Inventory(g, pcs);
            }
        }
    }

    static List<String> listInventory(String householdId) throws SQLException {
        List<String> out = new ArrayList<>();
        try (PreparedStatement p = conn.prepareStatement("SELECT id, name FROM items WHERE household_id = ?")) {
            p.setString(1, householdId);
            try (ResultSet r = p.executeQuery()) {
                while (r.next()) {
                    int id = r.getInt("id");
                    String name = r.getString("name");
                    Inventory inv = computeInventoryForItem(householdId, id);
                    out.add(name + ": " + inv.asDisplay());
                }
            }
        }
        return out;
    }

    static String normalizeUnitForCalc(String unit) {
        if (unit == null) return "g";
        String s = unit.toLowerCase();
        if (s.contains("kg") || s.contains("กก") || s.contains("กิโล")) return "g";
        if (s.contains("g") || s.contains("กรัม") || s.contains("gram")) return "g";
        if (s.contains("pcs") || s.contains("ชิ้น")) return "pcs";
        if (s.contains("pack") || s.contains("แพ็ค") || s.contains("แพค") || s.contains("แพ็ก")) return "pack";
        if (s.contains("ขีด")) return "g";
        return s;
    }

    static double toGrams(double qty, String unit) {
        if (unit == null) return qty;
        String u = unit.toLowerCase();
        if (u.contains("kg") || u.contains("กก") || u.contains("กิโล")) return qty * 1000.0;
        if (u.contains("g") || u.contains("กรัม") || u.contains("gram")) return qty;
        if (u.contains("ขีด")) return qty * 100.0;
        return qty;
    }

    static class ParsedResult {
        String cmd = "unknown";
        String rawText;
        String date;
        String name;
        Double quantity_raw;
        String unit_raw;
        String unit;
        Double qty_in_g;
        Double price;
        String source;
    }

    static ParsedResult parseMessageFlexible(String text) {
        ParsedResult res = new ParsedResult();
        res.rawText = text;
        String raw = (text == null) ? "" : text.trim();
        String lower = raw.toLowerCase();

        if (lower.matches("^\\s*เช็ค\\b.*")) {
            res.cmd = "check";
            Matcher m = Pattern.compile("^\\s*เช็ค\\s*(.+)?", Pattern.CASE_INSENSITIVE).matcher(raw);
            if (m.find() && m.groupCount() >= 1) {
                String g = m.group(1);
                if (g != null) res.name = g.trim();
            }
            return res;
        }

        Matcher dateM = Pattern.compile("\\b(\\d{1,2}[\\/\\-]\\d{1,2}(?:[\\/\\-]\\d{2,4})?)\\b").matcher(raw);
        if (dateM.find()) res.date = dateM.group(1);

        Matcher priceM = Pattern.compile("(?:ราคา\\s*)?(\\d+(?:[\\.,]\\d+)?)(?:\\s*(?:บาท|฿))", Pattern.CASE_INSENSITIVE).matcher(raw);
        if (priceM.find()) res.price = parseNumberStr(priceM.group(1));

        Pattern qtyPattern = Pattern.compile("(\\d+(?:[\\.,]\\d+)?)(?:\\s*(kg|กก|กิโล|kilo|g|gram|grams|กรัม|ขีด|ชิ้น|pcs|แพ็ค|แพค|pack|แพ็ก|box|ขวด|กล่อง)?)\\b", Pattern.CASE_INSENSITIVE);
        Matcher qtyAll = qtyPattern.matcher(raw);
        List<MatchResult> qtyMatches = new ArrayList<>();
        while (qtyAll.find()) qtyMatches.add(qtyAll.toMatchResult());
        if (!qtyMatches.isEmpty()) {
            for (int i = qtyMatches.size()-1; i>=0; i--) {
                MatchResult mr = qtyMatches.get(i);
                int end = mr.end();
                String after = raw.substring(Math.min(end, raw.length()-1));
                if (!after.matches(".*(บาท|฿).*")) {
                    res.quantity_raw = parseNumberStr(mr.group(1));
                    res.unit_raw = mr.group(2) != null ? mr.group(2) : "";
                    break;
                }
            }
            if (res.quantity_raw == null) {
                MatchResult mr = qtyMatches.get(qtyMatches.size()-1);
                res.quantity_raw = parseNumberStr(mr.group(1));
                res.unit_raw = mr.group(2) != null ? mr.group(2) : "";
            }
        }

        if (lower.contains("ซื้อ")) res.cmd = "purchase";
        else if (lower.contains("ใช้")) res.cmd = "consume";

        Matcher fromM = Pattern.compile("\\b(?:จาก|ที่)\\s+([^\\d\\,\\.\\n]+?)(?:\\s|$)", Pattern.CASE_INSENSITIVE).matcher(raw);
        if (fromM.find()) {
            res.source = fromM.group(1).trim().replaceAll("\\s+(ราคา|บาท|฿).*", "").trim();
        }

        String candidate = raw.replaceAll("(?i)\\b(ซื้อ|ใช้|เช็ค)\\b", "").trim();
        if (res.date != null) candidate = candidate.replace(res.date, "").trim();
        if (res.price != null) {
            candidate = candidate.replaceAll("\\b\\d+(?:[\\.,]\\d+)?\\s*(?:บาท|฿)?", "").trim();
        }
        if (res.unit_raw != null && res.quantity_raw != null) {
            candidate = candidate.replaceFirst("(\\d+(?:[\\.,]\\d+)?)(?:\\s*(?:kg|กก|กิโล|kilo|g|gram|grams|กรัม|ขีด|ชิ้น|pcs|แพ็ค|แพค|pack|แพ็ก|box|ขวด|กล่อง)?)\\b", "");
            candidate = candidate.trim();
        }
        if (res.source != null) {
            candidate = candidate.replaceAll("(?i)(จาก|ที่)\\s+" + Pattern.quote(res.source), "").trim();
        }
        candidate = candidate.replaceAll("(?i)\\b(จาก|ที่|ราคา|บาท|฿)\\b", "").trim();
        res.name = candidate.isEmpty() ? "item" : candidate;

        if (res.quantity_raw != null) {
            UnitResult ur = normalizeAndConvertUnit(res.unit_raw, res.quantity_raw);
            res.unit = ur.unit;
            res.qty_in_g = ur.qtyInGrams;
        }
        return res;
    }

    static double parseNumberStr(String s) {
        if (s == null) return 0.0;
        s = s.replaceAll("\\u00A0", "").replaceAll("บาท|฿", "").trim();
        s = s.replaceAll(",", ".");
        Matcher m = Pattern.compile("-?\\d+(?:\\.\\d+)?").matcher(s);
        if (m.find()) {
            return Double.parseDouble(m.group());
        }
        return 0.0;
    }

    static class UnitResult { String unit; Double qtyInGrams; UnitResult(String u, Double q){ unit=u; qtyInGrams=q;} }

    static UnitResult normalizeAndConvertUnit(String unitRaw, Double qty) {
        if (unitRaw == null) return new UnitResult("g", toGrams(qty, "g"));
        String s = unitRaw.toLowerCase().replace(".", "").trim();
        List<String> gVariants = Arrays.asList("g","gram","grams","กรัม","g","g,");
        List<String> kgVariants = Arrays.asList("kg","กก","กิโล","kilo","kilogram","กิโลกรัม");
        List<String> pcsVariants = Arrays.asList("pcs","piece","pieces","ชิ้น");
        List<String> packVariants = Arrays.asList("pack","แพ็ค","แพค","แพ็ก");
        List<String> keedVariants = Arrays.asList("ขีด");

        if (gVariants.stream().anyMatch(s::contains) || s.matches("^$")) {
            return new UnitResult("g", toGrams(qty, "g"));
        }
        if (kgVariants.stream().anyMatch(s::contains)) {
            return new UnitResult("g", toGrams(qty, "kg"));
        }
        if (keedVariants.stream().anyMatch(s::contains)) {
            return new UnitResult("g", toGrams(qty, "ขีด"));
        }
        if (pcsVariants.stream().anyMatch(s::contains)) {
            return new UnitResult("pcs", null);
        }
        if (packVariants.stream().anyMatch(s::contains)) {
            return new UnitResult("pack", null);
        }
        if (s.matches(".*(box|ขวด|กล่อง).*")) {
            return new UnitResult("box", null);
        }
        if (s.endsWith("kg")) return new UnitResult("g", toGrams(qty, "kg"));
        if (s.endsWith("g")) return new UnitResult("g", toGrams(qty, "g"));
        return new UnitResult(s, null);
    }

    static String displayQty(ParsedResult p) {
        if (p.quantity_raw == null) return "1";
        String u = (p.unit != null) ? p.unit : (p.unit_raw != null ? p.unit_raw : "g");
        if ("g".equals(u)) return (p.qty_in_g != null ? (int)Math.round(p.qty_in_g) + " g" : p.quantity_raw + " " + u);
        return p.quantity_raw + " " + u;
    }

    static void replyToLine(String replyToken, String text) {
        System.out.println("Will reply: " + text);
        replyToLine(replyToken, text, LINE_TOKEN);
    }
    static void replyToLine(String replyToken, String message, String token) {
        if (token == null) {
            System.err.println("LINE_CHANNEL_TOKEN not set");
            return;
        }
        try {
            JsonObject msg = new JsonObject();
            msg.addProperty("type", "text");
            msg.addProperty("text", message);
            JsonObject body = new JsonObject();
            body.addProperty("replyToken", replyToken);
            JsonArray arr = new JsonArray(); arr.add(msg);
            body.add("messages", arr);
            Request request = new Request.Builder()
                    .url("https://api.line.me/v2/bot/message/reply")
                    .addHeader("Authorization", "Bearer " + token)
                    .post(RequestBody.create(body.toString(), MediaType.parse("application/json; charset=utf-8")))
                    .build();
            try (Response resp = httpClient.newCall(request).execute()) {
                System.out.println("LINE reply code: " + resp.code());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class Inventory {
        double grams;
        double pcs;
        Inventory(double g, double p) { grams = g; pcs = p; }
        String asDisplay() {
            StringBuilder sb = new StringBuilder();
            if (Math.abs(grams) > 0.0001) sb.append(Math.round(grams)).append(" g");
            if (Math.abs(pcs) > 0.0001) {
                if (sb.length() > 0) sb.append(" / ");
                sb.append((int)pcs).append(" pcs");
            }
            if (sb.length() == 0) return "0";
            return sb.toString();
        }
    }
}
