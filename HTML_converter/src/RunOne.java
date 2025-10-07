import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.List;

public class RunOne {
    public static void main(String[] args) throws Exception {
        // ① 指定單一 ZAP HTML 路徑（先把這行改成你的檔案）
        String inputHtml = "C:/Users/Shih_Hsuan%20Yu/Desktop/Git%20Project/data_place/非電算中心委外系統清單/report-account.ncut.edu.tw.html";

        // ② 指定輸出 JSON 路徑（可改）
        String outputJson = "C:/Users/Shih_Hsuan Yu/Desktop/Git Project/data_place/JSON";

        // ③ 讀檔 → 解析 → 輸出
        Document doc = Jsoup.parse(new File(inputHtml), StandardCharsets.UTF_8.name());

        // 這行呼叫你已經有的解析器（zap alerts 轉物件）
        List<ZapHtmlParser.AlertItem> alerts = ZapHtmlParser.parseAlerts(doc);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(alerts);

        Files.writeString(Path.of(outputJson), json, StandardCharsets.UTF_8);
        System.out.println("完成！已輸出：" + outputJson);
    }
}

