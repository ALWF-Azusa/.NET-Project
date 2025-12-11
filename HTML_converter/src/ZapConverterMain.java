import java.io.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ZapConverterMain {

    public static void main(String[] args) {

        // ==========================================
        // ▼▼▼ 1. 設定輸入檔案路徑 (讀取您的特定報告) ▼▼▼
        // ==========================================
        // 您提供的路徑 (保留原本的寫法)
        String inputFilePath = "C:\\Users\\Shih_Hsuan Yu\\Desktop\\Git Project\\data_place\\非電算中心委外系統清單\\！report-eeproject.ncut.edu.tw.html";

        // ==========================================
        // ▼▼▼ 2. 設定輸出資料夾路徑 (JSON 存到這裡) ▼▼▼
        // ==========================================
        // 指定輸出到 JSON 資料夾
        String outputDirectoryPath = "C:/Users/Shih_Hsuan Yu/Desktop/Git Project/data_place/JSON";

        System.out.println("準備讀取檔案: " + inputFilePath);

        try {
            // --- 檢查輸入檔案 ---
            File inputFile = new File(inputFilePath);
            if (!inputFile.exists()) {
                System.err.println("錯誤：找不到輸入檔案 -> " + inputFile.getAbsolutePath());
                System.exit(1);
            }

            // --- 檢查並建立輸出資料夾 ---
            File outputDir = new File(outputDirectoryPath);
            if (!outputDir.exists()) {
                System.out.println("輸出資料夾不存在，正在建立: " + outputDirectoryPath);
                boolean created = outputDir.mkdirs(); // 自動建立資料夾
                if (!created) {
                    System.err.println("錯誤：無法建立輸出資料夾 -> " + outputDirectoryPath);
                    System.exit(1);
                }
            }

            // --- 1. 呼叫 Parser 解析 HTML ---
            ZapReportParser.Report report = ZapReportParser.parse(inputFile);
            System.out.println("解析成功！網站名稱 (Site): " + report.meta.site);

            // --- 2. 決定輸出檔名 ---
            String safeSiteName = ZapReportParser.sanitizeFilename(report.meta.site);
            // 組合完整路徑： 資料夾 + 檔名
            File outputFile = new File(outputDir, safeSiteName + ".json");

            // --- 3. 轉換為 JSON 並存檔 ---
            Gson gson = new GsonBuilder()
                    .setPrettyPrinting()
                    .disableHtmlEscaping()
                    .create();

            try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8)) {
                writer.write(gson.toJson(report));
            }

            System.out.println("------------------------------------------------");
            System.out.println("轉換完成！");
            System.out.println("輸出檔案位置: " + outputFile.getAbsolutePath());
            System.out.println("------------------------------------------------");

        } catch (Exception e) {
            System.err.println("發生錯誤: " + e.getMessage());
            e.printStackTrace();
        }
    }
}