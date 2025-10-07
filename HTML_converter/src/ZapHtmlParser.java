import org.jsoup.Jsoup;
import org.jsoup.nodes.*;
import org.jsoup.select.Elements;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

public class ZapHtmlParser {

    public static class Instance {
        public String url;
        public String method;
        public String parameter;
        public String evidence;
    }

    public static class AlertItem {
        public String id;           // 例如 #alert-123（若可解析）
        public String name;
        public String risk;         // High / Medium / Low / Info
        public String confidence;   // Confirmed / Medium / Low / False Positive ...
        public String cwe;          // 例如 CWE-79
        public String wasc;         // 例如 WASC-8
        public String description;
        public String solution;
        public List<String> references = new ArrayList<>();
        public List<Instance> instances = new ArrayList<>();
    }

    private static final Pattern LABEL_COLON = Pattern.compile("^\\s*([A-Za-z\\s/()_-]+)\\s*:\\s*(.*)$");
    private static final List<String> RISK_WORDS = List.of("risk", "風險", "嚴重度");
    private static final List<String> CONF_WORDS = List.of("confidence", "信心", "可信度");
    private static final List<String> DESC_WORDS = List.of("description", "說明", "描述");
    private static final List<String> SOL_WORDS  = List.of("solution", "解決方案", "修補建議");
    private static final List<String> REF_WORDS  = List.of("reference", "references", "參考", "參考資料");
    private static final List<String> CWE_WORDS  = List.of("cwe");
    private static final List<String> WASC_WORDS = List.of("wasc");

    public static void main(String[] args) throws Exception {
        List<String> argList = Arrays.asList(args);
        String file = getOpt(argList, "--file", null);

        // ✅ 如果沒傳參數，直接指定你要讀的那份檔案
        if (file == null) {
            // ← 這裡填你實際的 HTML 路徑，不要用 %20，要用正常空白或雙斜線
            file = "C:\\Users\\Shih_Hsuan Yu\\Desktop\\Git Project\\data_place\\非電算中心委外系統清單\\2025-07-03-ZAP-Report-aleph.ncut.edu.tw.html";
        }

        // ✅ 檢查檔案是否存在
        File htmlFile = new File(file);
        if (!htmlFile.exists()) {
            System.err.println("找不到檔案: " + htmlFile.getAbsolutePath());
            return;
        }

        String out = getOpt(argList, "--out", "json");
        boolean pretty = argList.contains("--pretty");
        String csvOut = getOpt(argList, "--csvOut", null);

        // ✅ 解析 HTML
        Document doc = Jsoup.parse(htmlFile, StandardCharsets.UTF_8.name());
        List<AlertItem> alerts = parseAlerts(doc);

        // ✅ 輸出 JSON 或 CSV
        if ("csv".equalsIgnoreCase(out)) {
            String csv = toCsv(alerts);
            if (csvOut != null) {
                try (FileWriter fw = new FileWriter(csvOut, StandardCharsets.UTF_8)) {
                    fw.write(csv);
                }
                System.out.println("CSV 已輸出：" + csvOut);
            } else {
                System.out.println(csv);
            }
        } else {
            Gson gson = pretty ? new GsonBuilder().setPrettyPrinting().create() : new Gson();
            String json = gson.toJson(alerts);

            String outputPath = "C:\\Users\\Shih_Hsuan Yu\\Desktop\\Git Project\\data_place\\JSON\\ZAP_output.json";


            try (FileWriter fw = new FileWriter(outputPath, StandardCharsets.UTF_8)) {
                fw.write(json);
                System.out.println("✅ 已輸出 JSON 檔案到：" + outputPath);
            }
        }
    }

    private static String getOpt(List<String> args, String key, String defVal) {
        int i = args.indexOf(key);
        return (i >= 0 && i + 1 < args.size()) ? args.get(i + 1) : defVal;
    }

    /** 嘗試解析 alerts。策略：
     * 1) 若有總表（table/列表）則先抓 alert 錨點 id → 再去詳細區塊取實例/描述等。
     * 2) 否則直接掃描可能的詳細區塊（id 以 alert 開頭、或含風險/描述標籤的區段）。
     */
    public static List<AlertItem> parseAlerts(Document doc) {
        Map<String, AlertItem> byId = new LinkedHashMap<>();
        List<AlertItem> results = new ArrayList<>();

        // --- 策略 1：從總表出發（常見在新舊版 ZAP 報告都有 summary 區） ---
        Elements tableRows = doc.select("table#alertsTable tbody tr, table.alerts tbody tr, table#summaryTable tbody tr");
        if (!tableRows.isEmpty()) {
            for (Element tr : tableRows) {
                // 找名稱與錨點
                Element nameCell = firstNonNull(
                        tr.selectFirst("td.alertname a[href^=#]"),
                        tr.selectFirst("td a[href^=#]"),
                        tr.selectFirst("td:nth-of-type(1) a[href^=#]"),
                        tr.selectFirst("td:nth-of-type(1)")
                );
                if (nameCell == null) continue;

                String name = cleanText(nameCell.text());
                String href = nameCell.hasAttr("href") ? nameCell.attr("href").trim() : null;
                String risk = guessRiskFromRow(tr);
                String confidence = guessConfidenceFromRow(tr);

                AlertItem item = new AlertItem();
                item.name = name;
                item.risk = risk;
                item.confidence = confidence;
                item.id = normalizeAnchor(href);
                byId.put(item.id != null ? item.id : UUID.randomUUID().toString(), item);
            }
        }

        // 如果有 id，去詳細段落補齊
        if (!byId.isEmpty()) {
            for (Map.Entry<String, AlertItem> kv : byId.entrySet()) {
                String id = kv.getKey();
                AlertItem item = kv.getValue();
                Element detail = (id != null && id.startsWith("#"))
                        ? findByAnchorId(doc, id.substring(1))
                        : null;
                if (detail != null) {
                    fillFromDetail(detail, item);
                } else {
                    // fallback：全文件找同名段落（風險不保證唯一，僅做輔助）
                    Element byName = doc.select("h2, h3, h4").stream()
                            .filter(h -> cleanText(h.text()).equalsIgnoreCase(item.name))
                            .findFirst().orElse(null);
                    if (byName != null) {
                        fillFromDetail(byName.parent(), item);
                    }
                }
                results.add(item);
            }
            return results;
        }

        // --- 策略 2：無總表時，直接掃所有可能的 alert 區塊 ---
        Elements candidates = new Elements();
        candidates.addAll(doc.select("div[id^=alert], section[id^=alert]"));
        if (candidates.isEmpty()) {
            // 再退一步：找含關鍵欄位的父容器（例如包含 Risk/Confidence/Description 的卡片）
            candidates = doc.select("div, section, article").stream()
                    .filter(el -> {
                        String t = el.text().toLowerCase();
                        return t.contains("risk") && t.contains("confidence") && (t.contains("description") || t.contains("solution"));
                    })
                    .collect(Elements::new, Elements::add, Elements::addAll);
        }

        for (Element block : candidates) {
            AlertItem item = new AlertItem();
            item.id = "#" + Optional.ofNullable(block.id()).orElse(UUID.randomUUID().toString());

            // 名稱：優先用近的標題
            Element title = firstNonNull(
                    block.selectFirst("h2"), block.selectFirst("h3"), block.selectFirst("h4"),
                    block.parent() != null ? block.parent().selectFirst("h2, h3, h4") : null
            );
            if (title != null) item.name = cleanText(title.text());

            // 解析標籤:值 形式（Description:, Solution:, Risk:, Confidence:, CWE:, WASC:, References:）
            fillLabeledFields(block, item);
            // 解析實例表格
            item.instances.addAll(extractInstances(block));

            // 至少有名字或風險才收
            if (item.name != null || item.risk != null || !item.instances.isEmpty()) {
                results.add(item);
            }
        }

        return results;
    }

    private static Element findByAnchorId(Document doc, String id) {
        // 1) 直接 id 命中
        Element e = doc.getElementById(id);
        if (e != null) return e;

        // 2) a[name=id] 或 a[id=id]
        Element a = doc.selectFirst("a[name=" + cssEscape(id) + "], a[id=" + cssEscape(id) + "]");
        return a != null ? a.parent() : null;
    }

    private static void fillFromDetail(Element detailRoot, AlertItem item) {
        // 標題名
        if (item.name == null) {
            Element h = firstNonNull(detailRoot.selectFirst("h2"), detailRoot.selectFirst("h3"), detailRoot.selectFirst("h4"));
            if (h != null) item.name = cleanText(h.text());
        }
        // 標籤欄位（Description: / Solution: / Risk: / Confidence: / CWE: / WASC: / References:）
        fillLabeledFields(detailRoot, item);
        // 實例（URLs/Instances table）
        item.instances.addAll(extractInstances(detailRoot));
    }

    private static void fillLabeledFields(Element root, AlertItem item) {
        // 常見版面：dl/dt/dd；也可能是 <p><b>Label:</b> text 或 table 的兩欄 label:value
        // 1) dl 結構
        for (Element dl : root.select("dl")) {
            Elements dts = dl.select("dt");
            for (Element dt : dts) {
                Element dd = nextTagSibling(dt, "dd");
                if (dd == null) continue;
                assignByLabel(dt.text(), dd, item);
            }
        }
        // 2) <p><b>Label:</b> value
        for (Element p : root.select("p")) {
            Element b = p.selectFirst("b, strong");
            if (b != null) {
                String bt = cleanText(b.text());
                if (bt.endsWith(":")) {
                    assignByLabel(bt, p, item);
                } else {
                    // 也可能是 "Risk: High" 在同個 <p> 文字裡
                    assignByColonText(p.text(), item);
                }
            } else {
                assignByColonText(p.text(), item);
            }
        }
        // 3) table 兩欄 label:value
        for (Element tr : root.select("table tr")) {
            Elements tds = tr.select("td, th");
            if (tds.size() >= 2) {
                assignByLabel(tds.get(0).text(), tds.get(1), item);
            } else if (tds.size() == 1) {
                assignByColonText(tds.get(0).text(), item);
            }
        }
        // 4) References 列表
        if (item.references.isEmpty()) {
            Elements refLists = root.select("ul, ol");
            for (Element ul : refLists) {
                // 粗略判斷該列表是否是參考資料（含 http/https 連結）
                boolean hasLinks = !ul.select("a[href]").isEmpty();
                if (hasLinks) {
                    List<String> links = ul.select("a[href]").stream()
                            .map(a -> a.attr("href").isBlank() ? cleanText(a.text()) : a.attr("href"))
                            .collect(Collectors.toList());
                    if (!links.isEmpty()) item.references.addAll(links);
                }
            }
        }
    }

    private static void assignByColonText(String text, AlertItem item) {
        Matcher m = LABEL_COLON.matcher(text);
        if (m.find()) {
            String label = cleanText(m.group(1));
            String val = cleanText(m.group(2));
            writeField(label, val, item);
        }
    }

    private static void assignByLabel(String labelText, Element valueEl, AlertItem item) {
        String label = cleanText(labelText.replace("：", ":")); // 全形轉半形
        String val = cleanText(valueEl.ownText().isBlank() ? valueEl.text() : valueEl.ownText());

        // 若值空，試著抓 valueEl 後續文字
        if (val.isBlank()) val = cleanText(valueEl.text());

        if (writeField(label, val, item)) {
            // ok
        } else {
            // 如果 label 本身就包含 "References"，把裡面的 link 一併收
            if (matchAny(label, REF_WORDS)) {
                List<String> links = valueEl.select("a[href]").stream()
                        .map(a -> a.attr("href").isBlank() ? cleanText(a.text()) : a.attr("href"))
                        .toList();
                if (!links.isEmpty()) item.references.addAll(links);
            }
        }
    }

    private static boolean writeField(String label, String value, AlertItem item) {
        String l = label.toLowerCase();
        if (matchAny(l, RISK_WORDS))        { item.risk = emptyThen(item.risk, value); return true; }
        if (matchAny(l, CONF_WORDS))        { item.confidence = emptyThen(item.confidence, value); return true; }
        if (matchAny(l, DESC_WORDS))        { item.description = emptyThen(item.description, value); return true; }
        if (matchAny(l, SOL_WORDS))         { item.solution = emptyThen(item.solution, value); return true; }
        if (matchAny(l, REF_WORDS))         { if (value!=null && !value.isBlank()) item.references.add(value); return true; }
        if (matchAny(l, CWE_WORDS))         { item.cwe = emptyThen(item.cwe, value); return true; }
        if (matchAny(l, WASC_WORDS))        { item.wasc = emptyThen(item.wasc, value); return true; }
        // 也有些 ZAP 會把「CWE: 79 (XSS)」這類一起寫在文字裡，已由 assignByColonText 處理
        return false;
    }

    private static String emptyThen(String cur, String v) {
        return (cur == null || cur.isBlank()) ? v : cur;
    }

    private static boolean matchAny(String s, List<String> keys) {
        String t = s.toLowerCase();
        for (String k : keys) {
            if (t.contains(k.toLowerCase())) return true;
        }
        return false;
    }

    private static List<Instance> extractInstances(Element root) {
        List<Instance> list = new ArrayList<>();

        // 常見：一張 Instances/URLs 表
        Elements tables = root.select("table");
        for (Element tb : tables) {
            // 先看表頭
            Map<String, Integer> header = headerIndex(tb.selectFirst("thead"), tb.selectFirst("tr"));
            if (header.isEmpty()) continue;

            Elements rows = tb.select("tbody tr");
            for (Element tr : rows) {
                Instance ins = new Instance();
                ins.url       = pickCell(tr, header, List.of("url", "uri", "地址", "連結"));
                ins.method    = pickCell(tr, header, List.of("method", "http method", "方法"));
                ins.parameter = pickCell(tr, header, List.of("parameter", "param", "參數", "變數"));
                ins.evidence  = pickCell(tr, header, List.of("evidence", "證據", "片段"));
                if (notAllEmpty(ins.url, ins.method, ins.parameter, ins.evidence)) {
                    list.add(ins);
                }
            }
        }

        // 若表格沒抓到，退而求其次：找包含 URL 的清單
        if (list.isEmpty()) {
            for (Element a : root.select("a[href^=http], a[href^=/]")) {
                Instance ins = new Instance();
                ins.url = a.attr("href");
                if (!ins.url.isBlank()) list.add(ins);
            }
        }
        return list;
    }

    private static Map<String, Integer> headerIndex(Element thead, Element firstRow) {
        Elements ths = thead != null ? thead.select("th") : new Elements();
        if (ths.isEmpty() && firstRow != null) ths = firstRow.select("th, td");
        Map<String, Integer> map = new HashMap<>();
        for (int i=0; i<ths.size(); i++) {
            String key = cleanText(ths.get(i).text()).toLowerCase();
            map.put(key, i);
        }
        return map;
    }

    private static String pickCell(Element tr, Map<String,Integer> header, List<String> wantKeys) {
        Elements tds = tr.select("td");
        if (tds.isEmpty()) return null;
        // 嘗試依 key 包含關鍵字比對
        for (Map.Entry<String,Integer> kv : header.entrySet()) {
            for (String w : wantKeys) {
                if (kv.getKey().contains(w.toLowerCase())) {
                    int idx = kv.getValue();
                    if (idx >= 0 && idx < tds.size()) {
                        String v = cleanText(tds.get(idx).text());
                        if (!v.isBlank()) return v;
                    }
                }
            }
        }
        return null;
    }

    private static String normalizeAnchor(String href) {
        if (href == null || href.isBlank()) return null;
        return href.startsWith("#") ? href : ("#" + href);
    }

    private static Element nextTagSibling(Element e, String tag) {
        for (Node n = e.nextSibling(); n != null; n = n.nextSibling()) {
            if (n instanceof Element el && el.tagName().equalsIgnoreCase(tag)) return el;
        }
        return null;
    }

    private static String cleanText(String s) {
        if (s == null) return null;
        return s.replace('\u00A0',' ').replaceAll("\\s+", " ").trim();
    }

    private static boolean notAllEmpty(String... ss) {
        for (String s : ss) if (s != null && !s.isBlank()) return true;
        return false;
    }

    private static Element firstNonNull(Element... els) {
        for (Element e : els) if (e != null) return e;
        return null;
    }

    private static String cssEscape(String s) {
        // 簡易處理
        return s.replace("\"","\\\"");
    }

    // --- CSV 匯出（摘要每個 alert 一列；instances 另以數量與第一筆 URL 表示）---
    private static String toCsv(List<AlertItem> alerts) {
        String[] headers = {"name","risk","confidence","cwe","wasc","instances_count","first_url"};
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", headers)).append("\n");
        for (AlertItem a : alerts) {
            String firstUrl = a.instances.isEmpty() ? "" : safeCsv(a.instances.get(0).url);
            String line = String.join(",",
                    safeCsv(a.name),
                    safeCsv(a.risk),
                    safeCsv(a.confidence),
                    safeCsv(a.cwe),
                    safeCsv(a.wasc),
                    String.valueOf(a.instances.size()),
                    firstUrl
            );
            sb.append(line).append("\n");
        }
        return sb.toString();
    }

    private static String safeCsv(String v) {
        if (v == null) return "";
        String s = v.replace("\"","\"\"");
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s + "\"";
        }
        return s;
    }
    // 根據 <tr> 的文字內容判斷風險
    private static String guessRiskFromRow(org.jsoup.nodes.Element tr) {
        String text = tr.text().toLowerCase();
        if (text.contains("high")) return "High";
        if (text.contains("medium")) return "Medium";
        if (text.contains("low")) return "Low";
        if (text.contains("info")) return "Informational";
        return "";
    }
    // 根據 <tr> 內容判斷 Confidence (信心等級)
    private static String guessConfidenceFromRow(org.jsoup.nodes.Element tr) {
        String text = tr.text().toLowerCase();
        if (text.contains("high")) return "High";
        if (text.contains("medium")) return "Medium";
        if (text.contains("low")) return "Low";
        if (text.contains("confirmed")) return "Confirmed";
        return "";
    }



}
