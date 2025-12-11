// ZapHtmlParser.java
// 修正版：改用 anchor-id 定位 Alert Detail，並從 <table class="results"> 的 row 區塊逐列解析
// 需求：需要 jsoup + gson on classpath（同先前說明）
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ZapHtmlParser {

    // ===== Data models =====
    public static class ReportMeta { public String site; public String generatedOn; public String zapVersion; }
    public static class SummaryCounts { public Integer totalAlerts; public Integer high; public Integer medium; public Integer low; public Integer informational; public Integer falsePositives; }
    public static class SequenceStep { public String step; public String result; public String risk; }
    public static class Instance { public String url; public String method; public String parameter; public String attack; public String evidence; public String otherInfo; }
    public static class AlertItem {
        public String id;
        public String name;
        public String risk;
        public String confidence;
        public String cwe;
        public String wasc;
        public String description;
        public String solution;
        public String attack;
        public String otherInfo;
        public List<String> references = new ArrayList<>();
        public List<Instance> instances = new ArrayList<>();
    }
    public static class Report { public ReportMeta meta = new ReportMeta(); public SummaryCounts summary = new SummaryCounts(); public List<SequenceStep> sequences = new ArrayList<>(); public List<AlertItem> alerts = new ArrayList<>(); }

    // ===== utilities =====
    private static String clean(String s) { if (s==null) return ""; return s.replace('\u00A0',' ').trim(); }
    private static String afterColon(String s) { if (s==null) return null; int i=s.indexOf(':'); if (i<0) i=s.indexOf('：'); return (i>=0)? s.substring(i+1).trim() : s.trim(); }
    private static Integer tryParseInt(String s) { try { String n = s.replaceAll("[^0-9]", ""); return n.isEmpty()? null: Integer.parseInt(n); } catch(Exception e){return null;} }

    // ===== parse meta =====
    private static ReportMeta parseReportMeta(Document doc){
        ReportMeta m = new ReportMeta();
        Element body = doc.body();
        for(Element e: body.select("h2,h3,h4,p,div,span,td")) {
            String t = clean(e.text()).toLowerCase();
            if (t.contains("site:") && m.site==null) m.site = afterColon(e.text());
            else if (t.contains("generated on") && m.generatedOn==null) m.generatedOn = afterColon(e.text());
            else if (t.contains("zap version") && m.zapVersion==null) m.zapVersion = afterColon(e.text());
        }
        return m;
    }

    // ===== parse summary of alerts =====
    private static SummaryCounts parseSummaryOfAlerts(Document doc){
        SummaryCounts sc = new SummaryCounts();
        Element h = doc.select("h1,h2,h3,h4").stream().filter(x->clean(x.text()).equalsIgnoreCase("Summary of Alerts")).findFirst().orElse(null);
        Element scope = (h!=null)? h.parent() : doc.body();
        if (scope==null) return sc;
        Element tbl = scope.select("table").stream().findFirst().orElse(null);
        if (tbl != null) {
            for (Element tr : tbl.select("tr")) {
                Elements tds = tr.select("th,td");
                if (tds.size()>=2) {
                    String k = clean(tds.first().text());
                    String v = clean(tds.last().text());
                    fillSummaryCount(sc, k, v);
                }
            }
        } else {
            for (Element p : scope.select("p,li,div,span")) {
                String s = clean(p.text());
                if (s.isBlank()) continue;
                String[] parts = s.split("[;]");
                for (String part: parts) {
                    String[] kv = part.split("[:]",2);
                    if (kv.length==2) fillSummaryCount(sc, kv[0], kv[1]);
                }
            }
        }
        return sc;
    }
    private static void fillSummaryCount(SummaryCounts sc, String k, String v) {
        String key = clean(k).toLowerCase();
        Integer val = tryParseInt(v);
        if (val==null) return;
        if (key.contains("high")) sc.high = val;
        else if (key.contains("medium")) sc.medium = val;
        else if (key.contains("low")) sc.low = val;
        else if (key.contains("informational") || key.contains("info")) sc.informational = val;
        else if (key.contains("false")) sc.falsePositives = val;
        else if (key.contains("number of alerts") || key.contains("alerts") || key.contains("total")) sc.totalAlerts = val;
    }

    // ===== parse sequences (keeps previous approach) =====
    private static List<SequenceStep> parseSummaryOfSequences(Document doc) {
        List<SequenceStep> out = new ArrayList<>();
        Element h = doc.select("h1,h2,h3,h4").stream().filter(x->clean(x.text()).toLowerCase().startsWith("summary of sequences")).findFirst().orElse(null);
        if (h==null) return out;
        Element scope = h.parent();
        Element tbl = scope.select("table").stream().findFirst().orElse(null);
        if (tbl!=null) {
            List<String> headers = tbl.select("tr").stream().findFirst().map(tr->tr.select("th,td").eachText().stream().map(ZapHtmlParser::clean).collect(Collectors.toList())).orElse(List.of());
            for (Element tr: tbl.select("tr:has(td)")) {
                List<String> cells = tr.select("td").eachText().stream().map(ZapHtmlParser::clean).collect(Collectors.toList());
                SequenceStep s = new SequenceStep();
                for (int i=0;i<Math.min(headers.size(), cells.size()); i++){
                    String hn = headers.get(i).toLowerCase();
                    String val = cells.get(i);
                    if (hn.contains("step")) s.step = val;
                    else if (hn.contains("result")) s.result = val;
                    else if (hn.contains("risk")) s.risk = val;
                }
                if (s.step!=null||s.result!=null||s.risk!=null) out.add(s);
            }
        }
        return out;
    }

    // ===== parse alerts list and link to details by anchor id =====
    private static List<AlertItem> parseAlerts(Document doc) {
        List<AlertItem> out = new ArrayList<>();
        Element alertsTable = doc.select("table.alerts, table[class*=alerts]").stream().findFirst().orElse(null);
        if (alertsTable != null) {
            // table rows: columns: name (with <a href="#id">), Risk Level, Number of Instances
            for (Element tr : alertsTable.select("tr:has(td)")) {
                Elements tds = tr.select("td");
                if (tds.size() < 1) continue;
                Element nameCell = tds.get(0);
                Element link = nameCell.selectFirst("a[href]");
                AlertItem item = new AlertItem();
                if (link != null) {
                    String href = link.attr("href").trim();
                    if (href.startsWith("#")) item.id = href.substring(1);
                    item.name = clean(link.text());
                } else {
                    // fallback: plain text in cell
                    item.name = clean(nameCell.text());
                }
                // risk cell if exists
                if (tds.size() >= 2) {
                    item.risk = clean(tds.get(1).text());
                }
                // add and then fill details by id
                out.add(item);
            }
        } else {
            // fallback: find links in page that look like alerts
            for (Element a : doc.select("a[href]")) {
                String txt = clean(a.text());
                if (txt.length()>0 && txt.matches(".*[A-Za-z].*")) {
                    AlertItem it = new AlertItem();
                    String href = a.attr("href");
                    if (href.startsWith("#")) it.id = href.substring(1);
                    it.name = txt;
                    out.add(it);
                }
            }
        }

        // Fill details for each alert using anchor id (preferred)
        for (AlertItem ai : out) {
            fillAlertDetailsById(doc, ai);
        }
        return out;
    }

    // ===== find anchor and parse the detail block that follows =====
    private static void fillAlertDetailsById(Document doc, AlertItem item) {
        if (item.id==null || item.id.isBlank()) {
            // fallback: search by name in headings / ths
            Element guess = doc.select("th,td,h2,h3,h4").stream().filter(e->clean(e.text()).toLowerCase().contains(item.name.toLowerCase())).findFirst().orElse(null);
            if (guess!=null) {
                // parse from the table containing guess
                Element tbl = guess.closest("table");
                if (tbl!=null) parseAlertDetailFromResultsTable(tbl, item, guess);
            }
            return;
        }
        // find anchor <a id="..."> (exact)
        Element anchor = doc.selectFirst("a[id="+item.id+"]");
        if (anchor == null) {
            // sometimes id may be on an element other than <a> - try attribute search
            anchor = doc.selectFirst("[id="+item.id+"]");
        }
        if (anchor == null) return;

        // anchor is inside a table row that is the header for the alert detail
        Element tr = anchor.closest("tr");
        Element resultsTable = tr != null ? tr.closest("table") : null;

        if (resultsTable != null && resultsTable.classNames().contains("results")) {
            // parse detail from this table, starting from the row after the header row (the one containing the anchor)
            parseAlertDetailFromResultsTable(resultsTable, item, tr);
        } else if (resultsTable != null) {
            // still try to parse
            parseAlertDetailFromResultsTable(resultsTable, item, tr);
        } else {
            // fallback: search global tables for a <tr> that contains the anchor and parse from its table
            Element tab = anchor.closest("table");
            if (tab != null) parseAlertDetailFromResultsTable(tab, item, anchor.closest("tr"));
        }
    }

    private static void parseAlertDetailFromResultsTable(Element table, AlertItem item, Element headerRow) {
        // get all rows and find index of headerRow
        List<Element> rows = table.select("tr");
        int startIndex = 0;
        if (headerRow != null) {
            for (int i=0;i<rows.size();i++){
                if (rows.get(i).outerHtml().contains(headerRow.html())) { startIndex = i+1; break; }
            }
        } else {
            // default start at 0
            startIndex = 0;
        }

        // First: try to capture Description if present: look for a tr where first td/th contains "Description"
        for (int i = startIndex; i < rows.size(); i++) {
            Element r = rows.get(i);
            Elements ths = r.select("th,td");
            if (ths.size()>=2) {
                String left = clean(ths.get(0).text()).toLowerCase();
                if (left.contains("description") || left.contains("描述")) {
                    // the right cell contains description (could be many <div>)
                    item.description = ths.get(1).text().trim();
                    startIndex = i+1;
                    break;
                }
            }
        }

        // Now parse sequential label:value rows into instances.
        List<Instance> instances = new ArrayList<>();
        Instance cur = null;

        for (int i = startIndex; i < rows.size(); i++) {
            Element r = rows.get(i);
            Elements tds = r.select("td");
            if (tds.size() == 0) continue;

            // Some rows are header-like: if first cell contains nothing or is empty, skip
            String left = clean(tds.get(0).text());
            String right = tds.size() >= 2 ? tds.get(1).html() : "";

            // Detect if this row marks the start of a new alert header (a new <th> header row), stop parsing further
            if (r.select("th").size() > 0 && r.select("th").text().length() > 0 && r.select("th a[id]").size()>0 && !r.outerHtml().contains("id=\""+item.id+"\"")) {
                // encountered next alert header -> stop
                break;
            }

            // normalize label (Chinese/English)
            String label = left.toLowerCase().trim();
            if (label.equalsIgnoreCase("url") || label.equalsIgnoreCase("網址") || label.equals("url")) {
                // start a new instance
                if (cur != null) {
                    instances.add(cur);
                }
                cur = new Instance();
                // right cell may contain <a href="...">link</a>
                Element a = tds.get(1).selectFirst("a[href]");
                if (a != null) cur.url = clean(a.attr("href"));
                else cur.url = clean(tds.get(1).text());
            } else if (label.contains("方法") || label.contains("method")) {
                if (cur == null) cur = new Instance();
                cur.method = clean(tds.get(1).text());
            } else if (label.contains("parameter") || label.contains("參數")) {
                if (cur == null) cur = new Instance();
                cur.parameter = clean(tds.get(1).text());
            } else if (label.contains("attack") || label.contains("攻擊")) {
                if (cur == null) cur = new Instance();
                // Sometimes '攻擊' field is empty; we still set from right cell
                cur.attack = clean(tds.get(1).text());
            } else if (label.toLowerCase().contains("evidence") || label.contains("證據")) {
                if (cur == null) cur = new Instance();
                // keep the raw HTML text for evidence (avoid losing < and >); convert HTML entities to text
                cur.evidence = clean(tds.get(1).text());
            } else if (label.toLowerCase().contains("other info") || label.contains("其他資訊") || label.contains("other information")) {
                if (cur == null) cur = new Instance();
                cur.otherInfo = clean(tds.get(1).text());
                // note: after Other Info, next row is likely next URL or next group
            } else {
                // Could be global field like "Other Info" at alert-level (not instance-level)
                // If left cell is "Other Info" but we haven't started an instance, store at alert level
                if ((label.contains("other info") || label.contains("其他資訊") || label.contains("other information")) && cur==null) {
                    item.otherInfo = clean(tds.get(1).text());
                }
                // Also check for Attack at alert level
                if ((label.contains("attack") || label.contains("攻擊")) && (cur==null)) {
                    item.attack = clean(tds.get(1).text());
                }
                // Also check for Evidence at alert level
                if ((label.toLowerCase().contains("evidence") || label.contains("證據")) && (cur==null)) {
                    item.description = item.description == null ? clean(tds.get(1).text()) : item.description;
                }
            }
        }

        // push last cur
        if (cur != null) instances.add(cur);
        item.instances.addAll(instances);

        // Also try to extract references / CWE / WASC / Solution from table rows (scan remaining rows)
        for (Element r : table.select("tr")) {
            Elements tds2 = r.select("td,th");
            if (tds2.size() >= 2) {
                String left = clean(tds2.get(0).text()).toLowerCase();
                String right = clean(tds2.get(1).text());
                if (left.contains("solution") || left.contains("解決方案") || left.contains("建議")) {
                    item.solution = firstNonEmpty(item.solution, right);
                } else if (left.contains("references") || left.contains("參考")) {
                    if (right.length()>0) item.references.addAll(Arrays.asList(right.split("[;,]")));
                } else if (left.contains("cwe")) {
                    item.cwe = firstNonEmpty(item.cwe, right);
                } else if (left.contains("wasc")) {
                    item.wasc = firstNonEmpty(item.wasc, right);
                } else if (left.contains("confidence")) {
                    item.confidence = firstNonEmpty(item.confidence, right);
                }
            }
        }
    }

    private static String firstNonEmpty(String a, String b) { if (a!=null && !a.isBlank()) return a; if (b!=null && !b.isBlank()) return b; return null; }

    // ===== main =====
    public static void main(String[] args) {
        String input = (args!=null && args.length>=1) ? args[0] : "report.html";
        String output = (args!=null && args.length>=2) ? args[1] : "ZAP_output.json";
        try {
            File f = new File(input);
            if (!f.exists()) {
                System.err.println("找不到輸入檔案: " + f.getAbsolutePath());
                System.exit(2);
            }
            Document doc = Jsoup.parse(f, "UTF-8");

            Report report = new Report();
            report.meta = parseReportMeta(doc);
            report.summary = parseSummaryOfAlerts(doc);
            report.sequences = parseSummaryOfSequences(doc);
            report.alerts = parseAlerts(doc);

            Gson g = new GsonBuilder().setPrettyPrinting().create();
            try (Writer w = new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8)) {
                w.write(g.toJson(report));
            }
            System.out.println("輸出 JSON: " + new File(output).getAbsolutePath());
        } catch (Exception e) {
            System.err.println("解析失敗：" + e.getMessage());
            e.printStackTrace();
        }
    }
}
