import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

// 這個類別只負責邏輯與資料結構，不包含 main
public class ZapReportParser {

    // ===== Data Models (公開靜態類別，讓 Main 可以存取) =====
    public static class ReportMeta { public String site; public String generatedOn; public String zapVersion; }
    public static class SummaryCounts { public Integer totalAlerts; public Integer high; public Integer medium; public Integer low; public Integer informational; public Integer falsePositives; }
    public static class SequenceStep { public String step; public String result; public String risk; }
    public static class Instance { public String url; public String method; public String parameter; public String attack; public String evidence; public String otherInfo; }
    
    public static class AlertItem {
        public String pluginId; 
        public String name;
        public Integer count; 
        public String risk;
        public String confidence;
        public String cweId;
        public String wascId;
        public String description;
        public String solution;
        public String attack;
        public String otherInfo;
        public List<String> references = new ArrayList<>();
        public List<Instance> instances = new ArrayList<>();
    }
    
    public static class Report { 
        public ReportMeta meta = new ReportMeta(); 
        public SummaryCounts summary = new SummaryCounts(); 
        public List<SequenceStep> sequences = new ArrayList<>(); 
        public List<AlertItem> alerts = new ArrayList<>(); 
    }

    // ===== Public API: 主要的呼叫入口 =====
    public static Report parse(File htmlFile) throws IOException {
        Document doc = Jsoup.parse(htmlFile, "UTF-8");
        Report report = new Report();
        report.meta = parseReportMeta(doc);
        report.summary = parseSummaryOfAlerts(doc);
        report.sequences = parseSummaryOfSequences(doc);
        report.alerts = parseAlerts(doc);
        return report;
    }

    // ===== Utility: 檔名清理工具 (供 Main 使用) =====
    public static String sanitizeFilename(String site) {
        if (site == null || site.isBlank()) return "ZAP_output";
        String name = site.replaceAll("(?i)^https?://", ""); // 移除 http://
        if (name.endsWith("/")) name = name.substring(0, name.length() - 1); // 移除尾部斜線
        name = name.replaceAll("[^a-zA-Z0-9.\\-_]", "_"); // 替換特殊字元
        return name;
    }

    // ===== Private Helpers (內部邏輯) =====
    private static String clean(String s) { if (s==null) return ""; return s.replace('\u00A0',' ').trim(); }
    private static String afterColon(String s) { if (s==null) return null; int i=s.indexOf(':'); if (i<0) i=s.indexOf('：'); return (i>=0)? s.substring(i+1).trim() : s.trim(); }
    private static Integer tryParseInt(String s) { try { String n = s.replaceAll("[^0-9]", ""); return n.isEmpty()? null: Integer.parseInt(n); } catch(Exception e){return null;} }
    private static String firstNonEmpty(String a, String b) { if (a!=null && !a.isBlank()) return a; if (b!=null && !b.isBlank()) return b; return null; }

    // ===== Internal Parsing Logic =====

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
                    fillSummaryCount(sc, clean(tds.first().text()), clean(tds.last().text()));
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

    private static List<SequenceStep> parseSummaryOfSequences(Document doc) {
        List<SequenceStep> out = new ArrayList<>();
        Element h = doc.select("h1,h2,h3,h4").stream().filter(x->clean(x.text()).toLowerCase().startsWith("summary of sequences")).findFirst().orElse(null);
        if (h==null) return out;
        Element scope = h.parent();
        Element tbl = scope.select("table").stream().findFirst().orElse(null);
        if (tbl!=null) {
            List<String> headers = tbl.select("tr").stream().findFirst().map(tr->tr.select("th,td").eachText().stream().map(ZapReportParser::clean).collect(Collectors.toList())).orElse(List.of());
            for (Element tr: tbl.select("tr:has(td)")) {
                List<String> cells = tr.select("td").eachText().stream().map(ZapReportParser::clean).collect(Collectors.toList());
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

    private static List<AlertItem> parseAlerts(Document doc) {
        List<AlertItem> out = new ArrayList<>();
        Element alertsTable = doc.select("table.alerts, table[class*=alerts]").stream().findFirst().orElse(null);
        if (alertsTable != null) {
            for (Element tr : alertsTable.select("tr:has(td)")) {
                Elements tds = tr.select("td");
                if (tds.size() < 1) continue;
                Element nameCell = tds.get(0);
                Element link = nameCell.selectFirst("a[href]");
                AlertItem item = new AlertItem();
                if (link != null) {
                    String href = link.attr("href").trim();
                    if (href.startsWith("#")) item.pluginId = href.substring(1);
                    item.name = clean(link.text());
                } else {
                    item.name = clean(nameCell.text());
                }
                
                if (tds.size() >= 2) item.risk = clean(tds.get(1).text());
                if (tds.size() >= 3) item.count = tryParseInt(clean(tds.get(2).text()));
                out.add(item);
            }
        } else {
            for (Element a : doc.select("a[href]")) {
                String txt = clean(a.text());
                if (txt.length()>0 && txt.matches(".*[A-Za-z].*")) {
                    AlertItem it = new AlertItem();
                    String href = a.attr("href");
                    if (href.startsWith("#")) it.pluginId = href.substring(1);
                    it.name = txt;
                    out.add(it);
                }
            }
        }

        for (AlertItem ai : out) {
            fillAlertDetailsById(doc, ai);
            if (ai.count == null && !ai.instances.isEmpty()) {
                ai.count = ai.instances.size();
            }
        }
        return out;
    }

    private static void fillAlertDetailsById(Document doc, AlertItem item) {
        if (item.pluginId==null || item.pluginId.isBlank()) {
            Element guess = doc.select("th,td,h2,h3,h4").stream().filter(e->clean(e.text()).toLowerCase().contains(item.name.toLowerCase())).findFirst().orElse(null);
            if (guess!=null) {
                Element tbl = guess.closest("table");
                if (tbl!=null) parseAlertDetailFromResultsTable(tbl, item, guess);
            }
            return;
        }
        Element anchor = doc.selectFirst("a[id="+item.pluginId+"]");
        if (anchor == null) anchor = doc.selectFirst("[id="+item.pluginId+"]");
        if (anchor == null) return;

        Element tr = anchor.closest("tr");
        Element resultsTable = tr != null ? tr.closest("table") : null;

        if (resultsTable != null) {
            parseAlertDetailFromResultsTable(resultsTable, item, tr);
        } else {
            Element tab = anchor.closest("table");
            if (tab != null) parseAlertDetailFromResultsTable(tab, item, anchor.closest("tr"));
        }
    }

    private static void parseAlertDetailFromResultsTable(Element table, AlertItem item, Element headerRow) {
        List<Element> rows = table.select("tr");
        int startIndex = 0;
        if (headerRow != null) {
            for (int i=0;i<rows.size();i++){
                if (rows.get(i).outerHtml().contains(headerRow.html())) { startIndex = i+1; break; }
            }
        }

        // Description
        for (int i = startIndex; i < rows.size(); i++) {
            Element r = rows.get(i);
            Elements ths = r.select("th,td");
            if (ths.size()>=2) {
                String left = clean(ths.get(0).text()).toLowerCase();
                if (left.contains("description") || left.contains("描述")) {
                    item.description = ths.get(1).text().trim();
                    startIndex = i+1;
                    break;
                }
            }
        }

        // Instances
        List<Instance> instances = new ArrayList<>();
        Instance cur = null;

        for (int i = startIndex; i < rows.size(); i++) {
            Element r = rows.get(i);
            Elements tds = r.select("td");
            if (tds.size() == 0) continue;

            String left = clean(tds.get(0).text());
            
            // Check for next header
            if (r.select("th").size() > 0 && r.select("th").text().length() > 0 && r.select("th a[id]").size()>0 && !r.outerHtml().contains("id=\""+item.pluginId+"\"")) {
                break;
            }

            String label = left.toLowerCase().trim();
            if (label.equalsIgnoreCase("url") || label.equalsIgnoreCase("網址") || label.equals("url")) {
                if (cur != null) instances.add(cur);
                cur = new Instance();
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
                cur.attack = clean(tds.get(1).text());
            } else if (label.toLowerCase().contains("evidence") || label.contains("證據")) {
                if (cur == null) cur = new Instance();
                cur.evidence = clean(tds.get(1).text());
            } else if (label.toLowerCase().contains("other info") || label.contains("其他資訊") || label.contains("other information")) {
                if (cur == null) cur = new Instance();
                cur.otherInfo = clean(tds.get(1).text());
            } else {
                if ((label.contains("other info") || label.contains("其他資訊") || label.contains("other information")) && cur==null) {
                    item.otherInfo = clean(tds.get(1).text());
                }
                if ((label.contains("attack") || label.contains("攻擊")) && (cur==null)) {
                    item.attack = clean(tds.get(1).text());
                }
                if ((label.toLowerCase().contains("evidence") || label.contains("證據")) && (cur==null)) {
                    item.description = item.description == null ? clean(tds.get(1).text()) : item.description;
                }
            }
        }
        if (cur != null) instances.add(cur);
        item.instances.addAll(instances);

        // Meta info
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
                    item.cweId = firstNonEmpty(item.cweId, right);
                } else if (left.contains("wasc")) {
                    item.wascId = firstNonEmpty(item.wascId, right);
                } else if (left.contains("confidence")) {
                    item.confidence = firstNonEmpty(item.confidence, right);
                }
            }
        }
    }
}
