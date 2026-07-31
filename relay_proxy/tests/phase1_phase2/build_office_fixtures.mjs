import fs from "node:fs/promises";
import path from "node:path";
import {
  Presentation,
  PresentationFile,
  SpreadsheetFile,
  Workbook,
} from "@oai/artifact-tool";

const outputDir = path.resolve(process.argv[2] ?? "fixtures");
const qaDir = path.resolve(process.argv[3] ?? "qa");
const korean = "이 문서는 로컬 DLP 1차 2차 기능 검증용 문서입니다.";
const english = "LOCAL DLP PHASE ONE TWO TEST DOCUMENT";
const marker = "DLP_TEST_CONFIDENTIAL_MARKER_2026";

await fs.mkdir(outputDir, { recursive: true });
await fs.mkdir(qaDir, { recursive: true });

const workbook = Workbook.create();
const sheet = workbook.worksheets.add("DLP_Test");
sheet.showGridLines = false;
sheet.getRange("A1:D1").merge();
sheet.getRange("A1").values = [["Local DLP spreadsheet extraction fixture"]];
sheet.getRange("A1:D1").format = {
  fill: "#17365D",
  font: { bold: true, color: "#FFFFFF", size: 16 },
  verticalAlignment: "center",
};
sheet.getRange("A3:D6").values = [
  ["Field", "Value", "Purpose", "Length"],
  ["Korean", korean, "Korean text extraction", null],
  ["English", english, "English text extraction", null],
  ["Marker", marker, "DLP rule verification", null],
];
sheet.getRange("D4").formulas = [["=LEN(B4)"]];
sheet.getRange("D4:D6").fillDown();
sheet.getRange("A3:D3").format = {
  fill: "#D9EAF7",
  font: { bold: true, color: "#17365D" },
  horizontalAlignment: "center",
};
sheet.getRange("A3:D6").format.borders = {
  preset: "all",
  style: "thin",
  color: "#B4C7E7",
};
sheet.getRange("A3:A6").format.columnWidth = 14;
sheet.getRange("B3:B6").format.columnWidth = 48;
sheet.getRange("C3:C6").format.columnWidth = 28;
sheet.getRange("D3:D6").format.columnWidth = 12;
sheet.getRange("A3:D6").format.wrapText = true;
sheet.freezePanes.freezeRows(3);

const workbookInspection = await workbook.inspect({
  kind: "table,formula",
  sheetId: "DLP_Test",
  range: "A1:D6",
  include: "values,formulas",
  maxChars: 5000,
});
await fs.writeFile(path.join(qaDir, "xlsx_inspection.ndjson"), workbookInspection.ndjson, "utf8");
const workbookPreview = await workbook.render({
  sheetName: "DLP_Test",
  range: "A1:D6",
  scale: 2,
  format: "png",
});
await fs.writeFile(path.join(qaDir, "xlsx_preview.png"), new Uint8Array(await workbookPreview.arrayBuffer()));
const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(path.join(outputDir, "safe_sample.xlsx"));
await fs.rm(path.join(outputDir, "safe_sample.xlsx.inspect.ndjson"), { force: true });

const presentation = Presentation.create({
  slideSize: { width: 1280, height: 720 },
});
const slide = presentation.slides.add();
slide.background.fill = "#F7FAFC";

const accent = slide.shapes.add({
  geometry: "rect",
  name: "accent",
  position: { left: 0, top: 0, width: 22, height: 720 },
  fill: "#2563EB",
  line: { style: "solid", fill: "none", width: 0 },
});
accent.text = "";

const title = slide.shapes.add({
  geometry: "textbox",
  name: "title",
  position: { left: 84, top: 74, width: 1080, height: 76 },
  fill: "none",
  line: { style: "solid", fill: "none", width: 0 },
});
title.text = "Local DLP presentation extraction fixture";
title.text.style = { fontSize: 50, bold: true, color: "#0F172A", fontFamily: "Malgun Gothic" };

const body = slide.shapes.add({
  geometry: "roundRect",
  name: "fixture-text",
  position: { left: 84, top: 202, width: 1080, height: 338 },
  fill: "#FFFFFF",
  line: { style: "solid", fill: "#CBD5E1", width: 2 },
  borderRadius: "rounded-xl",
});
body.text = `${korean}\n\n${english}\n\n${marker}`;
body.text.style = { fontSize: 30, color: "#1E293B", fontFamily: "Malgun Gothic" };

const footer = slide.shapes.add({
  geometry: "textbox",
  name: "footer",
  position: { left: 84, top: 594, width: 1080, height: 40 },
  fill: "none",
  line: { style: "solid", fill: "none", width: 0 },
});
footer.text = "Synthetic test data only - no real confidential information";
footer.text.style = { fontSize: 18, color: "#64748B" };

const slidePreview = await presentation.export({ slide, format: "png", scale: 1 });
await fs.writeFile(path.join(qaDir, "pptx_slide_1.png"), new Uint8Array(await slidePreview.arrayBuffer()));
const slideLayout = await slide.export({ format: "layout" });
await fs.writeFile(path.join(qaDir, "pptx_slide_1.layout.json"), await slideLayout.text(), "utf8");
const snapshot = await presentation.inspect({
  kind: "slide,textbox,shape",
  maxChars: 5000,
});
await fs.writeFile(path.join(qaDir, "pptx_inspection.ndjson"), snapshot.ndjson, "utf8");
const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save(path.join(outputDir, "safe_sample.pptx"));
await fs.rm(path.join(outputDir, "safe_sample.pptx.inspect.ndjson"), { force: true });

console.log(JSON.stringify({ xlsx: "safe_sample.xlsx", pptx: "safe_sample.pptx" }));
