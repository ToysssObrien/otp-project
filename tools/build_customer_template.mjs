import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const outputPath = path.join(projectRoot, "static", "customer-import-template.xlsx");

const csvText = [
  "ID,Name,PhoneNumber,OTP",
  "CUS-001,Sokha Chan,0971234567,",
  "CUS-002,Dara Lim,0887654321,",
  "CUS-003,Example Customer,012345678,"
].join("\n");

const workbook = await Workbook.fromCSV(csvText, { sheetName: "Customers" });

await workbook.inspect({
  kind: "table",
  range: "Customers!A1:D4",
  include: "values",
  tableMaxRows: 4,
  tableMaxCols: 4
});

await fs.mkdir(path.dirname(outputPath), { recursive: true });
const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(outputPath);

console.log(outputPath);
