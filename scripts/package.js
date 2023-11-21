/**
 * Build the package.json for the actual publishing
 */
// eslint-disable-next-line
import fs from "fs";
import path from "path";
import * as url from 'url';
const __filename = url.fileURLToPath(import.meta.url);
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

// eslint-disable-next-line
import rootPackage from "../package.json" assert { type: "json" };

// Don't keep scripts
delete rootPackage["scripts"];

// Don't keep dev dependencies
delete rootPackage["devDependencies"];

// Setup the main and types correctly
rootPackage["main"] = "index.js";
rootPackage["module"] = "./index.js";
rootPackage["types"] = "index.d.ts";

// Write it out
fs.writeFileSync(`${path.join(__dirname, "../dist", "package.json")}`, JSON.stringify(rootPackage, null, 2), (err) => {
  if (err) throw new Error(err);
});
