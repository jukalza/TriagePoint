import fs from "fs";

export function saveRawData(cveId, data) {

    const filePath = `data/raw/${cveId}.json`;

    fs.writeFileSync(
        filePath,
        JSON.stringify(data, null, 2)
    );
}

export function saveProcessedData(cveId, data) {

    const filePath = `data/processed/${cveId}.json`;

    fs.writeFileSync(
        filePath,
        JSON.stringify(data, null, 2)
    );
}