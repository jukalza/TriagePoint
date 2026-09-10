import express from "express";
import { fetchCveFromNvd, fetchMultipleCvesFromNvd } from "../services/nvdService.js";
import { transformNvdResponse, transformMultipleNvdResponses } from "../services/nvdTransformer.js";
import { saveRawData, saveProcessedData } from "../services/fileService.js";
import { 
    saveVulnerability, 
    getAllVulnerabilities, 
    updateVulnerabilityEpss, 
    getVulnerabilityByCveId, 
    getRecentVulnerabilities, 
    getVulnerabilitySummary,
    updateVulnerabilityKev,
    getCveIdsWithoutEpss,
    getCveIdsWithoutKev,
    improveVulnerability,
    syncVulnerabilityData,
    recalculateAllPriorities
} from "../services/vulnerabilityService.js";
import { fetchEpssForCve, fetchEpssForMultipleCves} from "../services/epssService.js";
import { transformEpssResponse, transformMultipleEpssResponses } from "../services/epssTransformer.js";
import { raw } from "mysql2";
import { fetchKev } from "../services/kevServices.js";
import { findKevForCve } from "../services/kevTransformer.js";

const router = express.Router();

router.get("/", (req, res) => {
    res.json({
        message: "Add a CVE ID to the URL",
        example: "/api/nvd/CVE-2026-47323"
    });
});


router.get("/import/multiple", async function(req, res) {
    try {
        let limit = Number(req.query.limit);

        if (!limit) {
            limit = 10;
        }

        if (limit < 1 || limit > 100) {
            return res.status(400).json({
                error: "Limit must be between 1 and 100"
            });
        }

        const startDate = req.query.startDate;
        const endDate = req.query.endDate;

        if (!startDate || !endDate) {
            return res.status(400).json({
                error: "Start date and end date are required"
            });
        }

        const rawData = await fetchMultipleCvesFromNvd(
            limit,
            startDate,
            endDate
        );

        const vulnerabilities = transformMultipleNvdResponses(rawData);

        for (const vulnerability of vulnerabilities) {
            await saveVulnerability(vulnerability);
        }

        res.json({
            imported: vulnerabilities.length,
            vulnerabilities: vulnerabilities
        });
    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
});

router.get("/test", function(req, res) {
    res.json({
        message: "NVD routes are working"
    });
});


router.get("/database/all", async function (req, res) {

    try {

        const severity = req.query.severity;
        const minScore = req.query.minScore;
        const search = req.query.search;
        const minEpss = req.query.minEpss;
        const kev = req.query.kev;
        const priority = req.query.priority;
        const sort = req.query.sort;

        const page = req.query.page;
        const limit = req.query.limit;

        const vulnerabilities = await getAllVulnerabilities(severity, minScore, search, minEpss, kev, priority, sort, page, limit);

        res.json(vulnerabilities);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }
    
});

router.get("/epss/:cveId", async (req,res) => {
    try {

        const cveId = req.params.cveId;

        const rawData = await fetchEpssForCve(cveId);

        const epssData = transformEpssResponse(rawData);

        if (!epssData) {
            return res.status(404).json({
                error: "EPSS data not found"
            });
        }

        await updateVulnerabilityEpss(epssData);

        res.json(epssData);

    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
});

router.get("/search/:cveId", async function(req,res) {
    try {

        const cveId = req.params.cveId.toUpperCase();

        //check MySql first
        let vulnerability = await getVulnerabilityByCveId(cveId);

        //if found return it
        if (vulnerability) {
            return res.json({
                source: "database",
                vulnerability: vulnerability
            });
        }

        // if not, fetch from NVD
        const rawData = await fetchCveFromNvd(cveId);

        const transformed = transformNvdResponse(rawData);

        if (!transformed) {
            return res.status(404).json({
                error: "CVE not found"
            });
        }

        // save new CVE
        await saveVulnerability(transformed);

        await improveVulnerability(cveId);

        const savedVulnerability = await getVulnerabilityByCveId(cveId);

        return res.json({
            source: "nvd",
            vulnerability: savedVulnerability
        });

    } catch {
        res.status(500).json({
            error: error.message
        })
    }
});

router.get("/database/recent", async function (req,res) {
    try {
        let limit = Number(req.query.limit);

        if (!limit) {
            limit = 20;
        }

        const vulnerabilities = await getRecentVulnerabilities(limit);

        if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
            return res.status(400).json({
                error: "Limit must be a whole number between 1 and 100"
            });
        }

        res.json(vulnerabilities);
    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
});

router.get("/database/summary", async function (req, res) {
    try {
        const summary = await getVulnerabilitySummary();

        res.json(summary);
    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
})

router.get("/kev/:cveId", async function(req, res) {

    try {

        const cveId = req.params.cveId.toUpperCase();

        const rawData = await fetchKev();

        const kevData = findKevForCve(
            rawData,
            cveId
        );

        // CVE is not in KEV
        if (!kevData) {

            const notKevData = {
                cveId: cveId,
                isKev: false,
                kevDateAdded: null
            };

            await updateVulnerabilityKev(notKevData);

            return res.json(notKevData);
        }

        // CVE is in KEV
        await updateVulnerabilityKev(kevData);

        res.json(kevData);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

});

router.get("/epss/update/batch", async function(req, res) {

    try {

        let limit = Number(req.query.limit);

        if (!limit) {
            limit = 20;
        }

        const rows =
            await getCveIdsWithoutEpss(limit);

        const cveIds = [];

        for (const row of rows) {
            cveIds.push(row.cve_id);
        }

        if (cveIds.length === 0) {
            return res.json({
                message: "No vulnerabilities need EPSS data"
            });
        }

        const rawData =
            await fetchEpssForMultipleCves(cveIds);

        const epssResults =
            transformMultipleEpssResponses(rawData);

        for (const epssData of epssResults) {
            await updateVulnerabilityEpss(epssData);
        }

        res.json({
            updated: epssResults.length
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });
    }
});

router.get("/kev/update/batch", async function(req, res) {

    try {

        let limit = Number(req.query.limit);

        if (!limit) {
            limit = 20;
        }

        const rows =
            await getCveIdsWithoutKev(limit);

        const rawKevData =
            await fetchKev();

        let updated = 0;

        for (const row of rows) {

            const cveId = row.cve_id;

            const kevData =
                findKevForCve(rawKevData, cveId);

            if (kevData) {

                await updateVulnerabilityKev(kevData);

            } else {

                await updateVulnerabilityKev({
                    cveId: cveId,
                    isKev: false,
                    kevDateAdded: null
                });

            }

            updated++;
        }

        res.json({
            updated: updated
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

});

router.post("/sync", async function(req, res) {

    try {

        const limit = 100;

        // End date = now
        const endDate = new Date();

        // Start date = 7 days ago
        const startDate = new Date();

        startDate.setDate(
            startDate.getDate() - 3
        );

        const result =
            await syncVulnerabilityData(
                limit,
                startDate.toISOString(),
                endDate.toISOString()
            );

        res.json({
            message: "Vulnerability data sync completed",
            nvdProcessed: result.nvdProcessed,
            epssUpdated: result.epssUpdated,
            kevMatches: result.kevMatches
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: error.message
        });

    }

});

router.post("/priority/recalculate", async function(req, res) {

    try {

        const updated =
            await recalculateAllPriorities();

        res.json({
            message: "Priorities recalculated",
            updated: updated
        });

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }

});

router.get("/:cveId", async (req,res) => {
    try {

        const cveId = req.params.cveId;

        const rawData = await fetchCveFromNvd(req.params.cveId);

        const vulnerability = transformNvdResponse(rawData);

        if (!vulnerability) {
            return res.status(404).json({
                error: "CVE not found"
            });
        }

        saveRawData(vulnerability.cveId, rawData);

        saveProcessedData(vulnerability.cveId, vulnerability);

        await saveVulnerability(vulnerability);

        res.json(vulnerability);

    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
});

export default router;
