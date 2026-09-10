export function transformNvdResponse(nvdResponse) {
    const vulnerabilities = nvdResponse.vulnerabilities;

    if (!vulnerabilities || vulnerabilities.length === 0) {
        return null;
    }

    const cve = vulnerabilities[0].cve;

    let englishDescription = null;

    if (cve.descriptions) {
        englishDescription = cve.descriptions.find(function(description){
            return description.lang === "en";
        });
    }


    let cvssMetric = null;

    if (cve.metrics) {

        if (cve.metrics.cvssMetricV40) {
            cvssMetric = cve.metrics.cvssMetricV40[0];
        } else if (cve.metrics.cvssMetricV31) {
            cvssMetric = cve.metrics.cvssMetricV31[0];
        } else if (cve.metrics.cvssMetricV30) {
            cvssMetric = cve.metrics.cvssMetricV30[0];
        } else if (cve.metrics.cvssMetricV2) {
            cvssMetric = cve.metrics.cvssMetricV2[0];
        }
    }

    let description = null;
    let cvssVersion = null;
    let cvssScore = null;
    let cvssSeverity = null;
    let cvssVector = null;

    if (englishDescription) {
        description = englishDescription.value;
    }

    if (cvssMetric) {

        if (cvssMetric.cvssData) {
            cvssVersion = cvssMetric.cvssData.version;
            cvssScore = cvssMetric.cvssData.baseScore;
            cvssSeverity = cvssMetric.cvssData.baseSeverity;
            cvssVector = cvssMetric.cvssData.vectorString;
        } 

        // some CVE severities stored here
        if (!cvssSeverity && cvssMetric.baseSeverity) {
            cvssSeverity = cvssMetric.baseSeverity;
        }
    }

    return {
        cveId: cve.id,
        description: description,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        cvssVersion: cvssVersion,
        cvssScore: cvssScore,
        cvssSeverity: cvssSeverity,
        cvssVector: cvssVector
    };
}


export function transformMultipleNvdResponses(nvdResponse) {
    const transformedVulnerabilities = [];

    const vulnerabilities = nvdResponse.vulnerabilities;

    if (!vulnerabilities) {
        return transformedVulnerabilities;
    }

    for (const vulnerabilityEntry of vulnerabilities) {
        const singleResponse = {
            vulnerabilities: [vulnerabilityEntry]
        };


        const transformedVulnerability = transformNvdResponse(singleResponse);

        if (transformedVulnerability) {
            transformedVulnerabilities.push(transformedVulnerability);
        }

    }

    return transformedVulnerabilities;
}