const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function sleep(milliseconds) {
    return new Promise(function(resolve) {
        setTimeout(resolve, milliseconds);
    });
}

export async function fetchCveFromNvd(cveId) {

    if (!cveId) {
        throw new Error("A CVE ID must be provided")
    }

    const normalisedCveID = cveId.trim().toUpperCase();

    const url = new URL(NVD_BASE_URL);
    url.searchParams.set('cveId', normalisedCveID);

    const headers = {
        Accept: 'application/json'
    };

    if (process.env.NVD_API_KEY) {
        headers.apiKey = process.env.NVD_API_KEY;
    }

    const response = await fetch(url, {
        method: "GET",
        headers
    });

    if (!response.ok) {
        const responseText = await response.text();

        throw new Error(
            `NVD request failed with status ${response.status}: ${responseText}`
        );
    }
    const data = await response.json();

    return data;
}


export async function fetchMultipleCvesFromNvd(
    limit,
    startDate,
    endDate
) {
    let allVulnerabilities = [];
    let startIndex = 0;
    let totalResults = 0;

    do {

        let url =
            "https://services.nvd.nist.gov/rest/json/cves/2.0" +
            "?resultsPerPage=" + limit +
            "&startIndex=" + startIndex;

        if (startDate && endDate) {
            url +=
                "&pubStartDate=" +
                encodeURIComponent(startDate) +
                "&pubEndDate=" +
                encodeURIComponent(endDate);
        }

        console.log(
            "Fetching NVD page starting at:",
            startIndex
        );

        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(
                "NVD request failed with status " +
                response.status
            );
        }

        const data = await response.json();

        if (data.vulnerabilities) {

            for (const vulnerability of data.vulnerabilities) {
                allVulnerabilities.push(vulnerability);
            }

        }

        totalResults = data.totalResults;

        startIndex += data.resultsPerPage;

        // Wait before requesting another page
        if (startIndex < totalResults) {

            console.log(
                "Waiting before next NVD request..."
            );

            await sleep(6000);
        }

    } while (startIndex < totalResults);

    return {
        vulnerabilities: allVulnerabilities
    };
}