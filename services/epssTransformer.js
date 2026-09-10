export function transformEpssResponse(epssResponse) {

    if (!epssResponse.data || epssResponse.data.length === 0) {
        return null;
    }

    const epssData = epssResponse.data[0];

    return {
        cveId: epssData.cve,
        epssScore: Number(epssData.epss),
        epssPercentile: Number(epssData.percentile),
        epssDate: epssData.date
    };
}

export function transformMultipleEpssResponses(epssResponse) {

    const results = [];

    if (!epssResponse.data) {
        return results;
    }

    for (const item of epssResponse.data) {

        results.push({
            cveId: item.cve,
            epssScore: Number(item.epss),
            epssPercentile: Number(item.percentile),
            epssDate: item.date
        });

    }

    return results;
}