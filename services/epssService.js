export async function fetchEpssForCve(cveId) {

    const url = "https://api.first.org/data/v1/epss?cve=" + cveId;

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(
            "EPSS request failed with status " + response.status 
        );
    }

    const data = await response.json();

    return data;
    
}

export async function fetchEpssForMultipleCves(cveIds) {

    const joinedIds = cveIds.join(",");

    const url = "https://api.first.org/data/v1/epss?cve=" + joinedIds;

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(
            "EPSS request failed with status " + response.status
        );
    }

    const data = await response.json();

    return data;

}