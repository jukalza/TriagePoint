export async function fetchKev() {

    const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(
            "KEV request failed with status " + response.status
        );
    }

    const data = await response.json();

    return data;

}