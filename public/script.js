let currentPage = 1;
let totalPages = 1;

document.getElementById("previousPageButton").addEventListener("click", function() {
    if (currentPage > 1) {
        currentPage--;
        loadVulnerabilities();
    }
});

document.getElementById("nextPageButton").addEventListener("click", function() {
    if (currentPage < totalPages) {
        currentPage++;
        loadVulnerabilities();
    }
});

async function loadVulnerabilities() {
    
    const loader = document.getElementById("vulnerabilityLoader");

    loader.classList.remove("hidden");

    try {

        const search = document.getElementById("searchInput").value;
        const severity = document.getElementById("severityFilter").value;
        const minScore = document.getElementById("minScoreInput").value;
        const minEpss = document.getElementById("minEpssInput").value;
        const kev = document.getElementById("kevFilter").value;
        const priority = document.getElementById("priorityFilter").value;
        const sort = document.getElementById("sortFilter").value;


        const params = new URLSearchParams();

        // if the user enters something that looks like a CVE ID
        if (search.toUpperCase().startsWith("CVE-")) {
            const response = await fetch(
                "/api/nvd/search/" + search
            );

            const result = await response.json();

            if (!response.ok) {
                alert(result.error || "CVE not found");
                return;
            }

            displayVulnerabilities([
                result.vulnerability
            ]);

            showVulnerabilityDetails(
                result.vulnerability
            );

            return;
        }


        // otherwise use normal database filtering
        if (search) {
            params.append("search", search);
        }

        if (severity) {
            params.append("severity", severity);
        }

        if (minScore) {
            params.append("minScore", minScore);
        }

        if (minEpss) {

            const minEpssDecimal = Number(minEpss) / 100;
            params.append("minEpss", minEpssDecimal);
        }

        if (kev) {
            params.append("kev", kev);
        }

        if (priority) {
            params.append("priority", priority);
        }

        if (sort) {
            params.append("sort", sort);
        }

        params.append("page", currentPage);
        params.append("limit", 25);

        const response = await fetch(
            "/api/nvd/database/all?" + params.toString()
        );

        const data = await response.json();

        displayVulnerabilities(data.vulnerabilities);

        totalPages = data.totalPages;

        document.getElementById("pageInfo").textContent = "Page " + data.page + " of " + data.totalPages;

        document.getElementById("previousPageButton").disabled = data.page <=1;

        document.getElementById("nextPageButton").disabled = data.page >= data.totalPages;

    } catch (error) {

        console.log("Error loading vulnerabilities");
        console.log(error);

    } finally {
        loader.classList.add("hidden");
    }

}

async function displayVulnerabilities(vulnerabilities) {

    const table = document.getElementById("vulnerabilityTable");

    table.innerHTML = "";

    for (const vulnerability of vulnerabilities) {

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>
                <button class="cve-link" data-id="${vulnerability.id}">
                    ${vulnerability.cve_id}
                </button>
            </td>
            <td>
                ${
                    vulnerability.cvss_severity
                        ? `
                            <span class="label severity-${vulnerability.cvss_severity.toLowerCase()}">
                                ${vulnerability.cvss_severity}
                            </span>
                        `
                        : `<span class="pending">Not available</span>`
                }
            </td>
            <td>${vulnerability.cvss_score}</td>
            <td>
                ${vulnerability.epss_score !== null ? formatEpss(vulnerability.epss_score): "Not available"}
            </td>
            <td>
                ${vulnerability.is_kev 
                    ? `<span class="kev-label">KEV</span>`  
                    : `<span class="not-kev">No</span>`
                }
            </td>
             <td>
                ${vulnerability.priority_score != null 
                    ? vulnerability.priority_score 
                    : vulnerability.epss_score == null
                        ? "Pending EPSS": "Not available"
                }
            </td>
            <td>
                ${vulnerability.priority_level != null 
                    ? `
                        <span class="label priority-${vulnerability.priority_level.toLowerCase()}">
                            ${vulnerability.priority_level}
                        </span>
                    `
                    : vulnerability.epss_score == null
                        ? `<span class="pending">Pending EPSS</span>`
                        : `<span class="pending">Not available</span>`
                }
            </td>
            <td>${formatDate(vulnerability.published_date)}</td>
            <td class="description-cell">
                ${shortenDescription(vulnerability.description)}
            </td>
        `;

        const button = row.querySelector(".cve-link");

        button.addEventListener("click", function() {
            showVulnerabilityDetails(vulnerability);
        });

        table.appendChild(row);

    }
    
}

async function showVulnerabilityDetails(vulnerability) {

    const details = document.getElementById("vulnerabilityDetails");

    details.innerHTML = `
        <div class="details-header">
            <h2>${vulnerability.cve_id}</h2>
        </div>

        <div class="details-section">
            <h3>Severity Information</h3>

            <div class=detail-row>
                <span class="detail-label">Severity</span>
                <span>
                    ${
                        vulnerability.cvss_severity
                            ? `
                                <span class="label severity-${vulnerability.cvss_severity.toLowerCase()}">
                                ${vulnerability.cvss_severity}
                                </span>
                            `
                            : "Not available"
                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">CVSS Score</span>
                <span>
                    ${
                        vulnerability.cvss_score != null
                            ? vulnerability.cvss_score
                            : "Not available"
                    }
                </span>
            </div> 

            <div class="detail-row">
                <span class="detail-label">Published</span>
                <span>${formatDate(vulnerability.published_date)}</span>
            </div>
        
        </div>

        <div class="details-section">
            <h3>Exploitation</h3>

            <div class="detail-row">
                <span class="detail-label">EPSS Score</span>
                <span>
                    ${
                        vulnerability.epss_score !== null
                            ? formatEpss(vulnerability.epss_score)
                            : "Not available"
                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">EPSS Percentile</span>
                <span>
                    ${
                        vulnerability.epss_percentile !== null
                            ? formatPercentile(vulnerability.epss_percentile)
                            : "Not available"
                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">EPSS Date</span>
                <span>
                    ${
                        formatDate(vulnerability.epss_date) || "Not available"
                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">Known Exploitation</span>
                <span>
                    ${
                        vulnerability.is_kev
                            ? `<span class="kev-label">KEV</span>`
                            : "No"

                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">KEV Date Added</span>
                <span>
                    ${vulnerability.kev_date_added 
                        ? formatDate(vulnerability.kev_date_added) 
                        : "Not applicable"
                    }
                </span>
            </div>

        </div>

        <div class="details-section priority-section">
            <h3>TriagePoint Priority</h3>

            <div class="detail-row">
                <span class="detail-label">Priority Score</span>
                <span>
                    ${
                        vulnerability.priority_score != null
                            ? Number(vulnerability.priority_score).toFixed(2) + " / 100"
                            : vulnerability.epss_score == null
                                ? "Pending EPSS"
                                : "Not available"
                    }
                </span>
            </div>

            <div class="detail-row">
                <span class="detail-label">Priority Level</span>
                <span>
                    ${
                        vulnerability.priority_level
                            ? `
                                <span class="label priority-${vulnerability.priority_level.toLowerCase()}">
                                    ${vulnerability.priority_level}
                                </span>
                            `
                            : vulnerability.epss_score == null
                                ? `<span class="pending">Pending EPSS</span>`
                                : "Not available"
                    }
                </span>
            </div>
            
        </div>

        <div class="details-section description-section">
            <h3>Description</h3>

            <p class="details-description"> 
                ${
                    vulnerability.description
                        ? vulnerability.description
                        : "No description available"
                }
            </p>
        </div>

    `;
    
}

async function loadRecentVulnerabilities() {

    try {
        const response = await fetch(
            "/api/nvd/database/recent?limit=20"
        );

        const vulnerabilities = await response.json();

        displayVulnerabilities(vulnerabilities);
    } catch (error) {
        console.log("Error loading recent vulnerabilities: ");
        console.log(error);
    }
    
}

async function loadSummary() {

    try {

        const response = await fetch (
            "/api/nvd/database/summary"
        );

        const summary = await response.json();

        document.getElementById("totalCount").textContent =
            summary.total;

        document.getElementById("criticalCount").textContent =
            summary.critical;

        document.getElementById("highCount").textContent =
            summary.high;
        
        document.getElementById("kevCount").textContent =
            summary.kev;

        document.getElementById("highEpssCount").textContent =
            summary.high_epss;

    } catch (error) {
        console.log("Error loading summary");
        console.log(error);
    }
    
}

async function syncVulnerabilityData() {

    const button = document.getElementById("syncButton");

    const status = document.getElementById("syncStatus");

    const loader = document.getElementById("syncLoader");
    

    button.disabled = true;
    loader.classList.remove("hidden");
    status.textContent = "Syncing...";

    try {

        const response = await fetch(
            "/api/nvd/sync?limit=20",
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        status.textContent =
            "Sync complete: " +
            data.nvdProcessed +
            " vulnerabilities processed";

        // Refresh dashboard
        await loadRecentVulnerabilities();
        await loadSummary();

    } catch (error) {

        console.error(error);

        status.textContent =
            "Sync failed: " + error.message;

    } finally {

        button.disabled = false;
        loader.classList.add("hidden");

    }
}

function shortenDescription(description) {

    if (!description) {
        return "Not available";
    }

    if (description.length > 100) {
        return description.substring(0, 100) + "...";
    }

    return description;

}

function formatDate(dateValue) {

    if (!dateValue) {
        return "Not available";
    }

    const date = new Date(dateValue);

    return date.toLocaleDateString();
}


function formatEpss(epssScore) {

    if (epssScore == null) {
        return "Not available";
    }

    return (Number(epssScore) * 100).toFixed(2) + "%";

}

function formatPercentile(percentile) {

    if (percentile == null) {
        return "Not available";
    }

    return (
        Number(percentile) * 100
    ).toFixed(2) + "%";

}

document.getElementById("filterButton").addEventListener("click", function() {
    currentPage = 1;
    loadVulnerabilities();
});
document.getElementById("syncButton").addEventListener("click", syncVulnerabilityData);
document.getElementById("sortFilter").addEventListener("change" , function() {
    currentPage = 1;
    loadVulnerabilities();
});

loadVulnerabilities();
loadSummary();