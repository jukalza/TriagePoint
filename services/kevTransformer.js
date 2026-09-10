export function findKevForCve(kevData, cveId) {

    if (!kevData.vulnerabilities) {
        return null;
    }

    const match = kevData.vulnerabilities.find(function(vulnerability) {

        return vulnerability.cveID === cveId;

    });

    if (!match) {
        return null;
    }

    return {
        cveId: match.cveID,
        isKev: true,
        kevDateAdded: match.dateAdded
    };

}
