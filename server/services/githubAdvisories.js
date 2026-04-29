import axios from 'axios';
import { insertOrUpdateCve, updateFeedStatus, getSeverity } from '../db/database.js';

const GITHUB_GRAPHQL = 'https://api.github.com/graphql';

const GHSA_QUERY = `
query($cursor: String) {
  securityAdvisories(first: 100, after: $cursor, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      cveId
      summary
      description
      severity
      publishedAt
      updatedAt
      vulnerabilities(first: 5) {
        nodes {
          package {
            name
            ecosystem
          }
          vulnerableVersionRange
        }
      }
    }
  }
}
`;

export async function fetchGithubAdvisories(token) {
    if (!token) {
        console.log('[GitHub] No token provided, using public API');
        return fetchGithubAdvisoriesPublic();
    }

    try {
        let cursor = null;
        let totalCount = 0;
        const maxPages = 5;

        for (let page = 0; page < maxPages; page++) {
            const response = await axios.post(
                GITHUB_GRAPHQL,
                { query: GHSA_QUERY, variables: { cursor } },
                {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: 30000
                }
            );

            const data = response.data?.data?.securityAdvisories;
            if (!data) break;

            for (const adv of data.nodes) {
                const cveId = adv.cveId || adv.ghsaId;
                if (!cveId) continue;

                let cvssScore = 0;
                if (adv.severity === 'CRITICAL') cvssScore = 9.5;
                else if (adv.severity === 'HIGH') cvssScore = 8.0;
                else if (adv.severity === 'MEDIUM') cvssScore = 5.5;
                else cvssScore = 3.0;

                insertOrUpdateCve({
                    id: cveId,
                    source: 'github',
                    description: (adv.summary || adv.description || '').substring(0, 5000),
                    cvss_score: cvssScore,
                    cvss_vector: null,
                    severity: getSeverity(cvssScore),
                    published_at: adv.publishedAt
                });
                totalCount++;
            }

            if (!data.pageInfo.hasNextPage) break;
            cursor = data.pageInfo.endCursor;
        }

        await updateFeedStatus('github', 'success', totalCount);
        console.log(`[GitHub] Fetched ${totalCount} advisories`);
        return totalCount;
    } catch (error) {
        await updateFeedStatus('github', 'error', 0, error.message);
        console.error(`[GitHub] Error: ${error.message}`);
        return fetchGithubAdvisoriesPublic();
    }
}

async function fetchGithubAdvisoriesPublic() {
    try {
        const response = await axios.get(
            'https://api.github.com/advisories?type=reviewed',
            {
                headers: { Accept: 'application/vnd.github+json' },
                timeout: 30000
            }
        );

        const advisories = response.data || [];
        let count = 0;

        for (const adv of advisories) {
            const cveId = adv.cve_id || adv.ghsa_id;
            if (!cveId) continue;

            let cvssScore = adv.cvss?.score || 5.0;

            insertOrUpdateCve({
                id: cveId,
                source: 'github',
                description: (adv.description || '').substring(0, 5000),
                cvss_score: cvssScore,
                cvss_vector: adv.cvss?.vector_string || null,
                severity: getSeverity(cvssScore),
                published_at: adv.published_at
            });
            count++;
        }

        await updateFeedStatus('github', 'success', count);
        console.log(`[GitHub Public] Fetched ${count} advisories`);
        return count;
    } catch (error) {
        await updateFeedStatus('github', 'error', 0, error.message);
        console.error(`[GitHub Public] Error: ${error.message}`);
        throw error;
    }
}

export default { fetchGithubAdvisories };
