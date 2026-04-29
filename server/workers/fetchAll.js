import { getFeedConfig } from '../config/env.js';
import { initializeDb } from '../db/database.js';
import { fetchAllFeeds } from './scheduler.js';

await initializeDb();

try {
    const results = await fetchAllFeeds(getFeedConfig());
    console.log(JSON.stringify(results.summary || results, null, 2));
    process.exit(0);
} catch (error) {
    console.error(error.message);
    process.exit(1);
}
