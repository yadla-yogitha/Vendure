import { loadEnvVariables } from './utils/env-loader';

// Load environment variables at the very start
loadEnvVariables();

import { bootstrap, runMigrations } from '@vendure/core';
import { config } from './vendure-config';

runMigrations(config)
    .then(() => bootstrap(config))
    .catch(err => {
        console.log(err);
    });
