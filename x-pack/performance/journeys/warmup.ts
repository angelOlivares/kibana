/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SearchTotalHits } from '@elastic/elasticsearch/lib/api/types';
import { Journey } from '@kbn/journeys';
import expect from '@kbn/expect';
import { subj } from '@kbn/test-subj-selector';
import { waitForVisualizations } from '../utils';

const WARMUP_INDEX_NAME = 'warmup-index';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const journey = new Journey({
  esArchives: ['x-pack/performance/es_archives/sample_data_ecommerce'],
  kbnArchives: ['x-pack/performance/kbn_archives/ecommerce_tsvb_gauge_only_dashboard'],
})
  .step('Setup warmup index', async ({ esClient }) => {
    await esClient.indices.create({
      index: WARMUP_INDEX_NAME,
      body: {
        mappings: {
          properties: {
            '@timestamp': {
              type: 'date',
            },
            message: {
              type: 'keyword',
            },
            count: {
              type: 'long',
            },
          },
        },
      },
    });

    await esClient.create({
      index: WARMUP_INDEX_NAME,
      body: {
        '@timestamp': '2022-10-07T12:00:00.000Z',
        message: 'Obj 1',
        count: 1,
      },
      id: new Date().toISOString(),
      refresh: true,
    });

    await esClient.create({
      index: WARMUP_INDEX_NAME,
      body: {
        '@timestamp': '2022-11-07T12:00:00.000Z',
        message: 'Obj 2',
        count: 2,
      },
      id: new Date().toISOString(),
      refresh: true,
    });

    await esClient.create({
      index: WARMUP_INDEX_NAME,
      body: {
        '@timestamp': '2022-12-07T12:00:00.000Z',
        message: 'Obj 3',
        count: 3,
      },
      id: new Date().toISOString(),
      refresh: true,
    });
  })

  .step('Run search', async ({ esClient }) => {
    const searchResponse = await esClient.search({
      index: WARMUP_INDEX_NAME,
      size: 3,
    });

    expect((searchResponse.hits.total as SearchTotalHits).value).to.be(3);

    const asyncSearchResponse = await esClient.asyncSearch.submit({
      wait_for_completion_timeout: '10s',
      keep_on_completion: true,
      index: WARMUP_INDEX_NAME,
      aggs: {
        the_date: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1d',
          },
        },
      },
    });

    expect((asyncSearchResponse.response.hits.total as SearchTotalHits).value).to.be(3);
    expect(asyncSearchResponse.response.aggregations?.the_date).not.to.be(undefined);
  })
  .step('Open Kibana', async ({ page, kbnUrl }) => {
    await page.goto(kbnUrl.get(`/app/home`));
    await page.waitForSelector('.kbnAppWrapper');
  })
  .step('Go to Dashboards Page', async ({ page, kbnUrl }) => {
    await page.goto(kbnUrl.get(`/app/dashboards`));
    await page.waitForSelector('#dashboardListingHeading');
    await sleep(1000);
  })
  .step('Go to Ecommerce Dashboard with TSVB Gauge only', async ({ page, log }) => {
    await page.click(subj('dashboardListingTitleLink-[eCommerce]-TSVB-Gauge-Only-Dashboard'));
    await waitForVisualizations(page, log, 1);
  })
  .step('Cleanup', async ({ esClient }) => {
    const resp = await esClient.indices.delete({
      index: WARMUP_INDEX_NAME,
    });
    expect(resp.acknowledged).to.be(true);
  });
