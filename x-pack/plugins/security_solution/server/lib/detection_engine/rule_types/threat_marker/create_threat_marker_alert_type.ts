/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// TODO remove this
/* eslint-disable @typescript-eslint/no-explicit-any */

import { validateNonExact } from '@kbn/securitysolution-io-ts-utils';
import { THREAT_MARKER_RULE_TYPE_ID } from '@kbn/securitysolution-rules';
import { SERVER_APP_ID } from '../../../../../common/constants';

import type { ThreatMarkerRuleParams } from '../../rule_schema';
import { threatMarkerRuleParams } from '../../rule_schema';
import type { CreateRuleOptions, SecurityAlertType } from '../types';
import { validateIndexPatterns } from '../utils';

import { createSearchAfterReturnType, getUnprocessedExceptionsWarnings } from '../../signals/utils';
import { scan } from './scan';

export const createThreatMarkerAlertType = (
  _createOptions: CreateRuleOptions
): SecurityAlertType<ThreatMarkerRuleParams, {}, {}, 'default'> => {
  return {
    id: THREAT_MARKER_RULE_TYPE_ID,
    name: 'Threat Marker',
    validate: {
      params: {
        validate: (object: unknown) => {
          const [validated, errors] = validateNonExact(object, threatMarkerRuleParams);
          if (errors != null) {
            throw new Error(errors);
          }
          if (validated == null) {
            throw new Error('Validation of rule params failed');
          }
          return validated;
        },
        /**
         * validate rule params when rule is bulk edited (update and created in future as well)
         * returned params can be modified (useful in case of version increment)
         * @param mutatedRuleParams
         * @returns mutatedRuleParams
         */
        validateMutatedParams: (mutatedRuleParams) => {
          validateIndexPatterns(mutatedRuleParams.index);

          return mutatedRuleParams;
        },
      },
    },
    actionGroups: [
      {
        id: 'default',
        name: 'Default',
      },
    ],
    defaultActionGroupId: 'default',
    actionVariables: {
      context: [{ name: 'server', description: 'the server' }],
    },
    minimumLicenseRequired: 'basic',
    isExportable: false,
    producer: SERVER_APP_ID,
    async executor(execOptions) {
      const {
        runOpts: {
          ruleExecutionLogger,
          bulkCreate,
          completeRule,
          tuple,
          mergeStrategy,
          inputIndex,
          runtimeMappings,
          primaryTimestamp,
          secondaryTimestamp,
          aggregatableTimestampField,
          exceptionFilter,
          unprocessedExceptions,
          alertTimestampOverride,
        },
        services,
        params,
        spaceId,
        state,
      } = execOptions;

      ruleExecutionLogger.info('starting Indicator Marker rule');
      const esClient = services.scopedClusterClient.asCurrentUser;

      // TODO use config parameters
      const EVENTS_INDEX = ['filebeat-*'];
      const THREATS_INDEX = ['logs-ti_*'];

      try {
        // matcher POC
        await scan(
          { client: esClient as any, log: ruleExecutionLogger.info },
          { threatIndex: THREATS_INDEX, eventsIndex: EVENTS_INDEX, concurrency: 8, verbose: false }
        );
      } catch (error: unknown) {
        if (error instanceof Error) {
          ruleExecutionLogger.error(error.message);
        }
      }
      // end matcher POC

      const result = createSearchAfterReturnType();
      const exceptionsWarning = getUnprocessedExceptionsWarnings(unprocessedExceptions);
      if (exceptionsWarning) {
        result.warningMessages.push(exceptionsWarning);
      }

      return { ...result, state };
    },
  };
};
