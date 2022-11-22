/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

import {
  EuiButton,
  EuiButtonEmpty,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiIcon,
  EuiPopoverFooter,
  EuiPopoverTitle,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { FormattedMessage } from '@kbn/i18n-react';
import {
  BooleanRelation,
  buildCombinedFilter,
  buildCustomFilter,
  buildEmptyFilter,
  cleanFilter,
  FieldFilter,
  Filter,
  getFilterParams,
  isCombinedFilter,
} from '@kbn/es-query';
import React, { Component } from 'react';
import { XJsonLang } from '@kbn/monaco';
import { DataView } from '@kbn/data-views-plugin/common';
import { getIndexPatternFromFilter } from '@kbn/data-plugin/public';
import { CodeEditor } from '@kbn/kibana-react-plugin/public';
import { cx } from '@emotion/css';
import { GenericComboBox } from './generic_combo_box';
import {
  getFieldFromFilter,
  getOperatorFromFilter,
  isFilterValid,
} from './lib/filter_editor_utils';
import { FiltersBuilder } from '../../filters_builder';
import { FilterBadgeGroup } from '../../filter_badge/filter_badge_group';
import { flattenFilters } from './lib/helpers';
import { filterBadgeStyle, filtersBuilderMaxHeight } from './filter_editor.styles';
import { strings } from './strings';

export interface FilterEditorProps {
  filter: Filter;
  indexPatterns: DataView[];
  onSubmit: (filter: Filter) => void;
  onCancel: () => void;
  timeRangeForSuggestionsOverride?: boolean;
  mode?: 'edit' | 'add';
}

interface State {
  selectedDataView?: DataView;
  customLabel: string | null;
  queryDsl: string;
  isCustomEditorOpen: boolean;
  localFilter: Filter;
}

export class FilterEditor extends Component<FilterEditorProps, State> {
  constructor(props: FilterEditorProps) {
    super(props);
    const dataView = this.getIndexPatternFromFilter();
    this.state = {
      selectedDataView: dataView,
      customLabel: props.filter.meta.alias || '',
      queryDsl: this.parseFilterToQueryDsl(props.filter),
      isCustomEditorOpen: this.isUnknownFilterType(),
      localFilter: dataView ? props.filter : buildEmptyFilter(false),
    };
  }

  private parseFilterToQueryDsl(filter: Filter) {
    return JSON.stringify(cleanFilter(filter), null, 2);
  }

  public render() {
    const { localFilter } = this.state;
    const shouldDisableToggle = isCombinedFilter(localFilter);

    return (
      <div>
        <EuiPopoverTitle paddingSize="s">
          <EuiFlexGroup alignItems="baseline" responsive={false}>
            <EuiFlexItem>
              {this.props.mode === 'add' ? strings.getPanelTitleAdd() : strings.getPanelTitleEdit()}
            </EuiFlexItem>
            <EuiFlexItem grow={false} className="filterEditor__hiddenItem" />
            <EuiFlexItem grow={false}>
              <EuiToolTip
                position="top"
                content={shouldDisableToggle ? strings.getDisableToggleModeTooltip() : null}
                display="block"
              >
                <EuiButtonEmpty
                  size="xs"
                  data-test-subj="editQueryDSL"
                  disabled={shouldDisableToggle}
                  onClick={this.toggleCustomEditor}
                >
                  {this.state.isCustomEditorOpen ? (
                    <FormattedMessage
                      id="unifiedSearch.filter.filterEditor.editFilterValuesButtonLabel"
                      defaultMessage="Edit filter values"
                    />
                  ) : (
                    <FormattedMessage
                      id="unifiedSearch.filter.filterEditor.editQueryDslButtonLabel"
                      defaultMessage="Edit as Query DSL"
                    />
                  )}
                </EuiButtonEmpty>
              </EuiToolTip>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPopoverTitle>

        <EuiForm>
          <div className="globalFilterItem__editorForm">
            {this.renderIndexPatternInput()}

            {this.state.isCustomEditorOpen
              ? this.renderCustomEditor()
              : this.renderFiltersBuilderEditor()}

            <EuiSpacer size="l" />
            <EuiFormRow label={strings.getCustomLabel()} fullWidth>
              <EuiFieldText
                value={`${this.state.customLabel}`}
                onChange={this.onCustomLabelChange}
                placeholder={strings.getAddCustomLabel()}
                fullWidth
              />
            </EuiFormRow>
          </div>

          <EuiPopoverFooter paddingSize="s">
            {/* Adding isolation here fixes this bug https://github.com/elastic/kibana/issues/142211 */}
            <EuiFlexGroup
              direction="rowReverse"
              alignItems="center"
              style={{ isolation: 'isolate' }}
              responsive={false}
            >
              <EuiFlexItem grow={false}>
                <EuiButton
                  fill
                  onClick={this.onSubmit}
                  isDisabled={!this.isFilterValid()}
                  data-test-subj="saveFilter"
                >
                  {this.props.mode === 'add'
                    ? strings.getAddButtonLabel()
                    : strings.getUpdateButtonLabel()}
                </EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty
                  flush="right"
                  onClick={this.props.onCancel}
                  data-test-subj="cancelSaveFilter"
                >
                  <FormattedMessage
                    id="unifiedSearch.filter.filterEditor.cancelButtonLabel"
                    defaultMessage="Cancel"
                  />
                </EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem />
            </EuiFlexGroup>
          </EuiPopoverFooter>
        </EuiForm>
      </div>
    );
  }

  private renderIndexPatternInput() {
    if (
      this.props.indexPatterns.length <= 1 &&
      this.props.indexPatterns.find(
        (indexPattern) => indexPattern === this.getIndexPatternFromFilter()
      )
    ) {
      /**
       * Don't render the index pattern selector if there's just one \ zero index patterns
       * and if the index pattern the filter was LOADED with is in the indexPatterns list.
       **/

      return '';
    }
    const { selectedDataView } = this.state;
    return (
      <>
        <EuiFormRow fullWidth label={strings.getDataView()}>
          <GenericComboBox
            fullWidth
            placeholder={strings.getSelectDataView()}
            options={this.props.indexPatterns}
            selectedOptions={selectedDataView ? [selectedDataView] : []}
            getLabel={(indexPattern) => indexPattern.getName()}
            onChange={this.onIndexPatternChange}
            singleSelection={{ asPlainText: true }}
            isClearable={false}
            data-test-subj="filterIndexPatternsSelect"
          />
        </EuiFormRow>
        <EuiSpacer size="s" />
      </>
    );
  }

  private renderFiltersBuilderEditor() {
    const { selectedDataView, localFilter } = this.state;
    const flattenedFilters = flattenFilters([localFilter]);

    const shouldShowPreview =
      selectedDataView &&
      (flattenedFilters.length > 1 ||
        (flattenedFilters.length === 1 &&
          isFilterValid(
            selectedDataView,
            getFieldFromFilter(flattenedFilters[0] as FieldFilter, selectedDataView),
            getOperatorFromFilter(flattenedFilters[0]),
            getFilterParams(flattenedFilters[0])
          )));

    return (
      <>
        <div role="region" aria-label="" className={cx(filtersBuilderMaxHeight, 'eui-yScroll')}>
          <EuiToolTip
            position="top"
            content={selectedDataView ? '' : strings.getSelectDataViewToolTip()}
            display="block"
          >
            <FiltersBuilder
              filters={[localFilter]}
              timeRangeForSuggestionsOverride={this.props.timeRangeForSuggestionsOverride}
              dataView={selectedDataView!}
              onChange={this.onLocalFilterChange}
              isDisabled={!selectedDataView}
            />
          </EuiToolTip>
        </div>

        {shouldShowPreview ? (
          <EuiFormRow
            fullWidth
            hasEmptyLabelSpace={true}
            className={filterBadgeStyle}
            label={
              <strong>
                <FormattedMessage
                  id="unifiedSearch.filter.filterBar.preview"
                  defaultMessage="{icon} Preview"
                  values={{
                    icon: <EuiIcon type="inspect" size="s" />,
                  }}
                />
              </strong>
            }
          >
            <EuiText size="xs">
              <FilterBadgeGroup
                filters={[localFilter]}
                dataViews={this.props.indexPatterns}
                booleanRelation={BooleanRelation.AND}
                shouldShowBrackets={false}
              />
            </EuiText>
          </EuiFormRow>
        ) : null}
      </>
    );
  }

  private renderCustomEditor() {
    return (
      <EuiFormRow fullWidth label={strings.getQueryDslLabel()}>
        <CodeEditor
          languageId={XJsonLang.ID}
          width="100%"
          height={'250px'}
          value={this.state.queryDsl}
          onChange={this.onQueryDslChange}
          data-test-subj="customEditorInput"
          aria-label={strings.getQueryDslAriaLabel()}
        />
      </EuiFormRow>
    );
  }

  private toggleCustomEditor = () => {
    const isCustomEditorOpen = !this.state.isCustomEditorOpen;
    this.setState({ isCustomEditorOpen });
  };

  private isUnknownFilterType() {
    const { type } = this.props.filter.meta;
    return !!type && !['phrase', 'phrases', 'range', 'exists', 'combined'].includes(type);
  }

  private getIndexPatternFromFilter() {
    return getIndexPatternFromFilter(this.props.filter, this.props.indexPatterns);
  }

  private isFilterValid() {
    const { isCustomEditorOpen, queryDsl, selectedDataView, localFilter } = this.state;

    if (isCustomEditorOpen) {
      try {
        const queryDslJson = JSON.parse(queryDsl);
        return Object.keys(queryDslJson).length > 0;
      } catch (e) {
        return false;
      }
    }

    if (!selectedDataView) {
      return false;
    }

    return flattenFilters([localFilter]).every((f) =>
      isFilterValid(
        selectedDataView,
        getFieldFromFilter(f as FieldFilter, selectedDataView),
        getOperatorFromFilter(f),
        getFilterParams(f)
      )
    );
  }

  private onIndexPatternChange = ([selectedDataView]: DataView[]) => {
    this.setState({
      selectedDataView,
      localFilter: buildEmptyFilter(false, selectedDataView.id),
    });
  };

  private onCustomLabelChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const customLabel = event.target.value;
    this.setState({ customLabel });
  };

  private onQueryDslChange = (queryDsl: string) => {
    this.setState({ queryDsl });
  };

  private onLocalFilterChange = (updatedFilters: Filter[]) => {
    const { selectedDataView, customLabel } = this.state;
    const alias = customLabel || null;
    const {
      $state,
      meta: { disabled = false, negate = false },
    } = this.props.filter;

    if (!$state || !$state.store || !selectedDataView) {
      return;
    }

    let newFilter: Filter;

    if (updatedFilters.length === 1) {
      const f = updatedFilters[0];
      newFilter = {
        ...f,
        $state: {
          store: $state.store,
        },
        meta: {
          ...f.meta,
          disabled,
          alias,
        },
      };
    } else {
      newFilter = buildCombinedFilter(
        BooleanRelation.AND,
        updatedFilters,
        selectedDataView,
        disabled,
        negate,
        alias,
        $state.store
      );
    }

    this.setState({ localFilter: newFilter });
  };

  private onSubmit = () => {
    const { isCustomEditorOpen, queryDsl, customLabel } = this.state;
    const {
      $state,
      meta: { index, disabled = false, negate = false },
    } = this.props.filter;

    if (!$state || !$state.store) {
      return;
    }

    if (isCustomEditorOpen) {
      const newIndex = index || this.props.indexPatterns[0].id!;
      const body = JSON.parse(queryDsl);
      const filter = buildCustomFilter(
        newIndex,
        body,
        disabled,
        negate,
        customLabel || null,
        $state.store
      );

      this.props.onSubmit(filter);
    } else {
      this.props.onSubmit(this.state.localFilter);
    }
  };
}
