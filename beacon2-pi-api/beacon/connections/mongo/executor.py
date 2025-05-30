import asyncio
from concurrent.futures import ThreadPoolExecutor
from beacon.connections.mongo.g_variants import get_variants, get_variant_with_id, get_biosamples_of_variant, get_analyses_of_variant, get_individuals_of_variant, get_runs_of_variant
from beacon.connections.mongo.individuals import get_individuals, get_individual_with_id, get_biosamples_of_individual, get_variants_of_individual
from beacon.connections.mongo.analyses import get_analyses, get_analysis_with_id, get_variants_of_analysis
from beacon.connections.mongo.biosamples import get_biosamples, get_biosample_with_id, get_analyses_of_biosample, get_runs_of_biosample, get_variants_of_biosample
from beacon.connections.mongo.runs import get_runs, get_run_with_id, get_analyses_of_run, get_variants_of_run
from beacon.logs.logs import log_with_args, level, LOG
from typing import Optional
from beacon.request.parameters import RequestParams
from beacon.connections.mongo.datasets import get_analyses_of_dataset, get_biosamples_of_dataset, get_individuals_of_dataset, get_variants_of_dataset, get_runs_of_dataset
from beacon.connections.mongo.cohorts import get_analyses_of_cohort, get_biosamples_of_cohort, get_individuals_of_cohort, get_variants_of_cohort, get_runs_of_cohort
from beacon.connections.mongo.datasets import get_full_datasets, get_dataset_with_id
from beacon.connections.mongo.cohorts import get_cohorts, get_cohort_with_id

@log_with_args(level)
async def execute_function(self, entry_type: str, datasets: list, qparams: RequestParams, entry_id: Optional[str]):
    include = qparams.query.include_resultset_responses
    limit = qparams.query.pagination.limit
    datasets_docs = {}
    datasets_count = {}
    new_count = 0

    if entry_id is None:
        if entry_type == 'g_variants':
            function = get_variants
        elif entry_type == 'individuals':
            function = get_individuals
        elif entry_type == 'analyses':
            function = get_analyses
        elif entry_type == 'biosamples':
            function = get_biosamples
        elif entry_type == 'runs':
            function = get_runs
    else:
        if entry_type == 'g_variants':
            function = get_variant_with_id
        elif entry_type == 'individuals':
            function = get_individual_with_id
        elif entry_type == 'analyses':
            function = get_analysis_with_id
        elif entry_type == 'biosamples':
            function = get_biosample_with_id
        elif entry_type == 'runs':
            function = get_run_with_id
        elif entry_type == 'g_variants_biosamples':
            function = get_biosamples_of_variant
        elif entry_type == 'g_variants_analyses':
            function = get_analyses_of_variant
        elif entry_type == 'g_variants_individuals':
            function = get_individuals_of_variant
        elif entry_type == 'g_variants_runs':
            function = get_runs_of_variant
        elif entry_type == 'analyses_g_variants':
            function = get_variants_of_analysis
        elif entry_type == 'biosamples_g_variants':
            function = get_variants_of_biosample
        elif entry_type == 'biosamples_analyses':
            function = get_analyses_of_biosample
        elif entry_type == 'biosamples_runs':
            function = get_runs_of_biosample
        elif entry_type == 'individuals_biosamples':
            function = get_biosamples_of_individual
        elif entry_type == 'individuals_g_variants':
            function = get_variants_of_individual
        elif entry_type == 'runs_analyses':
            function = get_analyses_of_run
        elif entry_type == 'runs_g_variants':
            function = get_variants_of_run
        elif entry_type == 'datasets_analyses':
            function = get_analyses_of_dataset
        elif entry_type == 'datasets_biosamples':
            function = get_biosamples_of_dataset
        elif entry_type == 'datasets_individuals':
            function = get_individuals_of_dataset
        elif entry_type == 'datasets_g_variants':
            function = get_variants_of_dataset
        elif entry_type == 'datasets_runs':
            function = get_runs_of_dataset
        elif entry_type == 'cohorts_analyses':
            function = get_analyses_of_cohort
        elif entry_type == 'cohorts_biosamples':
            function = get_biosamples_of_cohort
        elif entry_type == 'cohorts_individuals':
            function = get_individuals_of_cohort
        elif entry_type == 'cohorts_g_variants':
            function = get_variants_of_cohort
        elif entry_type == 'cohorts_runs':
            function = get_runs_of_cohort

    loop = asyncio.get_running_loop()

    if datasets and include != 'NONE':
        with ThreadPoolExecutor() as pool:
            done, pending = await asyncio.wait(
                fs=[loop.run_in_executor(pool, function, self, entry_id, qparams, dataset) for dataset in datasets],
                return_when=asyncio.ALL_COMPLETED
            )
        for task in done:
            entity_schema, count, dataset_count, records, dataset = task.result()
            if include == 'ALL':
                if dataset_count != -1:
                    new_count += dataset_count
                    datasets_docs[dataset] = records
                    datasets_count[dataset] = dataset_count
                else:
                    datasets.remove(dataset)  # pragma: no cover
            elif include == 'HIT':
                if dataset_count != -1 and dataset_count != 0:
                    new_count += dataset_count
                    datasets_docs[dataset] = records
                    datasets_count[dataset] = dataset_count
                else:
                    datasets.remove(dataset)
            else:
                if dataset_count == 0:  # pragma: no cover
                    new_count += dataset_count
                    datasets_docs[dataset] = records
                    datasets_count[dataset] = dataset_count
                else:
                    datasets.remove(dataset)
        count = new_count

    else:
        if datasets:
            with ThreadPoolExecutor() as pool:
                done, pending = await asyncio.wait(
                    fs=[loop.run_in_executor(pool, function, self, entry_id, qparams, dataset) for dataset in datasets],
                    return_when=asyncio.ALL_COMPLETED
                )
            for task in done:
                entity_schema, count, dataset_count, records, dataset = task.result()
            datasets_docs["NONE"] = records
            if limit == 0 or new_count < limit:
                pass
            else:
                count = limit  # pragma: no cover
            datasets_count["NONE"] = count
        else:
            datasets_docs["NONE"] = []
            datasets_count["NONE"] = 0
            count = 0
            entity_schema = None

    return datasets_docs, datasets_count, count, entity_schema, include, datasets

@log_with_args(level)
async def execute_collection_function(self, entry_type: str, qparams: RequestParams, entry_id: Optional[str]):
    if entry_id is None:
        if entry_type == 'datasets':
            function = get_full_datasets
        elif entry_type == 'cohorts':
            function = get_cohorts
    else:
        if entry_type == 'datasets':
            function = get_dataset_with_id
        elif entry_type == 'cohorts':
            function = get_cohort_with_id

    response_converted, count, entity_schema = function(self, entry_id, qparams)
    return response_converted, count, entity_schema