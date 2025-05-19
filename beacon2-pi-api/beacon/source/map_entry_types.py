from beacon.conf import conf

map_analysis= {
                "entryType": "analysis",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/analyses/endpoints.json",
                "rootUrl": conf.uri + "analyses",
                "filteringTermsUrl": conf.uri + "analyses/filtering_terms",
            }
analysis_single=conf.uri + "analyses/{id}"
analysis_genomicVariant={
                        "returnedEntryType": "genomicVariant",
                        "url": conf.uri + "analyses/{id}/g_variants"
                    }
map_biosample= {
                "entryType": "biosample",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/biosamples/endpoints.json",
                "rootUrl": conf.uri + "biosamples",
                "filteringTermsUrl": conf.uri + "biosamples/filtering_terms",
            }
biosample_single=conf.uri + "biosamples/{id}"
biosample_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "biosamples/{id}/analyses"
                    }
biosample_genomicVariant={
                        "returnedEntryType": "genomicVariant",
                        "url": conf.uri + "biosamples/{id}/g_variants"
                    }
biosample_run={
                        "returnedEntryType": "run",
                        "url": conf.uri + "biosamples/{id}/runs"
                    }
map_cohort= {
                "entryType": "cohort",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/cohorts/endpoints.json",
                "rootUrl": conf.uri + "cohorts",
                "filteringTermsUrl": conf.uri + "cohorts/filtering_terms",
            }
cohort_single=conf.uri + "cohorts/{id}"
cohort_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "cohorts/{id}/analyses"
                    }
cohort_individual={
                        "returnedEntryType": "individual",
                        "url": conf.uri + "cohorts/{id}/individuals"
                    }
cohort_run={
                        "returnedEntryType": "run",
                        "url": conf.uri + "cohorts/{id}/runs"
                    }
map_dataset= {
                "entryType": "dataset",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/datasets/endpoints.json",
                "rootUrl": conf.uri + "datasets",
                "filteringTermsUrl": conf.uri + "datasets/filtering_terms",
            }
dataset_single=conf.uri + "datasets/{id}"
dataset_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "datasets/{id}/analyses"
                    }
dataset_biosample={
                        "returnedEntryType": "biosample",
                        "url": conf.uri + "datasets/{id}/biosamples"
                    }
dataset_genomicVariant={
                        "returnedEntryType": "genomicVariant",
                        "url": conf.uri + "datasets/{id}/g_variants"
                    }
dataset_individual={
                        "returnedEntryType": "individual",
                        "url": conf.uri + "datasets/{id}/individuals"
                    }
dataset_run={
                        "returnedEntryType": "run",
                        "url": conf.uri + "datasets/{id}/runs"
                    }
map_genomicVariant= {
                "entryType": "genomicVariant",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/genomicVariations/endpoints.json",
                "rootUrl": conf.uri + "g_variants",
                "filteringTermsUrl": conf.uri + "individuals/g_variants",
            }
genomicVariant_single=conf.uri + "g_variants/{variantInternalId}"
genomicVariant_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "g_variants/{variantInternalId}/analyses"
                    }
genomicVariant_biosample={
                        "returnedEntryType": "biosample",
                        "url": conf.uri + "g_variants/{variantInternalId}/biosamples"
                    }
genomicVariant_individual={
                        "returnedEntryType": "individual",
                        "url": conf.uri + "g_variants/{variantInternalId}/individuals"
                    }
genomicVariant_run={
                        "returnedEntryType": "run",
                        "url": conf.uri + "g_variants/{variantInternalId}/runs"
                    }
map_individual = {
                "entryType": "individual",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/individuals/endpoints.json",
                "rootUrl": conf.uri + "individuals",
                "filteringTermsUrl": conf.uri + "individuals/filtering_terms",
            }
individual_single=conf.uri + "individuals/{id}"
individual_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "individuals/{id}/analyses"
                    }
individual_biosample={
                        "returnedEntryType": "biosample",
                        "url": conf.uri + "individuals/{id}/biosamples"
                    }
individual_genomicVariant={
                        "returnedEntryType": "genomicVariant",
                        "url": conf.uri + "individuals/{id}/g_variants"
                    }
individual_run={
                        "returnedEntryType": "run",
                        "url": conf.uri + "individuals/{id}/runs"
                    }
map_run = {
                "entryType": "run",
                "openAPIEndpointsDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/runs/endpoints.json",
                "rootUrl": conf.uri + "runs",
                "filteringTermsUrl": conf.uri + "runs/filtering_terms"
            }
run_single=conf.uri + "runs/{id}"
run_analysis={
                        "returnedEntryType": "analysis",
                        "url": conf.uri + "runs/{id}/analyses"
                    }
run_genomicVariant= {
                        "returnedEntryType": "genomicVariant",
                        "url": conf.uri + "runs/{id}/g_variants"
                    }