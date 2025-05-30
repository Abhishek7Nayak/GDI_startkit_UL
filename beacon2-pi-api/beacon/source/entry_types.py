from beacon.response.schemas import DefaultSchemas

analysis = {
    "id": "analysis",
    "name": "Bioinformatics analysis",
    "ontologyTermForThisType": {
        "id": "edam:operation_2945",
        "label": "Analysis"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "Apply analytical methods to existing data of a specific type.",
    "defaultSchema": {
        "id": DefaultSchemas.ANALYSES.value['schema'],
        "name": "Default schema for a bioinformatics analysis",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/analyses/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "additionallySupportedSchemas": []
}
biosample = {
    "id": "biosample",
    "name": "Biological Sample",
    "ontologyTermForThisType": {
        "id": "NCIT:C70699",
        "label": "Biospecimen"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "Any material sample taken from a biological entity for testing, diagnostic, propagation, treatment or research purposes, including a sample obtained from a living organism or taken from the biological object after halting of all its life functions. Biospecimen can contain one or more components including but not limited to cellular molecules, cells, tissues, organs, body fluids, embryos, and body excretory products. [ NCI ]",
    "defaultSchema": {
        "id": DefaultSchemas.BIOSAMPLES.value['schema'],
        "name": "Default schema for a biological sample",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/biosamples/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "additionallySupportedSchemas": []
}
cohort = {
    "id": "cohort",
    "name": "Cohort",
    "ontologyTermForThisType": {
        "id": "NCIT:C61512",
        "label": "Cohort"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "A group of individuals, identified by a common characteristic. [ NCI ]",
    "defaultSchema": {
        "id": DefaultSchemas.COHORTS.value['schema'],
        "name": "Default schema for cohorts",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/cohorts/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "aCollectionOf": [{"id": "individual", "name": "Individuals"}],
    "additionalSupportedSchemas": []
}
dataset = {
    "id": "dataset",
    "name": "Dataset",
    "ontologyTermForThisType": {
        "id": "NCIT:C47824",
        "label": "Data set"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "A Dataset is a collection of records, like rows in a database or cards in a cardholder.",
    "defaultSchema": {
        "id": DefaultSchemas.DATASETS.value['schema'],
        "name": "Default schema for datasets",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/datasets/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "aCollectionOf": [{"id": "genomicVariation", "name": "Genomic Variants"}],
    "additionalSupportedSchemas": []
}
genomicVariant = {
    "id": "genomicVariation",
    "name": "Genomic Variants",
    "ontologyTermForThisType": {
        "id": "SO:0000735",
        "label": "sequence_location"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "The location of a sequence.",
    "defaultSchema": {
        "id": DefaultSchemas.GENOMICVARIATIONS.value['schema'],
        "name": "Default schema for a genomic variation",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/genomicVariations/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "additionallySupportedSchemas": []
}
individual = {
    "id": "individual",
    "name": "Individual",
    "ontologyTermForThisType": {
        "id": "NCIT:C25190",
        "label": "Person"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "A human being. It could be a Patient, a Tissue Donor, a Participant, a Human Study Subject, etc.",
    "defaultSchema": {
        "id": DefaultSchemas.INDIVIDUALS.value['schema'],
        "name": "Default schema for an individual",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/individuals/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "additionallySupportedSchemas": []
}
run = {
    "id": "run",
    "name": "Sequencing run",
    "ontologyTermForThisType": {
        "id": "NCIT:C148088",
        "label": "Sequencing run"
    },
    "partOfSpecification": "Beacon v2.0.0",
    "description": "The valid and completed operation of a high-throughput sequencing instrument for a single sequencing process. [ NCI ]",
    "defaultSchema": {
        "id": DefaultSchemas.RUNS.value['schema'],
        "name": "Default schema for a sequencing run",
        "referenceToSchemaDefinition": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/models/json/beacon-v2-default-model/runs/defaultSchema.json",
        "schemaVersion": "v2.0.0"
    },
    "additionallySupportedSchemas": []
}