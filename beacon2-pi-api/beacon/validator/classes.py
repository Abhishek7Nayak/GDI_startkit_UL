from jsonschema import Draft202012Validator
from loguru import logger

class JSONSchemaValidator:
    @classmethod
    def validate(cls, json_data: dict, schema: dict, resolver):# pragma: no cover
        validator = Draft202012Validator(schema, resolver=resolver)
        errors = validator.iter_errors(json_data)
        err_list = []
        for error in errors:
            logger.error(f"The JSON data is not valid: {error=}")
            err_list.append(error)
        return err_list
    
#JSONSchemaValidator.validate(instance, schema, resolver)
