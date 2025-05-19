from json import loads as parse_json


class jsonb(str):
    __parsed = None

    @property
    def parsed(self):
        """Return a JSON deserializing of itself."""
        if self.__parsed is None:
            self.__parsed = parse_json(self)
        return self.__parsed


def json_encoder(v):
    raise NotImplementedError('We should not use json encoding')


def json_decoder(v):
    return jsonb(v)  # just "tag" it
