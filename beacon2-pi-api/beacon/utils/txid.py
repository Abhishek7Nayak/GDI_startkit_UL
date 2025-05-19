
import uuid
from beacon.logs.logs import log_with_args_initial
from beacon.conf.conf import level

@log_with_args_initial(level)
def generate_txid(self):
    uniqueid = uuid.uuid4()
    uniqueid = str(uniqueid)[0:8]
    return uniqueid
