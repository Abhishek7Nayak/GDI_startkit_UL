from aiohttp import web
import json
from beacon.request.classes import ErrorClass

def raise_exception(beacon_response, errorCode):
    try:
        if errorCode == 400:
            if ErrorClass.error_response == None:
                ErrorClass.error_response = beacon_response
                ErrorClass.error_code = errorCode
            raise web.HTTPBadRequest(text=json.dumps(beacon_response), content_type='application/json')
        elif errorCode == 500:
            if ErrorClass.error_response == None:# pragma: no cover
                ErrorClass.error_response = beacon_response
                ErrorClass.error_code = errorCode
            raise web.HTTPInternalServerError(text=json.dumps(beacon_response), content_type='application/json')
        else:
            if ErrorClass.error_response == None:# pragma: no cover
                ErrorClass.error_response = beacon_response
                ErrorClass.error_code = 500
            raise web.HTTPInternalServerError(text=json.dumps(beacon_response), content_type='application/json')# pragma: no cover            
    except Exception as e:
        err = str(e)
        errcode=500
        raise_exception(err, errcode)
