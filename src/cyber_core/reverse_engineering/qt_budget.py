"""Streaming JSON admission: never materialize an over-budget JSON string."""
import json

def bounded_size(value, limit):
    size=0
    for piece in json.JSONEncoder(ensure_ascii=True,allow_nan=False).iterencode(value):
        size+=len(piece) # ASCII serialization, including escaped Unicode.
        if size>limit:
            return None
    return size

def compact_qml(unit):
    return {key:unit[key] for key in ('offset','size_bytes','format_version','qt_version_declared','checksum_status') if key in unit} | {
        'status':'partial','detail_omitted':True,'reason':'serialized_detail_budget',
        'string_count':len(unit.get('strings',[])),'constant_count':len(unit.get('constants',[])),
        'translation_count':len(unit.get('translations',[])),'object_count':len(unit.get('objects',[])),
        'binding_count':unit.get('binding_count',0),'strings':[],'constants':[],'translations':[],'objects':[]}
