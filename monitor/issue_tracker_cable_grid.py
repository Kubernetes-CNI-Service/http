"""Fixed three-business-sheet current-grid DATA, not source or send authority."""
import json
import re

from monitor.issue_tracker_cable_merge import SheetImage
from monitor.issue_tracker_local_workbook import _EXPECTED_HEADERS
from monitor.issue_tracker_sheets_read_decode import _cell

FIELDS='spreadsheetId,sheets(properties(sheetId,title,sheetType,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))'
RANGES=("'ETH&IB Switch'!A2:U5002","'ETH Cabling'!A2:AC10002","'IB Cabling'!A2:AC10002")
_ROWS=(('ETH&IB Switch',21,5002),('ETH Cabling',29,10002),('IB Cabling',29,10002))
_TARGET=re.compile(r'[A-Za-z0-9_-]{20,160}\Z')
_MAX=2*1024*1024

class CableGridHold(ValueError):
    def __init__(self):super().__init__('current_grid_invalid')

def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise CableGridHold()
        result[key]=value
    return result

def _constant(_value):raise CableGridHold()

def _entered(cell):
    frozen=_cell(cell) # Existing strict userEnteredValue/formula/type validator.
    result=dict(frozen)
    for value in result.values():
        if type(value) is str and len(value.encode('utf-8','strict'))>32768:
            raise CableGridHold()
    return result

def _images(target,document):
    if type(target) is not str or _TARGET.fullmatch(target) is None:raise CableGridHold()
    if (type(document) is not dict or set(document)!={'spreadsheetId','sheets'}
            or type(document['spreadsheetId']) is not str or document['spreadsheetId']!=target
            or type(document['sheets']) is not list or len(document['sheets'])!=3):
        raise CableGridHold()
    by_title={};ids=set();specs={name:(width,maximum) for name,width,maximum in _ROWS}
    for sheet in document['sheets']:
        if type(sheet) is not dict or set(sheet)!={'properties','data'}:raise CableGridHold()
        props=sheet['properties']
        if (type(props) is not dict or set(props)!={'sheetId','title','sheetType','gridProperties'}
                or type(props['sheetId']) is not int or not 0<=props['sheetId']<=2147483647
                or props['sheetId'] in ids or type(props['title']) is not str
                or props['title'] not in specs or props['title'] in by_title
                or props['sheetType']!='GRID'):
            raise CableGridHold()
        title=props['title'];width,maximum=specs[title];capacity=props['gridProperties']
        if (type(capacity) is not dict or set(capacity)!={'rowCount','columnCount'}
                or type(capacity['rowCount']) is not int or not 3<=capacity['rowCount']<=maximum
                or type(capacity['columnCount']) is not int or capacity['columnCount']!=width):
            raise CableGridHold()
        grids=sheet['data']
        if type(grids) is not list or len(grids)!=1:raise CableGridHold()
        block=grids[0]
        if (type(block) is not dict or not {'startRow','rowData'}<=set(block)<=
                {'startRow','startColumn','rowData'}
                or type(block['startRow']) is not int or block['startRow']!=1
                or type(block.get('startColumn',0)) is not int or block.get('startColumn',0)!=0):
            raise CableGridHold()
        rows=block['rowData'];headers=_EXPECTED_HEADERS[title]
        if type(rows) is not list or not 1<=len(rows)<=capacity['rowCount']-1:
            raise CableGridHold()
        header=rows[0]
        if (type(header) is not dict or set(header)!={'values'}
                or type(header['values']) is not list or len(header['values'])!=width
                or header['values']!=[{'userEnteredValue':{'stringValue':value}} for value in headers]):
            raise CableGridHold()
        output=[]
        for index,row in enumerate(rows[1:],2):
            if type(row) is not dict or not set(row)<={'values'}:raise CableGridHold()
            values=row.get('values',[])
            if type(values) is not list or len(values)>width:raise CableGridHold()
            cells=tuple(_entered(value) for value in values)+tuple({} for _ in range(width-len(values)))
            # API may omit trailing blank rows/cells. Omit only truly absent
            # entered values, never 0/False/formula/explicit empty-string values.
            if any(cells):output.append((index,cells))
        ids.add(props['sheetId']);by_title[title]=SheetImage(title,props['sheetId'],headers,tuple(output))
    if set(by_title)!=set(specs):raise CableGridHold()
    return tuple(by_title[title] for title,_width,_maximum in _ROWS)

def decode_current_grid(target,raw):
    """Strict original JSON bytes, including duplicate-key/nonfinite refusal."""
    failed=False;result=None
    try:
        if type(raw) is not bytes or not 1<=len(raw)<=_MAX:raise CableGridHold()
        document=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_constant)
        result=_images(target,document)
    except Exception:failed=True
    if failed:raise CableGridHold() from None
    return result

def sheet_images_from_sdk(target,document):
    """Detach actual SDK-parsed DATA; not a target/source/admission capability."""
    failed=False;result=None
    try:
        if type(document) is not dict:raise CableGridHold()
        # Bound and detach before inspecting mutable caller observations.
        raw=json.dumps(document,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8','strict')
        if not 1<=len(raw)<=_MAX:raise CableGridHold()
        result=_images(target,json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_constant))
    except Exception:failed=True
    if failed:raise CableGridHold() from None
    return result
