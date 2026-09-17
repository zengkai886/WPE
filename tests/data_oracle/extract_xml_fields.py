from pathlib import Path
import re, argparse
parser=argparse.ArgumentParser(description='Extract original XML field order and SQL types; developer tool only.')
parser.add_argument('source',type=Path)
parser.add_argument('project',type=Path)
args=parser.parse_args()
p=args.project.resolve()
s=(args.source.resolve()/'Operate.cs').read_text(encoding='utf-8-sig')
sql=(p/'src/shell/data_schema.h').read_text(encoding='utf-8')
fields={}
for kind,method,table in [('system','GetSystemConfig_XML()','SystemConfig'),('filter','GetFilterList_XML(List<FilterInfo> fiList)','Filter')]:
    body=s[s.index('public static XElement '+method):];body=body[:body.index('return null;')]
    names=re.findall(r'new XElement\("(\w+)"',body)[1 if kind=='system' else 2:]
    schema=re.search(r'CREATE TABLE IF NOT EXISTS '+table+r' \(([^;]+)\);',sql).group(1)
    types=dict(re.findall(r'(\w+) (BOOLEAN|INTEGER|TEXT)',schema))
    fields[kind]=[{'xml':n,'db':'GUID' if n=='ID' else n,'type':types.get('GUID' if n=='ID' else n,'TEXT')} for n in names]
out=['// Field order and types extracted from the supplied Operate.cs + original SQL.','#pragma once','#include <array>','namespace wpe::shell {','struct XmlField {const char* xml;const char* db;const char* type;};']
for kind,fs in fields.items():
    out+=['inline constexpr std::array<XmlField,'+str(len(fs))+'> '+kind+'Fields={{']
    out+=['    {"'+f['xml']+'","'+f['db']+'","'+f['type']+'"},' for f in fs]
    out+=['}};']
out+=['}'];(p/'src/shell/config_xml_fields.h').write_text('\n'.join(out)+'\n',encoding='utf-8')
print({k:len(v) for k,v in fields.items()})
