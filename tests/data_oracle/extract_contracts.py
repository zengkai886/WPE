from pathlib import Path
import re, json, hashlib, argparse
parser=argparse.ArgumentParser(description='Re-extract contracts from the supplied original source (developer tool, not a product dependency).')
parser.add_argument('source',type=Path,help='Original WinsockPacketEditor directory containing Operate.cs')
parser.add_argument('project',type=Path,help='C++ project directory')
args=parser.parse_args()
src=args.source.resolve()
out=args.project.resolve()
operate=(src/'Operate.cs').read_text(encoding='utf-8-sig')
tables={}
for match in re.finditer(r'string sql = "CREATE TABLE IF NOT EXISTS ',operate):
    end=operate.index('using (SQLiteCommand',match.end())
    literals=re.findall(r'(?:string sql =|sql \+=)\s*"([^"\r\n]*)"',operate[match.start():end])
    for stmt in ''.join(literals).split(';'):
        if stmt.strip(): tables[re.search(r'EXISTS (\w+)',stmt).group(1)]=stmt+';'
chosen=['SystemConfig','InjectMode','ProxyMode','Filter','Send','SendCollection','Robot','RobotInstruction','WareHouse','WareHouseData']
header='// SQL copied from the supplied Operate.cs; no renamed columns.\n#pragma once\nnamespace wpe::shell {\ninline constexpr char data_schema[]=R"SQL(\n'+'\n'.join(tables[n] for n in chosen)+'\n)SQL";\n}\n'
(out/'src/shell/data_schema.h').write_text(header,encoding='utf-8')
shell=(src/'ShellForm.cs').read_text(encoding='utf-8-sig')
methods=[{'method':m.group(1),'line':shell[:m.start()].count('\n')+1} for m in re.finditer(r'bridge.Register\("([^"]+)"',shell)]
(out/'contracts/original-rpc.json').write_text(json.dumps({'source':'WinsockPacketEditor/ShellForm.cs','sha256':hashlib.sha256((src/'ShellForm.cs').read_bytes()).hexdigest(),'methods':methods},ensure_ascii=False,indent=2),encoding='utf-8')
(out/'contracts/original-schema.json').write_text(json.dumps(tables,ensure_ascii=False,indent=2),encoding='utf-8')
print('RPC',len(methods),'SQL tables',len(tables))
langs={}
for name in ['En','Ja','Ko','Ru','Tw','Vi']:
    content=(src/f'ClassObject/L10n/L10n{name}.cs').read_text(encoding='utf-8-sig')
    pairs=re.findall(r'd\[("(?:\\.|[^"\\])*")\]\s*=\s*("(?:\\.|[^"\\])*")\s*;',content)
    d={json.loads(k):json.loads(v) for k,v in pairs}
    langs[d['ID']]=d
payload=json.dumps(langs,ensure_ascii=False)
chunks=','.join('R"L10N('+payload[i:i+4000]+')L10N"' for i in range(0,len(payload),4000))
country=dict(re.findall(r'\{ "([^"]+)", "([^"]+)" \}',(src/'ClassObject/CountryCodes.cs').read_text(encoding='utf-8-sig')))
(out/'src/shell/data_l10n.h').write_text('// Generated from the original C# translation tables and CountryCodes.cs.\n#pragma once\nnamespace wpe::shell { inline constexpr const char* data_l10n_chunks[]={'+chunks+'};\ninline constexpr char country_codes[]=R"CODES('+json.dumps(country,ensure_ascii=False)+')CODES"; }\n',encoding='utf-8')
