using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WinsockPacketEditor;

class Program
{
    // Test-only reference runner. Loads the already-built, unchanged supplied C#
    // assembly. Does not launch its UI, inject, install hooks, or start a proxy.
    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 3 && args[0] == "config-files") return ConfigFileOracle.Run(args[1],args[2]);
            if (args.Length == 3 && args[0] == "verify-encrypted") return ConfigFileOracle.Verify(args[1],args[2]);
            if (args.Length == 2 && args[0] == "export-snapshot") return ExportSnapshotOracle.Run(new[]{args[1]});
            if (args.Length == 3 && args[0] == "exports") return ExportOracle.Run(args[1],args[2]);
            if (args.Length == 3 && args[0] == "verify-export") return ExportOracle.Verify(args[1],args[2]);
            if (args.Length == 4 && args[0] == "editors") return EditorOracle.Run(args[1],args[2],args[3]);
            if (args.Length == 3 && args[0] == "verify-native") return VerifyNative(args[1],args[2]);
            if (args.Length != 2) throw new Exception("expected isolated database directory and fixture output");
            var directory = Path.GetFullPath(args[0]);
            Directory.CreateDirectory(directory);
            if(File.Exists(Path.Combine(directory,"oracle.db")))throw new Exception("Use a fresh isolated oracle directory");
            Operate.DataBase.dbPath = directory;
            Operate.DataBase.dbName = "oracle.db";
            Operate.DataBase.InitDB();
            var id = Operate.FilterConfig.List.AddFilter_New_ById();
            if (String.IsNullOrEmpty(id)) throw new Exception("original filter creation failed");
            var cases = new JArray();
            var random = new Random(4191);
            for (int i=0;i<120;i++)
            {
                var row = Operate.FilterConfig.List.GetFilterEdit_ById(id);
                row.Name = i%19==0 ? "\u3000\u00A0" : "\u3000 filter 中文 " + i + " \u00A0";
                row.Mode = i % 2; row.StartFrom = (i / 2) % 2;
                row.Action = i % 6; row.FunctionMask = random.Next(4096);
                row.ProgressionStep = i % 4 - 1; row.ProgressionCarryNumber = i % 5 - 2;
                row.Search = new[]{
                    new FilterSearchCell {Index=0,Value=" aa ",Exclude=true},
                    new FilterSearchCell {Index=-1,Value="11",Exclude=true},
                    new FilterSearchCell {Index=999,Value="CD",Exclude=false},
                    new FilterSearchCell {Index=1000,Value="FF",Exclude=true},
                    new FilterSearchCell {Index=7,Value="",Exclude=true}
                };
                row.Modify = new[]{
                    new FilterModifyCell {Index=-1001,Value="11",Progression=true},
                    new FilterModifyCell {Index=-1000,Value="22",Progression=true},
                    new FilterModifyCell {Index=-1,Value="",Random=true},
                    new FilterModifyCell {Index=0,Value="BB",Progression=true,Random=true},
                    new FilterModifyCell {Index=1,Value=" CC ",Random=true}
                };
                row.AppointSocket=i%7==0;row.SocketContent=i%14==0?"1-2":"12;34";
                var input = JObject.FromObject(row);
                var error = Operate.FilterConfig.List.SaveFilterEdit(row);
                var after = JObject.FromObject(Operate.FilterConfig.List.GetFilterEdit_ById(id));
                input["Id"]="ID"; after["Id"]="ID";
                cases.Add(new JObject { ["input"]=input,["ok"]=String.IsNullOrEmpty(error),["after"]=after });
            }
            var fixture = new JObject { ["sourceAssemblySha256"]=Hash(typeof(Operate).Assembly.Location),["cases"]=cases };
            File.WriteAllText(args[1],fixture.ToString(Formatting.Indented));
            Console.WriteLine("PASS: original C# produced "+cases.Count+" sequential filter edit cases; isolated DB "+directory);
            return 0;
        }
        catch(Exception e){Console.Error.WriteLine(e);return 1;}
    }
    static int VerifyNative(string database,string output)
    {
        var file=Path.GetFullPath(database);
        Operate.DataBase.dbPath=Path.GetDirectoryName(file);
        Operate.DataBase.dbName=Path.GetFileName(file);
        Operate.DataBase.InitConStr();
        UI.Prefs.ScanLine=true;UI.Prefs.FollowSystemTheme=false;
        Operate.SystemConfig.LoadSystemConfig_FromDB();
        if(UI.Prefs.ScanLine||!UI.Prefs.FollowSystemTheme||UI.Prefs.FilterReplace_ForeColor.Hex!="#112233")throw new Exception("Native preferences did not roundtrip through original loader");
        Operate.FilterConfig.List.LoadFilterList_FromDB();
        Operate.SendConfig.List.LoadSendList_FromDB();
        Operate.RobotConfig.List.LoadRobotList_FromDB();
        Operate.WareHouseConfig.List.LoadWareHouseList_FromDB();
        var filters=new JArray();
        foreach(var f in Operate.FilterConfig.List.lstFilterInfo)filters.Add(JObject.FromObject(Operate.FilterConfig.List.GetFilterEdit_ById(f.FID.ToString())));
        var result=new JObject { ["sourceAssemblySha256"]=Hash(typeof(Operate).Assembly.Location),["filterRows"]=filters,
            ["sendCount"]=Operate.SendConfig.List.lstSendInfo.Count,["robotCount"]=Operate.RobotConfig.List.lstRobotInfo.Count,
            ["warehouseCount"]=Operate.WareHouseConfig.List.lstWareHouseInfo.Count };
        if(filters.Count!=1 || (string)filters[0]["Name"]!="'); DROP TABLE Filter; -- 中文" ||
            (int)filters[0]["Modify"][0]["Index"]!=-1000 || (int)result["sendCount"]!=1 ||
            (int)result["robotCount"]!=1 || (int)result["warehouseCount"]!=1)throw new Exception("Native DB did not roundtrip through original loaders");
        File.WriteAllText(output,result.ToString(Formatting.Indented));
        Console.WriteLine("PASS: original C# loaded native SQLite filter, send, robot and warehouse; negative offset preserved");return 0;
    }
    static string Hash(string file){using(var h=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(h.ComputeHash(File.ReadAllBytes(file))).Replace("-","");}
}
