using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;
using WinsockPacketEditor;

// Test-only. Executes the supplied, unchanged .NET Framework assembly.
static class ConfigFileOracle
{
    static void Save(string file,XElement root){new XDocument(new XDeclaration("1.0","utf-8","yes"),root).Save(file);}
    public static int Run(string input,string output)
    {
        Directory.CreateDirectory(output);
        var db=Path.Combine(output,"db");Directory.CreateDirectory(db);
        if(File.Exists(Path.Combine(db,"oracle.db")))throw new Exception("Fresh oracle directory required");
        Operate.DataBase.dbPath=db;Operate.DataBase.dbName="oracle.db";Operate.DataBase.InitDB();
        Operate.SystemConfig.LoadSystemConfig_FromDB();
        Operate.SystemConfig.SetSystemConfig_FromXML(XElement.Load(Path.Combine(input,"system.xml")));
        Operate.FilterConfig.List.LoadFilterList_FromXDocument(XDocument.Load(Path.Combine(input,"input.fp")));
        Operate.SendConfig.List.LoadSendList_FromXDocument(XDocument.Load(Path.Combine(input,"input.sp")));
        Operate.RobotConfig.List.LoadRobotList_FromXDocument(XDocument.Load(Path.Combine(input,"input.rp")));
        Operate.WareHouseConfig.List.LoadWareHouseList_FromXDocument(XDocument.Load(Path.Combine(input,"input.whp")));
        var roots=new[]{Operate.FilterConfig.List.GetFilterList_XML(Operate.FilterConfig.List.lstFilterInfo.ToList()),
            Operate.SendConfig.List.GetSendList_XML(Operate.SendConfig.List.lstSendInfo.ToList()),
            Operate.RobotConfig.List.GetRobotList_XML(Operate.RobotConfig.List.lstRobotInfo.ToList()),
            Operate.WareHouseConfig.List.GetWareHouseList_XML(Operate.WareHouseConfig.List.lstWareHouseInfo.ToList())};
        var kinds=new[]{"fp","sp","rp","whp"};
        for(int i=0;i<4;i++)Save(Path.Combine(output,"original."+kinds[i]),roots[i]);
        // XElement.Value turns a null/self-closing text field into an empty
        // string on import. Capture both states, rather than expect a false
        // byte-identical roundtrip of an upstream default-null configuration.
        var system=Operate.SystemConfig.GetSystemConfig_XML();Save(Path.Combine(output,"system-before-import.xml"),system);
        Operate.SystemConfig.SetSystemConfig_FromXML(system);
        system=Operate.SystemConfig.GetSystemConfig_XML();Save(Path.Combine(output,"system.xml"),system);
        Save(Path.Combine(output,"original.sb"),new XElement("WPE64_BackUp",system,roots));
        var cases=new JArray();var passwords=new[]{"compatibility-test", "密码中文测试", "emoji-\U0001F512-\U0001F600", "\u00e9\u20ac\u0416\u3042\u3000", " leading and trailing ", "x", "\0embedded\0"};
        foreach(var kind in kinds.Concat(new[]{"sb"}))for(int i=0;i<passwords.Length;i++)
        {
            var file=Path.Combine(output,kind+"-"+i+".encrypted");File.Copy(Path.Combine(output,"original."+kind),file);
            Operate.SystemConfig.EncryptXMLFile(file,passwords[i]);
            var restored=Operate.SystemConfig.DecryptXMLFile(file,passwords[i]);if(restored==null)throw new Exception("Original encryption failed");
            cases.Add(new JObject { ["plain"]="original."+kind,["encrypted"]=Path.GetFileName(file),["password"]=passwords[i] });
        }
        string hash;using(var sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(typeof(Operate).Assembly.Location))).Replace("-","");
        File.WriteAllText(Path.Combine(output,"crypto.json"),new JObject { ["sourceAssemblySha256"]=hash,["codePage"]=Encoding.Default.CodePage,["cases"]=cases }.ToString());
        Console.WriteLine("PASS: original loaders and serializers, 4 parent lists + 5-section backup, "+cases.Count+" cipher vectors, ACP="+Encoding.Default.CodePage);return 0;
    }
    public static int Verify(string file,string password)
    {
        var doc=Operate.SystemConfig.DecryptXMLFile(file,password);if(doc==null||doc.Root==null)throw new Exception("Original rejected native encrypted XML");
        Console.WriteLine("PASS: unchanged original decrypted native "+doc.Root.Name);return 0;
    }
}
