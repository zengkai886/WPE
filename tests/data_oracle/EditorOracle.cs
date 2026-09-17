using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using WinsockPacketEditor;

// Calls unchanged original business methods. No executor or network is started.
static class EditorOracle
{
    static readonly Dictionary<string,string> aliases=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
    static readonly JArray cases=new JArray();
    static string fixtures;
    static JToken Normalize(JToken token,string key="")
    {
        if(token is JObject){var o=new JObject();foreach(var p in ((JObject)token).Properties())o[p.Name]=Normalize(p.Value,p.Name);return o;}
        if(token is JArray)return new JArray(((JArray)token).Select(t=>Normalize(t,key)));
        if(token.Type!=JTokenType.String)return token.DeepClone();
        var s=(string)token;
        if((key=="id"||key=="Id")&&!String.IsNullOrEmpty(s)){if(!aliases.ContainsKey(s))aliases[s]="$id"+(aliases.Count+1);return new JValue(aliases[s]);}
        foreach(var pair in aliases.Where(p=>p.Key.Length>=32).OrderByDescending(p=>p.Key.Length))s=s.Replace(pair.Key,pair.Value).Replace(pair.Key.ToLowerInvariant(),pair.Value);
        return new JValue(s);
    }
    static JObject Resolve(JObject args)
    {
        string json=args.ToString();foreach(var pair in aliases.OrderByDescending(p=>p.Value.Length))json=json.Replace(pair.Value,pair.Key);return JObject.Parse(json);
    }
    static JToken Step(string method,JObject args=null)
    {
        args=args??new JObject();var result=Normalize(JToken.FromObject(Invoke(method,Resolve(args))));
        cases.Add(new JObject{["method"]=method,["args"]=args,["result"]=result});return result;
    }
    static byte[] Bytes(JObject a){try{return Convert.FromBase64String((string)a["buffer"]??"");}catch{return new byte[0];}}
    static List<string> Ids(JObject a){return ((JArray)a["ids"]??new JArray()).Select(x=>(string)x).ToList();}
    static object Invoke(string m,JObject a)
    {
        switch(m)
        {
            case "addSend":return new{id=Operate.SendConfig.List.AddSend_New_ById()};
            case "addRobot":return new{id=Operate.RobotConfig.List.AddRobot_New_ById()};
            case "addWareHouse":return new{id=Operate.WareHouseConfig.List.AddWareHouse_New_ById()};
            case "addFilter":return new{id=Operate.FilterConfig.List.AddFilter_New_ById()};
            case "openRobotEdit":return Operate.RobotConfig.Robot.OpenRobotEdit_ById((string)a["id"]);
            case "closeRobotEdit":Operate.RobotConfig.Robot.CloseRobotEdit();return new{ok=true};
            case "getRobotInstructions":return new{rows=Operate.RobotConfig.Robot.GetRobotInstructionRows()};
            case "addRobotInstruction":return new{error=Operate.RobotConfig.Robot.AddRobotInstruction_Edit((int)a["type"],(string)a["content"],(int?)a["insertAt"]??-1)};
            case "saveRobotEdit":return new{error=Operate.RobotConfig.Robot.SaveRobotEdit((string)a["name"]),badIndex=Operate.RobotConfig.Robot.LastBadIndex};
            case "robotInstructionAction":return new{ok=true,delta=Operate.RobotConfig.Robot.RobotInstructionAction_ByIndexes((int)a["action"],((JArray)a["indexes"]??new JArray()).Select(x=>(int)x).ToList()).GetAwaiter().GetResult()};
            case "openSendEdit":return Operate.SendConfig.Send.OpenSendEdit_ById((string)a["id"]);
            case "closeSendEdit":Operate.SendConfig.Send.CloseSendEdit();return new{ok=true};
            case "getSendCollection":return new{rows=Operate.SendConfig.Send.GetSendCollectionRows()};
            case "importSendCollection":
                var collection=(BindingList<PacketInfo>)typeof(Operate.SendConfig.Send).GetField("editCollection",BindingFlags.Static|BindingFlags.NonPublic).GetValue(null);
                if(!Operate.SendConfig.Send.LoadSendCollection(Path.Combine(fixtures,"editor-send.sc"),collection,false).GetAwaiter().GetResult())throw new Exception("Original send import failed");return new{ok=true};
            case "sendCollectionAction":return new{ok=true,delta=Operate.SendConfig.Send.SendCollectionAction_ByIds((int)a["action"],Ids(a)).GetAwaiter().GetResult()};
            case "clearSendCollection":Operate.SendConfig.Send.ClearSendCollection_Dialog_Shell().GetAwaiter().GetResult();return new{ok=true};
            case "saveSendEdit":return new{error=Operate.SendConfig.Send.SaveSendEdit((string)a["name"],false,1,1000,"")};
            case "openPacketEdit":return Operate.PacketEditConfig.Open((string)a["list"],long.Parse((string)a["id"]));
            case "savePacketEdit":return new{error=Operate.PacketEditConfig.Save((string)a["list"],long.Parse((string)a["id"]),(int?)a["socket"]??0,Bytes(a))};
            case "storesCommand":
                if((int)a["action"]==8){var wh=Operate.WareHouseConfig.List.FindWareHouse_ById((string)a["wid"]);if(!Operate.WareHouseConfig.List.LoadStores(Path.Combine(fixtures,"editor-stores.whs"),wh.Stores,false).GetAwaiter().GetResult())throw new Exception("Original warehouse import failed");}
                else Operate.WareHouseConfig.List.StoresCommand_Shell((string)a["wid"],(int)a["action"]).GetAwaiter().GetResult();return new{ok=true};
            case "getStoreRows":return new{rows=Operate.WareHouseConfig.List.GetStoreRows_ById((string)a["wid"])};
            case "getStorePreviews":return new{items=Operate.WareHouseConfig.List.GetStorePreviews_ById((string)a["wid"],0,100)};
            case "storesAction":return new{ok=true,delta=Operate.WareHouseConfig.List.StoresAction_ByIds((string)a["wid"],(int)a["action"],Ids(a)).GetAwaiter().GetResult()};
            default:throw new Exception(m);
        }
    }
    static JObject A(params object[] pairs){var a=new JObject();for(int i=0;i<pairs.Length;i+=2)a[(string)pairs[i]]=JToken.FromObject(pairs[i+1]);return a;}
    public static int Run(string isolated,string fixtureDirectory,string output)
    {
        fixtures=Path.GetFullPath(fixtureDirectory);Directory.CreateDirectory(isolated);
        if(File.Exists(Path.Combine(isolated,"oracle.db")))throw new Exception("Fresh directory required");
        Operate.DataBase.dbPath=Path.GetFullPath(isolated);Operate.DataBase.dbName="oracle.db";Operate.DataBase.InitDB();UI.Attach(new TestUi(),null);
        string sid=(string)Step("addSend")["id"],rid=(string)Step("addRobot")["id"],wid=(string)Step("addWareHouse")["id"],fid=(string)Step("addFilter")["id"];
        Step("openRobotEdit",A("id",rid));Step("getRobotInstructions");
        var samples=new[]{
            A("type",-1,"content",""),A("type",9,"content",""),A("type",0,"content",sid),A("type",0,"content","bad"),
            A("type",1,"content","　+12 "),A("type",1,"content","0-20"),A("type",1,"content","20-10"),A("type",1,"content","-1"),A("type",1,"content","2147483648"),
            A("type",2,"content","2"),A("type",2,"content","0"),A("type",3,"content","ignored"),A("type",6,"content","ignored"),
            A("type",7,"content","Customize|+17"),A("type",7,"content","Customize|0"),A("type",7,"content","PacketConfig.List"),A("type",7,"content","FilterSocket"),
            A("type",8,"content","Enable|SendList|"+sid),A("type",8,"content","Disable|RobotList|"+rid),A("type",8,"content","Enable|FilterList|"+fid),A("type",8,"content","Enable|SendList|bad"),
            A("type",4,"content","Press|A"),A("type",4,"content","Down|B"),A("type",4,"content","Up|B"),A("type",4,"content","Combine|Ctrl+A"),A("type",4,"content","Text|中文"),A("type",4,"content","Text|"),A("type",4,"content","0|A"),
            A("type",5,"content","LeftClick|"),A("type",5,"content","WheelUp|2"),A("type",5,"content","WheelDown|0"),A("type",5,"content","MoveTo|-1,+2"),A("type",5,"content","MoveBy|2147483648,0"),
        };
        foreach(var a in samples){Step("addRobotInstruction",a);Step("getRobotInstructions");}
        Step("saveRobotEdit",A("name","　　"));Step("saveRobotEdit",A("name"," 原机器人 "));
        foreach(int action in new[]{0,1,2,3,6}){Step("robotInstructionAction",A("action",action,"indexes",new[]{2,0,2,999}));Step("getRobotInstructions");}
        Step("closeRobotEdit");Step("openRobotEdit",A("id",rid));Step("getRobotInstructions");
        Step("robotInstructionAction",A("action",7));
        foreach(var seq in new[]{new[]{2},new[]{3},new[]{3,2},new[]{2,2,3},new[]{2,3,2,3},new[]{2,2,3,3}}){
            Step("robotInstructionAction",A("action",7));foreach(int type in seq)Step("addRobotInstruction",A("type",type,"content","2"));Step("saveRobotEdit",A("name","循环验证"));
        }
        Step("closeRobotEdit");Step("addRobotInstruction",A("type",1,"content","2"));Step("saveRobotEdit",A("name","gone"));
        Step("openSendEdit",A("id",sid));Step("importSendCollection");var packets=Step("getSendCollection")["rows"];
        var ids=packets.Select(r=>(string)r["Id"]).ToArray();Step("saveSendEdit",A("name","发送保存","loopCount",1,"loopInterval",1000));
        Step("openPacketEdit",A("list","send","id",ids[0]));
        foreach(var b64 in new[]{"","????","AA=Z","/x==","  AAEC\r\n/w== "}){Step("savePacketEdit",A("list","send","id",ids[0],"socket",-3,"buffer",b64));Step("openPacketEdit",A("list","send","id",ids[0]));}
        Step("closeSendEdit");Step("openSendEdit",A("id",sid));Step("openPacketEdit",A("list","send","id",ids[0])); // observes the upstream shallow-copy leak
        Step("sendCollectionAction",A("action",4,"ids",new[]{ids[1],ids[0],ids[0]}));Step("getSendCollection");
        foreach(int action in new[]{0,1,2,3,6}){Step("sendCollectionAction",A("action",action,"ids",new[]{ids[1],ids[0]}));Step("getSendCollection");}
        Step("clearSendCollection");Step("getSendCollection");Step("closeSendEdit");Step("openSendEdit",A("id",sid));Step("getSendCollection");
        Step("openSendEdit",A("id","missing"));Step("getSendCollection"); // invalid open leaves previous session in the original
        Step("storesCommand",A("wid",wid,"action",8));var stores=Step("getStoreRows",A("wid",wid))["rows"].Select(r=>(string)r["Id"]).ToArray();Step("getStorePreviews",A("wid",wid,"from",0,"count",100));
        foreach(int action in new[]{4,0,1,2,3,6}){Step("storesAction",A("wid",wid,"action",action,"ids",new[]{stores[1],stores[0],stores[0]}));Step("getStoreRows",A("wid",wid));Step("getStorePreviews",A("wid",wid,"from",0,"count",100));}
        Step("storesCommand",A("wid",wid,"action",7));Step("getStoreRows",A("wid",wid));
        Step("openRobotEdit",A("id",rid));
        foreach(var sample in new[]{A("type",7,"content","Customize|\u30001"),A("type",5,"content","WheelUp|\u00A01"),A("type",1,"content","1\u00A0-2"),A("type",5,"content","MoveTo|\u30001,\u00A02"),A("type",5,"content","MoveBy|\u30001,\u00A02")})Step("addRobotInstruction",sample);
        var result=new JObject{["originalAssemblySha256"]=Hash(typeof(Operate).Assembly.Location),["cases"]=cases};File.WriteAllText(output,result.ToString());
        Console.WriteLine("PASS: original C# editor sequence: "+cases.Count+" calls; no execution or network");return 0;
    }
    static string Hash(string file){using(var h=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(h.ComputeHash(File.ReadAllBytes(file))).Replace("-","");}
    sealed class TestUi:IUiHost
    {
        public Task<bool> ConfirmAsync(string t,string c,UiIcon i=UiIcon.Warn){return Task.FromResult(true);}
        public void Notify(UiIcon l,string t,string c=null){} public void Toast(UiIcon l,string t){}
        public Task<string> PickOpenAsync(FilePick p){return Task.FromResult<string>(null);}public Task<string> PickSaveAsync(FilePick p){return Task.FromResult<string>(null);}
        public Task<T> BusyAsync<T>(string t,Func<T> work){return Task.FromResult(work());}
        public Task<T> PromptAsync<T>(string f,object a)where T:class{return Task.FromResult<T>(null);}
    }
}
