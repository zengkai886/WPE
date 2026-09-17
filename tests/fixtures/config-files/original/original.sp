<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<SendList>
  <Send>
    <IsEnable>True</IsEnable>
    <ID>22222222-2222-2222-2222-222222222222</ID>
    <Name>发送 中文</Name>
    <SystemSocket>False</SystemSocket>
    <LoopCNT>1</LoopCNT>
    <LoopINT>0</LoopINT>
    <Notes>line 1
line 2 &amp; 😀</Notes>
    <SendCollection>
      <Collection>
        <Socket>17</Socket>
        <Type>TCP_Req</Type>
        <IPTo>127.0.0.1:1234</IPTo>
        <Buffer>00 FF AA</Buffer>
      </Collection>
      <Collection>
        <Socket>-1</Socket>
        <Type>WebSocket_Resp</Type>
        <IPTo></IPTo>
        <Buffer></Buffer>
      </Collection>
    </SendCollection>
  </Send>
  <Send>
    <IsEnable>False</IsEnable>
    <ID>22222222-2222-2222-2222-222222222223</ID>
    <Name>empty send</Name>
    <SystemSocket>False</SystemSocket>
    <LoopCNT>1</LoopCNT>
    <LoopINT>1000</LoopINT>
    <Notes></Notes>
  </Send>
</SendList>