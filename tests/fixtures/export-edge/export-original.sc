<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<SendCollection>
  <Collection>
    <Socket>17</Socket>
    <Type>TCP_Req</Type>
    <IPFrom>line1
line2
line3
tab	😀</IPFrom>
    <IPTo>中文 &lt;&gt; &amp; "' 😀</IPTo>
    <Buffer>00 FF 80 41</Buffer>
  </Collection>
  <Collection>
    <Socket>23</Socket>
    <Type>-2147483648</Type>
    <IPFrom>::1</IPFrom>
    <IPTo>127.0.0.1:5000</IPTo>
    <Buffer>01 02 03</Buffer>
  </Collection>
  <Collection>
    <Socket>0</Socket>
    <Type>WS1_Send</Type>
    <IPFrom></IPFrom>
    <IPTo></IPTo>
    <Buffer></Buffer>
  </Collection>
</SendCollection>