<html>
    <title>Snorpy 2.0 - Web Based Snort Rule Creator</title>
    <link rel='stylesheet' href='./css/snorpy.css' type='text/css'></link>
    <link rel="stylesheet" href="./css/jquery-ui.css"></link>
    <meta charset="UTF-8">
    <meta name="description" content="Free web based snort rule creator, maker, with jquery">
    <meta name="keywords" content="web,based,snort,rule,creator,maker,builder">
    <meta name="author" content="Christopher Davis">

    <body>

    

<form method="post" action="./rule.php">  
  <!-- Name: <input type="text" name="name"> -->
  Add Rule
  <div class="rulebody">
  <br><br>
                    <select name="action" >
                        <option value="">Action</option>
                        <option value="alert">alert</option>
                        <option value="log">log</option>
                        <option value="pass">pass</option>
                        <option value="activate">activate</option>
                        <option value="dynamic">dynamic</option>
                        <option value="drop">drop</option>
                        <option value="reject">reject</option>
                        <option value="sdrop">sdrop</option>
                    </select>
                    <select name="protocol">
                        <option value="">Protocol</option>
                        <option value="tcp">tcp</option>
                        <option value="icmp">icmp</option>
                        <option value="udp">udp</option>
                        <option value="ip">ip</option>
                    </select>
                    <input name="sourceip" placeholder="source ip"></input>
                    <input name="srcport" placeholder="source port"></input>
                    <input name="dstip"  placeholder="dest ip"></input>
                    <input name="dstport"  placeholder="dest port"></input>
                    <input name="sid"  placeholder="sid"></input>
                    <input name="rev" placeholder="rev num"></input>

                    <input id=headermessage  name="headermessage" placeholder="Rule Message ( \ Escape special characters)"></input>
                    <input  name="classtype" placeholder="Class-Type"></input>
                    <select name="priority">
                        <option value="">Priority</option>
                        <option value="priority:1;">1</option>
                        <option value="priority:2;">2</option>
                        <option value="priority:3;">3</option>
                        <option value="priority:4;">4</option>
                        <option value="priority:5;">5</option>
                    </select>
                    <input  name="gid" placeholder="gid">
                    <!-- This is the LEFT Main box holind protocol option box -->
            
                    <h2>IP</h2>
                    <select name="ttlevaluator" >
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">TTL</option>
                    </select>

                    <input name="ttl" type="text" />
                    </br></br></br>
                    <select name="ipprotoevaluator" size="1">
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">IP PROTOCOL</option>
                    </select>
                    <input name="ipprotofield" type="text" />
            
                <!-- TCP Options -->
                
                    <h2>TCP</h2>
                    <select class="tcpinputs" id="httpmethodForm" >
                        <option value='content:"GET"; http_method;'>GET</option>
                        <option value='content:"POST"; http_method;'>POST</option>
                        <option value='content:"HEAD"; http_method;'>HEAD</option>
                        <option value='content:"TRACE"; http_method;'>TRACE</option>
                        <option value='content:"PUT"; http_method;'>PUT</option>
                        <option value='content:"DELETE"; http_method;'>DELETE</option>
                        <option value='content:"CONNECT"; http_method;'>CONNECT</option>
                        <option selected="selected" value="">HTTP REQUEST METHOD</option>
                    </select>
                &nbsp<select  class="tcpinputs" style="border-radius:5px; background-color:#f2f2f2; padding:3px;" id="httpstatuscode">
                    <option value="100">100</option>
                    <option value="101">101</option>
                    <option value="200">200</option>
                    <option value="201">201</option>
                    <option value="202">202</option>
                    <option value="203">203</option>
                    <option value="204">204</option>
                    <option value="205">205</option>
                    <option value="206">206</option>
                    <option value="300">300</option>
                    <option value="301">301</option>
                    <option value="302">302</option>
                    <option value="303">303</option>
                    <option value="304">304</option>
                    <option value="305">305</option>
                    <option value="306">306</option>
                    <option value="307">307</option>
                    <option value="400">400</option>
                    <option value="401">401</option>
                    <option value="402">402</option>
                    <option value="403">403</option>
                    <option value="404">404</option>
                    <option value="405">405</option>
                    <option value="406">406</option>
                    <option value="407">407</option>
                    <option value="408">408</option>
                    <option value="409">409</option>
                    <option value="410">410</option>
                    <option value="411">411</option>
                    <option value="412">412</option>
                    <option value="413">413</option>
                    <option value="415">415</option>
                    <option value="416">416</option>
                    <option value="417">417</option>
                    <option value="500">500</option>
                    <option value="501">501</option>
                    <option value="502">502</option>
                    <option value="503">503</option>
                    <option value="504">504</option>
                    <option value="505">505</option>
                    <option selected="selected" value="">HTTP RESPONSE CODE</option>
                    </select></br>
                    </br></br>
                    ACK
                    <input style="border-radius:5px; background-color:#f2f2f2; padding:3px;" id="ACK" class=" check2 opflags opflags" type="checkbox" value="A" />&nbsp;SYN<input id="SYN"  class=" check2 opflags" type="checkbox" value="S" />&nbsp;PSH<input id="PSH"  class=" check2 opflags" type="checkbox" value="P" />&nbsp;RST<input id="RST"  class=" check2 opflags" type="checkbox" value="R" />&nbsp;FIN<input id="FIN"  class=" check2 opflags" type="checkbox" value="F" />&nbsp;URG<input id="URG"  class=" check2 opflags" type="checkbox" value="U" />&nbsp;+<input id="flagplus" class=" check2 opflags flagoptions" type="checkbox" value="+" />&nbsp;*<input id="wildcard" class=" check2 opflags flagoptions" type="checkbox" value="*" /></br>
                    </br></br>
                    <select class="tcpinputs" id="tcpdirectionForm">
                        <option value="FROM_SERVER">FROM_SERVER</option>
                        <option value="TO_SERVER">TO_SERVER</option>
                        <option value="TO_CLIENT">TO_CLIENT</option>
                        <option value="FROM_CLIENT">FROM_CLIENT</option>
                        <option selected="selected" value="">DIRECTION</option>
                    </select>
                    &nbsp
                    <select  class="tcpinputs" id="tcpstateForm">
                        <option value="established">established</option>
                        <option value="stateless">stateless</option>
                        <option value="not_established">not_established</option>
                        <option selected="selected" value="">TCP STATE</option>
                    </select>
                
                <!-- UDP Options -->
                
                    </br></br></br><h2>UDP</h2>
                    </br></br></br>
                    <select style="width: 90%;" id="udpdirectionForm">
                        <option value="FROM_SERVER">FROM_SERVER</option>
                        <option value="TO_SERVER">TO_SERVER</option>
                        <option value="TO_CLIENT">TO_CLIENT</option>
                        <option value="FROM_CLIENT">FROM_CLIENT</option>
                        <option selected="selected" value="">DIRECTION</option>
                    </select>
                
                <!-- ICMP Options -->
                
                    </br></br></br><h2>ICMP</h2>
                    <select  class="tcpinputs" id="icmptypeevaluator">
                    <option value="&gt;">&gt;</option>
                    <option value="&lt;">&lt;</option>
                    <option value="=">=</option>
                    <option selected="selected" value="">ICMP TYPE</option>
                    </select>
                        <input  class="tcpinputs" id="icmptype" type="text" />
                        </br>
                    </br></br></br>
                    <select  class="tcpinputs" id="icmpcodeevaluator">
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">ICMP CODE</option>
                    </select>
                    <input  class="tcpinputs" id="icmpcode" type="text" />
           

                    
    

  <br><br>
  <!-- Gender:
  <input type="radio" name="gender" value="female">Female
  <input type="radio" name="gender" value="male">Male
  <br><br>
  <input type="checkbox" name="ch" value="ch"></input> -->
  <input type="submit" name="submit" value="Submit">  
  </div>
</form>

<!-- ========================================================================================================================== -->



    </body>
    <script src="./js/particles.js"></script>
    <script src="./js/part.js"></script>
    <script src="./js/jquery.min.js"></script>
    <script src="./js/jquery-ui.js"></script>
    <script src="./js/snorpy.js"></script>

</html>