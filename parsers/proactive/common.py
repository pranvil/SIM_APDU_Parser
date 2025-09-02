# parsers/proactive/common.py
from core.models import ParseNode

def _hex2int(h): return int(h, 16) if h else 0

def command_details_text(value_hex: str) -> str:
    # Value: cmd_num(1B) | type_of_command(1B) | qualifier(1B)
    cmd_map = {
        "01":"REFRESH","02":"MORE TIME","03":"POLL INTERVAL","04":"POLLING OFF","05":"SET UP EVENT LIST",
        "10":"SET UP CALL","11":"SEND SS","12":"SEND USSD","13":"SEND SHORT MESSAGE","14":"SEND DTMF",
        "15":"LAUNCH BROWSER","16":"GEOGRAPHICAL LOCATION REQUEST","20":"PLAY TONE","21":"DISPLAY TEXT",
        "22":"GET INKEY","23":"GET INPUT","24":"SELECT ITEM","25":"SET UP MENU","26":"PROVIDE LOCAL INFORMATION",
        "27":"TIMER MANAGEMENT","28":"SET UP IDLE MODE TEXT","30":"PERFORM CARD APDU","31":"POWER ON CARD",
        "32":"POWER OFF CARD","33":"GET READER STATUS","34":"RUN AT COMMAND","35":"LANGUAGE NOTIFICATION",
        "40":"OPEN CHANNEL","41":"CLOSE CHANNEL","42":"RECEIVE DATA","43":"SEND DATA","44":"GET CHANNEL STATUS",
        "45":"SERVICE SEARCH","46":"GET SERVICE INFORMATION","47":"DECLARE SERVICE",
        "50":"SET FRAMES","51":"GET FRAMES STATUS","60":"RETRIEVE MULTIMEDIA MESSAGE",
        "61":"SUBMIT MULTIMEDIA MESSAGE","62":"DISPLAY MULTIMEDIA MESSAGE","70":"ACTIVATE",
        "71":"CONTACTLESS STATE CHANGED","73":"ENCAPSULATED SESSION CONTROL","79":"LSI COMMAND",
        "81":"End of the proactive UICC session",
    }
    if len(value_hex) < 6:
        return "Unknown Command"
    cmd = value_hex[2:4].upper()
    q   = value_hex[4:6].upper()
    qual_map = {
        "21":{"00":"Normal priority","01":"High priority","80":"Clear after delay","81":"Wait user clear"},
        "22":{"00":"Digits only","01":"Alphabet set","02":"SMS default alphabet","03":"UCS2 alphabet",
              "04":"Echo input","05":"Not revealed","08":"No help","09":"Help available"},
        "23":{"00":"Digits only","01":"Alphabet set","02":"SMS default alphabet","03":"UCS2 alphabet",
              "04":"Echo input","05":"Not revealed","08":"No help","09":"Help available"},
        "24":{"00":"Presentation not specified","01":"Presentation specified",
              "02":"Choice data values","03":"Choice navigation","08":"No help","09":"Help available"},
        "25":{"00":"No selection preference","01":"Soft key preferred","08":"No help","09":"Help available"},
        "26":{"00":"Location Information","01":"IMEI","02":"Network Measurement","03":"Date/Time/TZ",
              "04":"Language","06":"Access Technology","08":"IMEISV","0E":"Multiple Access Technologies",
              "1A":"Supported RATs"},
        "27":{"00":"Start","01":"Deactivate","10":"Get current value"},
        "40":{"00":"On demand","01":"Immediate","02":"No auto reconnect","03":"Auto reconnect",
              "04":"No background mode","05":"Immediate background","06":"No DNS requested","07":"DNS requested"},
        "41":{"00":"No indication","01":"Indication for next CAT command"},
        "43":{"00":"Store in Tx buffer","01":"Send immediately"},
        "20":{"00":"Vibrate optional","01":"Vibrate with tone"},
        "10":{"00":"Set up call, not busy","01":"Set up call, not busy, with redial","02":"Put others on hold",
              "03":"Put others on hold w/ redial","04":"Disconnect others","05":"Disconnect others w/ redial"},
        "13":{"00":"Packing not required","01":"SMS packing required"},
        "73":{"00":"End session","01":"Request Master SA","02":"Request Connection SA",
              "03":"Start Secure Channel","04":"Close M/CSA"},
        "79":{"00":"Proactive Session Request","01":"UICC Platform Reset"},
    }
    cmd_name = cmd_map.get(cmd, f"Unknown({cmd})")
    qual_desc = qual_map.get(cmd, {}).get(q, f"Qualifier {q}")
    return f"{cmd_name} - {qual_desc}"

def device_identities_text(value_hex: str) -> str:
    dev_map = {"01":"Keypad","02":"Display","03":"Earpiece","10":"Additional Reader 0","11":"Additional Reader 1",
               "12":"Additional Reader 2","13":"Additional Reader 3","14":"Additional Reader 4","15":"Additional Reader 5",
               "16":"Additional Reader 6","17":"Additional Reader 7","21":"Channel 1","22":"Channel 2","23":"Channel 3",
               "24":"Channel 4","25":"Channel 5","26":"Channel 6","27":"Channel 7","81":"UICC","82":"Terminal","83":"Network"}
    if len(value_hex) < 4: return "Unknown device identities"
    s = value_hex[:2].upper(); d = value_hex[2:4].upper()
    return f"{dev_map.get(s,'?')} -> {dev_map.get(d,'?')}"

def result_details_text(value_hex: str) -> str:
    gen = {
        "00":"Command performed successfully","01":"Partial comprehension","02":"Missing information",
        "03":"REFRESH with add. EFs read","04":"Success but icon not displayed","05":"Modified by call control by NAA",
        "06":"Success, limited service","07":"Performed with modification","08":"REFRESH but NAA not active",
        "09":"Success, tone not played","10":"Session terminated by user","11":"Backward move requested",
        "12":"No response from user","30":"Beyond terminal's capabilities","31":"Type not understood",
        "32":"Data not understood","33":"Number not known","36":"Required values missing",
    }
    addi = {
        "20":{"00":"No specific cause","01":"Screen busy","02":"Busy on call","04":"No service","06":"Radio resource not granted"},
        "38":{"01":"Reader removed","02":"Card removed","03":"Reader busy","04":"Card powered off","05":"C-APDU format error"},
    }
    if len(value_hex) < 2: return "Unknown General Result"
    gr = value_hex[:2].upper()
    res = gen.get(gr, f"General {gr}")
    extra = ""
    if len(value_hex) > 2:
        ai = value_hex[2:4].upper()
        extra = addi.get(gr, {}).get(ai, "")
        if extra: extra = f", {extra}"
    return f"{res}{extra}"

def parse_duration_text(value_hex: str) -> str:
    if len(value_hex) != 4: return f"{value_hex}"
    unit_map = {"00":"minutes","01":"seconds","02":"tenths"}
    unit = unit_map.get(value_hex[:2],"?"); val = _hex2int(value_hex[2:])
    if unit == "tenths": return f"{val/10:.1f} seconds"
    return f"{val} {unit}"

def parse_address_text(value_hex: str) -> str:
    if len(value_hex) < 2: return value_hex
    b = bin(int(value_hex[:2],16))[2:].zfill(8)
    ton_bits = b[1:4]; npi_bits = b[4:8]
    ton = {"000":"Unknown","001":"International","010":"National","011":"Network Specific"}.get(ton_bits,"Reserved")
    npi = {"0000":"Unknown","0001":"ISDN","0011":"Data","0100":"Telex","1001":"Private","1111":"Ext"}.get(npi_bits,"Reserved")
    dn = ""
    raw = value_hex[2:]
    for i in range(0,len(raw),2):
        if i+2<=len(raw):
            dn += raw[i+1:i+2] + raw[i:i+1]
    return f"TON={ton}, NPI={npi}, Dial={dn}"

def parse_channel_status_text(value_hex: str) -> str:
    if len(value_hex) < 2: return value_hex
    b3 = int(value_hex[:2],16)
    ch = b3 & 0x07
    est = "BIP channel established" if (b3>>7)&1 else "BIP channel not established"
    further = ""
    if len(value_hex) >= 4:
        b4 = value_hex[2:4]
        if b4 == "00": further = "No further info"
        elif b4 == "05": further = "Link dropped"
    return f"Channel {ch}, {est}" + (f", {further}" if further else "")

def parse_access_tech_text(value_hex: str) -> str:
    m={"00":"GSM","03":"UTRAN","08":"E-UTRAN","0A":"NG-RAN"}
    return ", ".join(m.get(value_hex[i:i+2],"UNK") for i in range(0,len(value_hex),2))

def parse_timer_identifier_text(v:str)->str:
    m={'01':'Timer 1','02':'Timer 2','03':'Timer 3','04':'Timer 4','05':'Timer 5','06':'Timer 6','07':'Timer 7','08':'Timer 8'}
    return m.get(v, v)

def parse_imei_text(v:str)->str:
    out=""
    for i in range(0,len(v),2):
        b=v[i:i+2]
        if len(b)==2: out += b[1]+b[0]
    return out

def parse_comp_tlvs_to_nodes(hexstr: str) -> tuple[ParseNode, str]:
    """把 Comprehension TLV 串解析成 ParseNode 子树；返回(root, 首个命令名)。"""
    idx=0; n=len(hexstr); root=ParseNode(name="Comprehension TLVs"); first=None
    while idx+4 <= n:
        tag = hexstr[idx:idx+2].upper(); idx+=2
        ln  = int(hexstr[idx:idx+2],16) if idx+2<=n else 0; idx+=2
        val = hexstr[idx:idx+2*ln] if idx+2*ln<=n else ""; idx += 2*ln

        def is_tag(*alts): return tag in alts
        if is_tag("01","81"):
            txt = command_details_text(val)
            root.children.append(ParseNode(name="Command details (01)", value=txt))
            if first is None: first = txt.split(" - ")[0]
        elif is_tag("02","82"):
            root.children.append(ParseNode(name="Device identities (02)", value=device_identities_text(val)))
        elif is_tag("03","83"):
            root.children.append(ParseNode(name="Result (03)", value=result_details_text(val)))
        elif is_tag("04","84"):
            root.children.append(ParseNode(name="Duration (04)", value=parse_duration_text(val)))
        elif is_tag("05","85"):
            root.children.append(ParseNode(name="Alpha identifier (05)", value=val))
        elif is_tag("06","86"):
            root.children.append(ParseNode(name="Address (06)", value=parse_address_text(val)))
        elif is_tag("38","B8"):
            root.children.append(ParseNode(name="Channel status (38)", value=parse_channel_status_text(val)))
        elif is_tag("0B","8B"):
            root.children.append(ParseNode(name="SMS TPDU (0B)", value=val))
        elif is_tag("39","B9"):
            root.children.append(ParseNode(name="Buffer size (39)", value=str(int(val or "0",16))))
        elif is_tag("47","C7"):
            try: text = bytes.fromhex(val[2:]).decode("ascii","replace") if len(val)>=2 else ""
            except Exception: text = val
            root.children.append(ParseNode(name="Network Access Name (47)", value=text))
        elif is_tag("3C","BC"):
            t = val[:2]; port = int(val[2:] or "0",16)
            pm = {"01":"UDP client remote","02":"TCP client remote","03":"TCP server","04":"UDP client local","05":"TCP client local","06":"direct"}
            root.children.append(ParseNode(name="Transport Protocol (3C)", value=f"{pm.get(t,'?')}, port={port}"))
        elif is_tag("FD","7D"):
            if len(val)>=6:
                mccmnc_raw = val[:6]
                mccmnc = f"{mccmnc_raw[1]}{mccmnc_raw[0]}{mccmnc_raw[3]}{mccmnc_raw[5]}{mccmnc_raw[4]}{mccmnc_raw[2]}"
                tac = val[6:]
                root.children.append(ParseNode(name="MCCMNC+TAC (FD)", value=f"{mccmnc}, TAC:{tac}"))
        elif is_tag("B5","35"):
            root.children.append(ParseNode(name="Bearer description (B5)", value=val))
        elif is_tag("13","93"):
            root.children.append(ParseNode(name="Location Info (13)", value=val))
        elif is_tag("14","94"):
            root.children.append(ParseNode(name="IMEI (14)", value=parse_imei_text(val)))
        elif is_tag("62","E2"):
            root.children.append(ParseNode(name="IMEISV (62)", value=val))
        elif is_tag("19","99"):
            root.children.append(ParseNode(name="Event List (19)", value=val))
        elif is_tag("2F","AF"):
            root.children.append(ParseNode(name="AID (2F)", value=val))
        elif is_tag("3E","BE"):
            root.children.append(ParseNode(name="Data dest address (3E)", value=val))
        elif is_tag("36","B6"):
            root.children.append(ParseNode(name="Channel data (36)", value=val))
        elif is_tag("37","B7"):
            root.children.append(ParseNode(name="Channel data length (37)", value=val))
        elif is_tag("3F","BF"):
            root.children.append(ParseNode(name="Access Technology (3F)", value=parse_access_tech_text(val)))
        elif is_tag("A2","22"):
            root.children.append(ParseNode(name="C-APDU (A2)", value=val))
        elif is_tag("A4","24"):
            root.children.append(ParseNode(name="Timer identifier (A4)", value=parse_timer_identifier_text(val)))
        elif is_tag("A5","25"):
            root.children.append(ParseNode(name="Timer (A5)", value=f"{val[0:2]}:{val[2:4]}:{val[4:6]}" if len(val)>=6 else val))
        elif is_tag("21","A1"):
            root.children.append(ParseNode(name="Card ATR (21)", value=val))
        elif is_tag("E0","60"):
            root.children.append(ParseNode(name="MAC (E0)", value=val))
        elif is_tag("A6","26"):
            root.children.append(ParseNode(name="Date/Time/TZ (A6)", value=val))
        elif is_tag("6C","EC"):
            root.children.append(ParseNode(name="MMS Transfer Status (6C)", value=val))
        elif is_tag("7E","FE"):
            root.children.append(ParseNode(name="CSG ID list (7E)", value=val))
        elif is_tag("56","D6"):
            root.children.append(ParseNode(name="CSG ID (56)", value=val))
        elif is_tag("57","D7"):
            root.children.append(ParseNode(name="Timer Expiration (57)", value=val))
        else:
            root.children.append(ParseNode(name=f"TLV {tag}", value=f"len={ln}", hint=val[:120]))
    return root, (first or "")
