def parse_example(apdu_data):
    output = "uiccinfo2（BF22）\n"    
    length = len(apdu_data)
    index = 0
    index += 8  # Skip "BF22"
    while index < length:
        
        tag = apdu_data[index:index+2]
        
        index += 2 # skip tag
        length_byte = int(apdu_data[index:index+2], 16)
        index += 2 # skip length


        value = apdu_data[index:index + (length_byte * 2)]
        index += length_byte * 2

        if tag == "81":
            output +=  f"\tbaseProfilePackageVersion：{value}\n"
        elif tag == "82":
            output +=  f"\tlowestSvn：{value}\n"
        elif tag == "83":
            output +=  f"\teuiccFirmwareVersion：{value}\n"
        elif tag == "84":
            output +=  f"\textCardResource：{value}\n"
            ext_card_resource_details = parse_ext_card_resource(value)
            for detail in ext_card_resource_details:
                output +=  f"{detail}\n"

        elif tag == "85":
            output += f"\tUICCCapability：{value}\n"
            uicc_capability_details = parse_uicc_capability(value)
            for detail in uicc_capability_details:
                output += f"{detail}\n"
        elif tag == "86":
            output +=  f"\tts102241Version：{value}\n"
        elif tag == "87":
            output +=  f"\tglobalplatformVersion：{value}\n"
        elif tag == "88":
            output += f"\teuiccRspCapability：{value}\n"
            euicc_rsp_capability_details = parse_euicc_rsp_capability(value)
            for detail in euicc_rsp_capability_details:
                output += f"{detail}\n"
        elif tag == "A9":
            output +=  f"\teuiccCiPKIdListForVerification：{value}\n"
            print(tag,value)
            input()
        elif tag == "AA":
            output +=  f"\teuiccCiPKIdListForSigning：{value}\n"
            print(value)
        elif tag == "8B":
            category_name = parse_euicc_category(value)
            print(value)
        elif tag == "99":
            output +=  f"\tforbiddenProfilePolicyRules：{value}\n"
            print(value)
        elif tag == "04":
            output +=  f"\tppVersion：{value}\n"
            print(value)
        elif tag == "0C":
            try:
                utf8_string = bytes.fromhex(value).decode('utf-8')
                output +=  f"\t\tsasAcreditationNumber：{utf8_string}\n"
            except UnicodeDecodeError:
                output +=  f"\tError decoding sasAcreditationNumber：{value}\n"
        elif tag == "AC":
            certification_data_details = parse_certification_data_object(value)
            for detail in certification_data_details:
                output += f"{detail}\n"
        else:
            output += f"Unknown Tag {tag}: {value}\n"
            
            
    if output:
        return output
    else:
        return "BF22 解析未成功"