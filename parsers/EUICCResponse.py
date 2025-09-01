def EUICCResponse(apdu_data):
    output = "\tpeStatus\n"    
    length = len(apdu_data)
    index = 0
    index += 8
    while index < length:
        tag = apdu_data[index:index+2]        
        index += 2  # skip tag

        length_byte = int(apdu_data[index:index+2], 16)
        index += 2 # skip length
        if tag == "30":
            inner_index = 0
            inner_length = length_byte*2
            inner_apdu_data = apdu_data[index:index+inner_length]
            while inner_index < inner_length:  # parse PE status   
                tag = inner_apdu_data[inner_index:inner_index+2]
                inner_index += 2  # skip tag
                length_byte = int(inner_apdu_data[inner_index:inner_index+2], 16)
                inner_index += 2 # skip length
                value = inner_apdu_data[inner_index:inner_index + (length_byte * 2)]

                inner_index += length_byte * 2  #skip the value

                if tag == "80":
                    value=int(value, 16)
                    status_map = {
                        0: "ok",
                        1: "pe-not-supported",
                        2: "memory-failure",
                        3: "bad-values",
                        4: "not-enough-memory",
                        5: "invalid-request-format",
                        6: "invalid-parameter",
                        7: "runtime-not-supported",
                        8: "lib-not-supported",
                        9: "template-not-supported",
                        10: "feature-not-supported",
                        11: "pin-code-missing",
                        31: "unsupported-profile-version"
                    }
                    print('status:',status_map.get(value, 'Unknown Status'))
                    output +=  f"\t\tstatus: {status_map.get(value, 'Unknown Status')}({value})\n"

                elif tag == "81":
                    value = int(value, 16)
                    output +=  f"\t\tidentification number：{value}\n"

                else:
                    output += f"Unknown Tag {tag}: {value}\n"

            index += inner_index
                
                    
                   
        elif length_byte == 0:
            output +=  f"\tprofileInstallationAborted\n"
        else:
            output += f"Unknown Tag {tag}: {value}\n"
    if output:
        return output
    else:
        return "PE Status 解析未成功"

