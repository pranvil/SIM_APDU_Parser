def parse_bf22(apdu_data):
    def parse_ext_card_resource(value):
        index = 0
        length = len(value)
        result = []
        
        while index < length:
            tag = value[index:index+2]
            index += 2
            length_byte = int(value[index:index+2], 16)
            index += 2
            val = value[index:index + (length_byte * 2)]
            index += length_byte * 2

            if tag == "81":
                result.append(f"\tNumber of installed application: {val}")
            elif tag == "82":
                available_rom = int(val, 16)
                if available_rom > 1024:
                    result.append(f"\tAvailable ROM: {available_rom / 1024:.2f} KB ({available_rom} bytes)")
                else:
                    result.append(f"\tAvailable ROM: {available_rom} bytes")
            elif tag == "83":
                available_ram = int(val, 16)
                if available_ram > 1024:
                    result.append(f"\tAvailable RAM: {available_ram / 1024:.2f} KB ({available_ram} bytes)")
                else:
                    result.append(f"\tAvailable RAM: {available_ram} bytes")
            else:
                result.append(f"\tUnknown Tag {tag}: {val}")
        
        return result

    def parse_certification_data_object(value):
        index = 0
        length = len(value)
        result = []
        while index < length:
            tag = value[index:index+2]
            index += 2
            length_byte = int(value[index:index+2], 16)
            index += 2
            val = value[index:index + (length_byte * 2)]
            index += length_byte * 2

            try:
                utf8_string = bytes.fromhex(val).decode('utf-8')
                if tag == "80":
                    result.append(f"  platformLabel: {utf8_string}")
                elif tag == "81":
                    result.append(f"  discoveryBaseURL: {utf8_string}")
                else:
                    result.append(f"  Unknown Tag {tag}: {val}")
            except UnicodeDecodeError:
                result.append(f"  Error decoding UTF-8 for Tag {tag}: {val}")

        return result

    def parse_euicc_category(value):
        category_map = {
            0: "other",
            1: "basicEuicc",
            2: "mediumEuicc",
            3: "contactlessEuicc"
        }
        category_num = int(value, 16)
        return category_map.get(category_num, "Unknown Category")

    def parse_uicc_capability(value):
        # The first byte (assumed to be the leading octet) indicates unused bits
        unused_bits = int(value[:2], 16)  # Convert the first byte to the number of unused bits
        
        # The remaining bytes contain the bit string
        value_to_parse = value[2:]  # Skip the first byte to get the actual value
        
        # Convert the remaining hex to binary
        binary_string = bin(int(value_to_parse, 16))[2:].zfill(len(value_to_parse) * 4)
        
        # Remove the unused bits (i.e., the rightmost 'unused_bits' bits)
        if unused_bits > 0:
            binary_string = binary_string[:-unused_bits]
        
        # Define the bit mapping
        bit_mapping = [
            "contactlessSupport", "usimSupport", "isimSupport", "csimSupport",
            "akaMilenage", "akaCave", "akaTuak128", "akaTuak256",
            "usimTestAlgorithm", "rfu2", "gbaAuthenUsim", "gbaAuthenISim",
            "mbmsAuthenUsim", "eapClient", "javacard", "multos",
            "multipleUsimSupport", "multipleIsimSupport", "multipleCsimSupport",
            "berTlvFileSupport", "dfLinkSupport", "catTp", "getIdentity",
            "profile-a-x25519", "profile-b-p256", "suciCalculatorApi",
            "dns-resolution", "scp11ac", "scp11c-authorization-mechanism",
            "s16mode", "eaka", "iotminimal"
        ]

        # Initialize the result list
        result = []

        # Iterate over the bit mapping
        for i, feature in enumerate(bit_mapping):
            if i < len(binary_string):
                # Check the bit at position `i` from the right (LSB -> MSB)
                support = "Support" if binary_string[-(i + 1)] == '1' else "Not Support"
            else:
                support = "Not Support"
            result.append(f"  {feature}: {support}")

        return result

    def parse_euicc_rsp_capability(value):
        # The first byte indicates the number of unused bits
        unused_bits = int(value[:2], 16)
        
        # Remaining bytes contain the actual bit string
        value_to_parse = value[2:]  # Skip the first byte
        
        # Convert the hex to binary
        binary_string = bin(int(value_to_parse, 16))[2:].zfill(len(value_to_parse) * 4)
        
        # Remove the unused bits (rightmost bits)
        if unused_bits > 0:
            binary_string = binary_string[:-unused_bits]
        
        # Define the bit mapping (23 bits)
        bit_mapping = [
            "additionalProfile", "loadCrlSupport", "rpmSupport", "testProfileSupport",
            "deviceInfoExtensibilitySupport", "serviceSpecificDataSupport", "hriServerAddressSupport",
            "serviceProviderMessageSupport", "lpaProxySupport", "enterpriseProfilesSupport",
            "serviceDescriptionSupport", "deviceChangeSupport", "encryptedDeviceChangeDataSupport",
            "estimatedProfileSizeIndicationSupport", "profileSizeInProfilesInfoSupport",
            "crlStaplingV3Support", "certChainV3VerificationSupport", "signedSmdsResponseV3Support",
            "euiccRspCapInInfo1", "osUpdateSupport", "cancelForEmptySpnPnSupport",
            "updateNotifConfigInfoSupport", "updateMetadataV3Support"
        ]
        
        # Initialize the result list
        result = []
        
        # Iterate over the bit mapping
        for i, feature in enumerate(bit_mapping):
            if i < len(binary_string):
                # Since bit0 is the rightmost bit
                support = "Support" if binary_string[-(i + 1)] == '1' else "Not Support"
            else:
                support = "Not Support"
            result.append(f"  {feature}: {support}")
        
        return result
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
            output +=  f"  baseProfilePackageVersion：{value}\n"
        elif tag == "82":
            output +=  f"  lowestSvn：{value}\n"
        elif tag == "83":
            output +=  f"  euiccFirmwareVersion：{value}\n"
        elif tag == "84":
            output +=  f"  extCardResource：{value}\n"
            ext_card_resource_details = parse_ext_card_resource(value)
            for detail in ext_card_resource_details:
                output +=  f"{detail}\n"

        elif tag == "85":
            output += f"  UICCCapability：{value}\n"
            uicc_capability_details = parse_uicc_capability(value)
            for detail in uicc_capability_details:
                output += f"\t{detail}\n"
        elif tag == "86":
            output +=  f"  ts102241Version：{value}\n"
        elif tag == "87":
            output +=  f"  globalplatformVersion：{value}\n"
        elif tag == "88":
            output += f"  euiccRspCapability：{value}\n"
            euicc_rsp_capability_details = parse_euicc_rsp_capability(value)
            for detail in euicc_rsp_capability_details:
                output += f"\t{detail}\n"
        elif tag == "A9":
            output +=  f"  euiccCiPKIdListForVerification：{value}\n"
        elif tag == "AA":
            output +=  f"  euiccCiPKIdListForSigning：{value}\n"
        elif tag == "8B":
            category_name = parse_euicc_category(value)
        elif tag == "99":
            output +=  f"  forbiddenProfilePolicyRules：{value}\n"
        elif tag == "04":
            output +=  f"  ppVersion：{value}\n"
        elif tag == "0C":
            try:
                utf8_string = bytes.fromhex(value).decode('utf-8')
                output +=  f"  sasAcreditationNumber：{utf8_string}\n"
            except UnicodeDecodeError:
                output +=  f"  Error decoding sasAcreditationNumber：{value}\n"
        elif tag == "AC":
            output += f"  certificationDataObject：{value}\n"
            certification_data_details = parse_certification_data_object(value)
            for detail in certification_data_details:
                output += f"\t{detail}\n"
        else:
            output += f"Unknown Tag {tag}: {value}\n"
            
            
    if output:
        return output
    else:
        return "BF22 解析未成功"
  