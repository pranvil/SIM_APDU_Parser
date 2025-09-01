
from utils import parse_iccid
from parsers.EUICCResponse import EUICCResponse

def parse_bf37(apdu_data):
    output = "ProfileInstallationResult（BF37）\n"
    index = 8  # 跳过 'BF37' 和其后的两个字节长度字段

    if apdu_data[index:index + 4] == 'BF27':
        index += 6  # 跳过 'BF27'和长度
        index += 2  # 跳过 tag
        length = int(apdu_data[index:index + 2], 16) * 2
        index += 2
        output += "  transactionId: "
        transaction_id = apdu_data[index:index + length]
        output += transaction_id + "\n"
        index += length

        if apdu_data[index:index + 4] == 'BF2F':
            output += "  NotificationMetadata:\n"
            index += 4
            length = int(apdu_data[index:index + 2], 16) * 2
            index += 2

            if apdu_data[index:index + 2] == '80':
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                seq_number = apdu_data[index:index + length]
                output += f"\tseqNumber：{seq_number}\n"
                index += length

            if apdu_data[index:index + 2] == '81':
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                profile_management_operation = apdu_data[index:index + length]
                output += f"\tprofileManagementOperation：{profile_management_operation}\n"
                index += length

            if apdu_data[index:index + 2] == '0C':
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                raw_notification_address = apdu_data[index:index + length]
                notification_address = bytes.fromhex(raw_notification_address).decode('ascii')
                output += f"\tnotificationAddress：{notification_address}\n"
                index += length

            if apdu_data[index:index + 2] == '5A':
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                raw_iccid = apdu_data[index:index + length]
                iccid = parse_iccid(raw_iccid)
                output += f"\ticcid：{iccid}\n"
                index += length

        smdp_oid_length = int(apdu_data[index+2:index + 4], 16) * 2
        index += 4
        smdp_oid = apdu_data[index:index + smdp_oid_length]
        output += f"  smdpOid: {smdp_oid}\n"
        index += smdp_oid_length

        index += 4
        if apdu_data[index:index + 2] in ['A0', 'A1']:
            result_type = apdu_data[index:index + 2]
            index += 2
            length = int(apdu_data[index:index + 2], 16) * 2
            index += 2

            if result_type == 'A0':
                # output += "  finalResult： \033[32mInstallation success\033[0m\n"
                output += "  finalResult： Installation success\n"
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                aid = apdu_data[index:index + length]
                output += f"\tAID：{aid}\n"
                index += length

                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                ppi_response = apdu_data[index:index + length]
                print(ppi_response)
                output += EUICCResponse(ppi_response)
                index += length 

            elif result_type == 'A1':
                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                # output += "  finalResult： \033[31mInstallationFail\033[0m\n"
                output += "  finalResult： InstallationFail\n"
                bpp_command_id = int(apdu_data[index:index + length], 16)

                BppCommandId_map = {
                    0: "initialiseSecureChannel",
                    1: "configureISDP",
                    2: "storeMetadata",
                    3: "storeMetadata2",
                    4: "replaceSessionKeys",
                    5: "loadProfileElements"
                }
                output += f"\tBppCommandId：{BppCommandId_map.get(bpp_command_id, 'Unknown Command')} ({bpp_command_id})\n"
                index += length

                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                error_reason_map = {
                    1: "incorrectInputValues",
                    2: "invalidSignature",
                    3: "invalidTransactionId",
                    4: "unsupportedCrtValues",
                    5: "unsupportedRemoteOperationType",
                    6: "unsupportedProfileClass",
                    7: "bspStructureError",
                    8: "bspSecurityError",
                    9: "installFailedDueToIccidAlreadyExistsOnEuicc",
                    10: "installFailedDueToInsufficientMemoryForProfile",
                    11: "installFailedDueToInterruption",
                    12: "installFailedDueToPEProcessingError",
                    13: "installFailedDueToDataMismatch",
                    14: "testProfileInstallFailedDueToInvalidNaaKey",
                    15: "pprNotAllowed",
                    17: "enterpriseProfilesNotSupported",
                    18: "enterpriseRulesNotAllowed",
                    19: "enterpriseProfileNotAllowed",
                    20: "enterpriseOidMismatch",
                    21: "enterpriseRulesError",
                    22: "enterpriseProfilesOnly",
                    23: "lprNotSupported",
                    26: "unknownTlvInMetadata",
                    127: "installFailedDueToUnknownError"
                }

                error_reason_value = int(apdu_data[index:index + length], 16)
                error_reason_str = error_reason_map.get(error_reason_value, "UnknownError")
                output += f"\tErrorReason：{error_reason_str} ({error_reason_value})\n"
                index += length

                index += 2
                length = int(apdu_data[index:index + 2], 16) * 2
                index += 2
                ppi_response = apdu_data[index:index + length]
                output += EUICCResponse(ppi_response)
                index += length

    if output:
        return output
    else:
        return "BF37 解析未成功"