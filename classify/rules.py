
from typing import Tuple
from core.models import MsgType, Message
from core.utils import parse_apdu_header, first_tlv_tag_after_store_header

# Request titles mapping per spec
RESP_TITLES = {  
    'BF20': 'EUICCInfo1',
    'BF21': 'PrepareDownloadResponse',
    'BF22': 'EUICCInfo2',
    'BF27': 'Reserved',
    'BF28': 'ListNotificationResponse',
    'BF29': 'SetNicknameResponse',
    'BF2A': 'UpdateMetadataResponse',
    'BF2B': 'RetrieveNotificationsListResponse',
    'BF2D': 'ProfileInfoListResponse',
    'BF2E': 'GetEuiccChallengeResponse',
    'BF2F': 'NotificationMetadata',
    'BF30': 'NotificationSentResponse',
    'BF31': 'EnableProfileResponse',
    'BF32': 'DisableProfileResponse',
    'BF33': 'DeleteProfileResponse',
    'BF34': 'EuiccMemoryResetResponse',
    'BF35': 'Reserved',
    'BF36': 'BoundProfilePackage',
    'BF37': 'ProfileInstallationResult',
    'BF38': 'AuthenticateServerResponse',
    'BF39': 'InitiateAuthenticationResponse',
    'BF3A': 'GetBoundProfilePackageResponse',
    'BF3B': 'AuthenticateClientResponseEs9',
    'BF3C': 'EuiccConfiguredDataResponse',
    'BF3D': 'HandleNotification',
    'BF3E': 'GetEuiccDataResponse',
    'BF3F': 'SetDefaultDpAddressResponse',
    'BF40': 'AuthenticateClientResponseEs11',
    'BF41': 'CancelSessionResponse',
    'BF42': 'LpaeActivationResponse',
    'BF43': 'GetRatResponse',
    'BF44': 'LoadRpmPackageResult',
    'BF45': 'VerifySmdsResponseResponse',
    'BF46': 'CheckEventResponse',
    'BF4A': 'AlertData',
    'BF4B': 'VerifyDeviceChangeResponse',
    'BF4C': 'ConfirmDeviceChangeResponse',
    'BF4D': 'PrepareDeviceChangeResponse',
}

REQ_TITLES = {
    'BF20': 'GetEuiccInfo1Request',
    'BF21': 'PrepareDownloadRequest',
    'BF22': 'GetEuiccInfo2Request',
    'BF23': 'InitialiseSecureChannelRequest',
    'BF24': 'ConfigureISDPRequest',
    'BF25': 'StoreMetadataRequest',
    'BF26': 'ReplaceSessionKeysRequest',
    'BF27': 'Reserved',
    'BF28': 'ListNotificationRequest',
    'BF29': 'SetNicknameRequest',
    'BF2A': 'UpdateMetadataRequest',
    'BF2B': 'RetrieveNotificationsListRequest',
    'BF2D': 'ProfileInfoListRequest',
    'BF2E': 'GetEuiccChallengeRequest',
    'BF2F': 'NotificationMetadata',
    'BF30': 'NotificationSentRequest',
    'BF31': 'EnableProfileRequest',
    'BF32': 'DisableProfileRequest',
    'BF33': 'DeleteProfileRequest',
    'BF34': 'EuiccMemoryResetRequest',
    'BF35': 'Reserved',
    'BF36': 'BoundProfilePackage',
    'BF37': 'ProfileInstallationResult',
    'BF38': 'AuthenticateServerRequest',
    'BF39': 'InitiateAuthenticationRequest',
    'BF3A': 'GetBoundProfilePackageRequest',
    'BF3B': 'AuthenticateClientRequestEs9',
    'BF3C': 'EuiccConfiguredDataRequest',
    'BF3D': 'HandleNotification',
    'BF3E': 'GetEuiccDataRequest',
    'BF3F': 'SetDefaultDpAddressRequest',
    'BF40': 'AuthenticateClientRequestEs11',
    'BF41': 'CancelSessionRequest',
    'BF42': 'LpaeActivationRequest',
    'BF43': 'GetRatRequest',
    'BF44': 'LoadRpmPackageRequest',
    'BF45': 'VerifySmdsResponsesRequest',
    'BF46': 'CheckEventRequest',
    'BF4A': 'AlertData',
    'BF4B': 'VerifyDeviceChangeRequest',
    'BF4C': 'ConfirmDeviceChangeRequest',
    'BF4D': 'PrepareDeviceChangeRequest',
}



def classify_message(msg: Message):
    """Return (msg_type, direction_hint, tag, title). Direction uses ASCII '=>'."""
    s = msg.raw
    # ESIM => LPA (response from eUICC): BF..
    if s.startswith('BF'):
        tag = s[:4] if len(s) >= 4 else 'BF'
        title = f"eSIM=>LPA: {RESP_TITLES.get(tag, tag)}"
        return MsgType.ESIM, 'ESIM=>LPA', tag, title
    # Proactive UICC => Terminal: D0..
    if s.startswith('D0'):
        return MsgType.PROACTIVE, 'UICC=>TERMINAL', 'D0', 'Proactive UICC (D0)'
    # Parse header
    cla, ins, _, _ = parse_apdu_header(s).cla, parse_apdu_header(s).ins, None, None
    # Terminal => UICC proactive
    if cla == 0x80 and ins in (0x10, 0x12, 0x14, 0xC2):
        names = {0x10:'TERMINAL PROFILE',0x12:'FETCH',0x14:'TERMINAL RESPONSE',0xC2:'ENVELOPE'}
        return MsgType.PROACTIVE, 'TERMINAL=>UICC', f'80{ins:02X}', f"Proactive: {names[ins]}"
    # LPA => ESIM (STORE DATA E2)
    if ins == 0xE2 and ((0x80 <= (cla or -1) <= 0x83) or (0xC0 <= (cla or -1) <= 0xCF)):
        tag = first_tlv_tag_after_store_header(s) or 'E2'
        name = REQ_TITLES.get(tag)
        if name:
            return MsgType.ESIM, 'LPA=>ESIM', tag, f"LPA=>ESIM: {name}"
        return MsgType.ESIM, 'LPA=>ESIM', 'E2', 'eSIM STORE DATA (E2)'
    # Others
    return MsgType.NORMAL_SIM, 'UNKNOWN', None, 'SIM APDU'

# 在 classify/rules.py 的判定函数里追加/修正（示意）：

def _ber_take_value_of_D0(raw_hex: str) -> str | None:
    # raw_hex 以 D0 开头：D0 | L | [V]，支持 0x81 扩展长度
    if not raw_hex.startswith("D0"): return None
    L1 = int(raw_hex[2:4], 16); off = 4
    if L1 == 0x81:
        L  = int(raw_hex[4:6], 16); off = 6
    else:
        L  = L1
    return raw_hex[off:off + 2*L]

def classify_and_extract(raw_hex: str):
    s = raw_hex.upper().replace(" ", "")
    # 1) UICC=>TERMINAL: D0
    if s.startswith("D0"):
        payload = _ber_take_value_of_D0(s) or ""
        return ("PROACTIVE", "D0", "UICC=>TERMINAL", payload)

    # 2) TERMINAL=>UICC: 80 xx ...
    if len(s) >= 10 and s.startswith("80"):
        ins = s[2:4].upper()
        lc  = int(s[8:10], 16) if len(s) >= 10 else 0
        data = s[10:10+2*lc]

        if ins == "14":    # Terminal Response
            return ("PROACTIVE", "TERMINAL_RESPONSE", "TERMINAL=>UICC", data)
        if ins == "C2":    # Envelope
            return ("PROACTIVE", "ENVELOPE", "TERMINAL=>UICC", data)
        if ins == "10":    # Terminal Profile（无 TLV 展开）
            return ("PROACTIVE", "TERMINAL_PROFILE", "TERMINAL=>UICC", data)
        if ins == "12":    # FETCH（无 TLV 展开）
            return ("PROACTIVE", "FETCH", "TERMINAL=>UICC", data)

    # 其余：走你已有的 eSIM / normal SIM 识别
    return None
