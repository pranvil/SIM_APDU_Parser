
import re

def normalize_hex_line(s: str) -> str:
    """Uppercase, remove spaces and non-hex, return continuous HEX string."""
    s = s.strip()
    s = re.sub(r'[^0-9A-Fa-f]', '', s)
    return s.upper()

def pretty_hex(s: str, group=2) -> str:
    s = normalize_hex_line(s)
    return ' '.join(s[i:i+group] for i in range(0, len(s), group))

def detect_kind_and_tag(line: str):
    """Return ('proactive'|'esim'|None, tag) based on leading bytes."""
    s = normalize_hex_line(line)
    if len(s) < 2:
        return None, None
    if s.startswith("D0") or s.startswith("80"):
        # Proactive/Terminal commands
        if s.startswith("80") and len(s) >= 4:
            tag = s[:4]  # e.g., 8014 / 80C2
        else:
            tag = s[:2]  # D0
        return "proactive", tag
    if s.startswith("BF") and len(s) >= 4:
        return "esim", s[:4]  # e.g., BF22
    return None, None

# === eSIM 标题映射（按方向分两套） =========================================
# 说明：
# - keys 统一用无空格形式 'BF22'（抽取器传入的 tag 也是无空格）
# - ESIM⇒LPA：使用 RESP_TITLES
# - LPA⇒ESIM：使用 REQ_TITLES

RESP_TITLES = {  # eSIM => LPA（响应侧）
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
    # 原字典里写成 VerifySmdsResponseResponse，这里去掉重复的“Response”
    'BF45': 'VerifySmdsResponse',
    'BF46': 'CheckEventResponse',
    'BF4A': 'AlertData',
    'BF4B': 'VerifyDeviceChangeResponse',
    'BF4C': 'ConfirmDeviceChangeResponse',
    'BF4D': 'PrepareDeviceChangeResponse',
}

REQ_TITLES = {   # LPA => eSIM（请求侧，81 E2 开头）
    'BF20': 'GetEuiccinfotRequest',   # 原字典拼写如此（若要改为 GetEuiccInfo1Request 可在此处修正）
    'BF21': 'PrepareDownloadRequest',
    'BF22': 'GetEuiccinfo2Request',
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
    'BF35': 'Reserved',
    'BF36': 'BoundProfilePackage',
    'BF37': 'ProfileInstallationResult',
    'BF38': 'AuthenticateServerRequest',
    'BF39': 'InitiateAuthenticationRequest',
    'BF3A': 'GetBoundProfilePackageRequest',
    'BF3B': 'AuthenticateClientRequest',
    'BF3C': 'EuiccConfiguredDataRequest',
    'BF3D': 'HandleNotification',
    'BF3E': 'GetEuiccDataRequest',
    'BF3F': 'SetDefaultDpAddressRequest',
    'BF41': 'CancelSessionRequest',
    'BF42': 'LpaeActivationRequest',
    'BF43': 'GetRatRequest',
    'BF44': 'LoadRpmPackageRequest',
    'BF45': 'VerifySmdsRequest',
    'BF46': 'CheckEventRequest',
    'BF4A': 'AlertData',
    'BF4B': 'VerifyDeviceChangeRequest',
    'BF4C': 'ConfirmDeviceChangeRequest',
    'BF4D': 'PrepareDeviceChangeRequest',
}

def esim_semantic_for(tag: str, direction: str) -> str:
    """
    根据方向返回 eSIM 标题：
    - 'esim_to_lpa'  → 使用 RESP_TITLES
    - 'lpa_to_esim'  → 使用 REQ_TITLES
    - 其余（unknown）→ 优先 RESP_TITLES，否则 REQ_TITLES，否则原始 tag
    """
    t = (tag or '').upper().replace(' ', '')
    if direction == 'esim_to_lpa':
        return RESP_TITLES.get(t, t)
    if direction == 'lpa_to_esim':
        return REQ_TITLES.get(t, t)
    # unknown 时尽量给语义名
    return RESP_TITLES.get(t, REQ_TITLES.get(t, t))
