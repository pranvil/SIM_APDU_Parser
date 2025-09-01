import re


def parse_iccid(raw_iccid):
    """解析 ICCID，将每个字节的两位数互换位置"""
    if len(raw_iccid) != 20:
        raise ValueError("ICCID 应该是固定的 20 位十六进制字符")
    
    # 将每两位数互换位置
    swapped_iccid = ''.join([raw_iccid[i + 1] + raw_iccid[i] for i in range(0, len(raw_iccid), 2)])
    return swapped_iccid

def hex_to_utf8(hex_string):
    # 将十六进制字符串转换为字节
    bytes_data = bytes.fromhex(hex_string)
    # 将字节数据解码为 UTF-8 文本
    utf8_text = bytes_data.decode('utf-8')
    return utf8_text





def get_user_selected_tags():
    options = [
        "1. EUICCInfo2",
        "2. ProfileInstallationResult",
        "3. ProfileInfoListResponse",
        "4. eSIM <-> LPA Operation",
    ]

    tag_map = {
        "1": "BF 22",
        "2": "BF 37",
        "3": "BF 2D",
        "4": "00",
    }

    while True:
        # 显示给用户的选项
        print("请选择要解析的标签，使用逗号隔开多选：")
        for option in options:
            print(option)

        # 获取用户输入
        user_input = input("请输入选项编号：").split(',')
        user_input = [choice.strip() for choice in user_input]

        # 检查是否包含无效选项
        if not all(choice in tag_map or choice == "4" for choice in user_input):
            print("选择包含无效选项，请重新输入！")
            continue

        # 检查用户选择是否包含 "4"
        if "4" in user_input:
            if len(user_input) > 1:
                print("您选择了选项 4（eSIM <-> LPA Operation），此选项不能与其他选项同时选择，请重新输入。")
                continue

        # 将用户选择的选项转换为对应的标签
        selected_tags = [tag_map[choice] for choice in user_input if choice in tag_map]
                
        if not selected_tags:
            print("没有选择有效的标签，请重新运行并选择有效的选项。")
            continue


        return selected_tags


