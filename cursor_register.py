import os
import csv
import copy
import argparse
import concurrent.futures
import sys
# import hydra # 暂时注释掉 Hydra，可能不再需要
from faker import Faker
from datetime import datetime
# from omegaconf import OmegaConf, DictConfig # 暂时注释掉 OmegaConf
from DrissionPage import ChromiumOptions, Chromium
import base64
import json
import queue

# 设置控制台输出编码为UTF-8，避免中文字符编码问题
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        # Python 3.6及更早版本没有reconfigure方法
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# from temp_mails import Tempmail_io, Guerillamail_com # 不再需要临时邮箱
from helper.cursor_register import CursorRegister
from helper.email import * # 仍然需要 IMAP

# Parameters for debugging purpose
hide_account_info = os.getenv('HIDE_ACCOUNT_INFO', 'false').lower() == 'true'
enable_headless = os.getenv('ENABLE_HEADLESS', 'false').lower() == 'true'
enable_browser_log = os.getenv('ENABLE_BROWSER_LOG', 'true').lower() == 'true' or not enable_headless

# 新增：从环境变量读取核心配置
registration_email = os.getenv('REGISTRATION_EMAIL')
receiving_gmail_address = os.getenv('RECEIVING_GMAIL_ADDRESS') # 不再使用此变量
receiving_gmail_app_password = os.getenv('RECEIVING_GMAIL_APP_PASSWORD') # 不再使用此变量
ingest_to_oneapi = os.getenv('INGEST_TO_ONEAPI', 'false').lower() == 'true'
oneapi_url = os.getenv('CURSOR_ONEAPI_URL')
oneapi_token = os.getenv('CURSOR_ONEAPI_TOKEN')
oneapi_channel_url = os.getenv('CURSOR_CHANNEL_URL')
max_workers = int(os.getenv('MAX_WORKERS', '1')) # 暂时保留，但当前逻辑为单线程

# 新增：读取 Action 类型
action_type = os.getenv('ACTION_TYPE', 'signup').lower()

# 新增：读取接收邮箱的 IMAP 配置
receiving_imap_server = os.getenv('RECEIVING_IMAP_SERVER')
receiving_imap_port = os.getenv('RECEIVING_IMAP_PORT')
receiving_username = os.getenv('RECEIVING_USERNAME')
receiving_password = os.getenv('RECEIVING_PASSWORD')

# --- 新增: 余额判断阈值 ---
LOW_BALANCE_THRESHOLD = int(os.getenv('LOW_BALANCE_THRESHOLD', '50'))

def register_cursor_core(reg_email, options):

    try:
        browser = Chromium(options)
    except Exception as e:
        print(f"[Error] Failed to initialize browser: {e}")
        return None

    # 直接设置邮箱地址
    email_address = reg_email

    # 使用从环境变量读取的配置实例化 IMAP 服务器
    print(f"[IMAP] Connecting to {receiving_username}@{receiving_imap_server} to find verification for {reg_email}")
    try:
      # 检查配置是否存在
      if not all([receiving_imap_server, receiving_imap_port, receiving_username, receiving_password]):
          raise ValueError("接收邮箱的 IMAP 配置环境变量不完整")

      # 注意端口需要是整数
      imap_port_int = int(receiving_imap_port)

      email_server = Imap(imap_server=receiving_imap_server,
                          imap_port=imap_port_int,
                          username=receiving_username,
                          password=receiving_password,
                          email_to=reg_email) # 传递注册邮箱用于可能的过滤
    except Exception as e:
        print(f"[IMAP Error] Failed to connect or initialize IMAP for {receiving_username}: {e}")
        if browser:
            browser.quit(force=True, del_data=True)
        return None # 初始化失败，无法继续

    register = CursorRegister(browser, email_server) # 传递 email_server

    # --- 根据 action_type 执行操作 ---
    token = None
    final_tab = None
    final_status = False

    if action_type == 'signin':
        print(f"[Register] Action Type: signin. Attempting sign in for {email_address}...")
        tab_signin, status_signin = register.sign_in(email_address) # 传入 email_address
        token_signin = None
        if status_signin:
             token_signin = register.get_cursor_cookie(tab_signin) # 传入 tab_signin

        if token_signin:
            print(f"[Register] Sign in successful for {email_address}. Checking balance...")
            # --- 登录成功，检查余额 ---
            balance = 0
            is_low_balance = False
            user_id_signin = None
            try:
                # 解析 User ID
                try:
                    payload_b64 = token_signin.split('.')[1]
                    payload_b64 += '=' * (-len(payload_b64) % 4)
                    payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
                    payload = json.loads(payload_json)
                    user_id_signin = payload.get('sub')
                except Exception as jwt_err:
                    print(f"[JWT Decode Error in Signin] Failed to decode or parse JWT: {jwt_err}")

                # 获取 Usage
                if user_id_signin:
                    print(f"[Balance Check in Signin] Getting usage for UserID: {user_id_signin}...")
                    usage = register.get_usage(user_id_signin) # 传入 user_id_signin
                    if usage and 'gpt-4' in usage:
                        balance = usage["gpt-4"]["maxRequestUsage"] - usage["gpt-4"]["numRequests"]
                        is_low_balance = balance <= LOW_BALANCE_THRESHOLD # 使用阈值判断
                        print(f"[Balance Check in Signin] Email: {email_address}, Balance: {balance}, Low Balance: {is_low_balance}")
                    else:
                        print(f"[Balance Check Warning in Signin] Could not get valid usage data. Usage response: {usage}")
                else:
                     print("[Balance Check Skip in Signin] Skipping balance check due to missing User ID.")
            except Exception as e:
                print(f"[Balance Check Error in Signin] An unexpected error occurred: {e}")
                # 即使余额检查失败，也认为余额未知，可能需要重新注册以确保状态
                is_low_balance = True # 假设余额不足，触发重新注册
                print("[Balance Check Error] Assuming low balance due to error.")

            # --- 根据余额决定下一步 ---
            if is_low_balance:
                print(f"[Register] Low balance detected for {email_address}. Attempting re-registration via signup...")
                # 关闭旧的 IMAP 线程 (如果存在且在运行)
                if register.email_thread and register.email_thread.is_alive():
                    # 尝试优雅地停止，但 IMAP 库可能不支持直接停止阻塞操作
                    # 重新初始化 email_server 可能更安全
                    print("[IMAP] Re-initializing IMAP server for signup...")
                    try:
                        # 确保 register 对象的 email_server 被重新设置
                        register.email_server = Imap(imap_server=receiving_imap_server,
                                                 imap_port=imap_port_int,
                                                 username=receiving_username,
                                                 password=receiving_password,
                                                 email_to=reg_email)
                         # 重置邮件队列
                        register.email_queue = queue.Queue()
                    except Exception as e_reinit:
                         print(f"[IMAP Error] Failed to re-initialize IMAP for signup: {e_reinit}")
                         # 标记最终状态为失败，因为无法进行注册
                         final_status = False
                         token = None
                         final_tab = tab_signin # 保留原始标签页以便退出
                         # 跳过后续的注册尝试
                         print("[Register] Aborting re-registration due to IMAP re-initialization failure.")

                # 只有在IMAP重新初始化成功后才尝试注册
                if final_status is not False: # 检查是否因IMAP错误而提前终止
                    tab_signup, status_signup = register.sign_up(email_address) # 传入 email_address
                    if status_signup:
                        token = register.get_cursor_cookie(tab_signup) # 传入 tab_signup
                        print(f"[Register] Re-registration via signup successful for {email_address}.")
                    else:
                        token = None
                        print(f"[Register] Re-registration via signup failed for {email_address}.")
                    final_tab = tab_signup # 最终标签页是注册页
                    final_status = token is not None
            else:
                print(f"[Register] Balance is sufficient for {email_address}. Using existing token.")
                token = token_signin
                final_tab = tab_signin # 最终标签页是登录页
                final_status = True

        else: # 初始登录失败
            print(f"[Register] Initial sign in failed for {email_address}.")
            final_tab = tab_signin # 保留失败的标签页
            final_status = False
            token = None

    elif action_type == 'signup':
        print(f"[Register] Action Type: signup. Attempting sign up for {email_address}...")
        # 确保 email_server 实例已准备好用于注册
        if not register.email_server:
             print("[Error] Email server not properly initialized for signup.")
             final_status = False
             token = None
        else:
            tab_signup, status_signup = register.sign_up(email_address) # 传入 email_address
            if status_signup:
                token = register.get_cursor_cookie(tab_signup) # 传入 tab_signup
            else:
                token = None
            final_tab = tab_signup
            final_status = token is not None
            if not final_status:
                 print(f"[Register] Sign up for {email_address} failed or did not yield token.")

    else: # 未知的 action_type
        print(f"[Error] Unknown ACTION_TYPE: {action_type}. Aborting.")
        final_status = False # 确保状态为失败
        token = None

    # --- 最终状态确定后，进行最后的余额检查 (主要用于记录最终状态) ---
    final_balance = 0
    final_is_low_balance = False # 这个值现在主要是信息性的
    final_user_id = None

    if final_status and token: # 只对最终成功的 token 检查余额
        try:
            # 解析 User ID
            try:
                payload_b64 = token.split('.')[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
                payload = json.loads(payload_json)
                final_user_id = payload.get('sub')
            except Exception as jwt_err:
                print(f"[JWT Decode Error in Final Check] Failed to decode or parse JWT: {jwt_err}")

            # 获取 Usage
            if final_user_id:
                print(f"[Balance Check in Final] Getting usage for UserID: {final_user_id}...")
                # 使用当前的 register 对象
                final_usage = register.get_usage(final_user_id) # 传入 final_user_id
                if final_usage and 'gpt-4' in final_usage:
                    final_balance = final_usage["gpt-4"]["maxRequestUsage"] - final_usage["gpt-4"]["numRequests"]
                    final_is_low_balance = final_balance <= LOW_BALANCE_THRESHOLD
                    print(f"[Balance Check in Final] Email: {email_address}, Final Balance: {final_balance}, Low Balance: {final_is_low_balance}")
                else:
                    print(f"[Balance Check Warning in Final] Could not get valid usage data. Usage response: {final_usage}")
            else:
                 print("[Balance Check Skip in Final] Skipping final balance check due to missing User ID.")
        except Exception as e:
            print(f"[Balance Check Error in Final] An unexpected error occurred: {e}")
            # 记录错误，但不改变 final_status 或 token
            final_balance = 0 # 设为0表示未知或错误
            final_is_low_balance = True

    # 浏览器退出逻辑
    if not final_status or not enable_browser_log:
        # 退出浏览器实例
        if browser:
            try:
                # 确保在退出前关闭所有可能打开的标签页，特别是 final_tab
                if final_tab and not final_tab.closed:
                    # final_tab.close() # DrissionPage 可能不需要显式关闭
                    pass
                browser.quit(force=True, del_data=True)
                print("[Browser] Browser quit.")
            except Exception as quit_error:
                 print(f"[Warning] Error quitting browser: {quit_error}")
        # 关闭 IMAP 连接 (如果 email_server 实例有关闭方法)
        if hasattr(email_server, 'close') and callable(email_server.close):
            try:
                email_server.close()
                print("[IMAP] IMAP connection closed.")
            except Exception as imap_close_err:
                print(f"[Warning] Error closing IMAP connection: {imap_close_err}")

    # 输出最终结果信息
    if final_status and not hide_account_info:
        print(f"[Register] Final Outcome: Success")
        print(f"[Register] Cursor Email Used: {email_address}") # 显示实际使用的邮箱
        print(f"[Register] Cursor Token: {token}")
        print(f"[Register] Final Balance: {final_balance}")
    elif not final_status:
        print(f"[Register] Final Outcome: Failed for {email_address}")


    ret = {
        "username": email_address, # 返回实际使用的邮箱
        "token": token,
        "balance": final_balance, # 添加最终余额到返回结果
        "is_low_balance": final_is_low_balance # 添加最终低余额状态到返回结果
    }

    return ret

def register_cursor(reg_email):

    options = ChromiumOptions()
    options.auto_port()
    options.new_env()
    # Use turnstilePatch from https://github.com/TheFalloutOf76/CDP-bug-MouseEvent-.screenX-.screenY-patcher
    turnstile_patch_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "turnstilePatch"))
    # 检查扩展路径是否存在
    if os.path.isdir(turnstile_patch_path):
        options.add_extension(turnstile_patch_path)
    else:
        print(f"[Warning] Turnstile patch extension not found at: {turnstile_patch_path}")


    # If fail to pass the cloudflare in headless mode, try to align the user agent with your real browser
    if enable_headless:
        print("[Config] Headless mode enabled.")
        # 获取正确的 platformIdentifier
        platform_identifier = ""
        if sys.platform == "linux" or sys.platform == "linux2":
            platform_identifier = "X11; Linux x86_64"
        elif sys.platform == "darwin":
            platform_identifier = "Macintosh; Intel Mac OS X 10_15_7"
        elif sys.platform == "win32":
            platform_identifier = "Windows NT 10.0; Win64; x64"
        else:
             platform_identifier = "Unknown" # Default or handle other platforms

        # 请根据实际情况调整 Chrome 版本
        chrome_version = "120.0.0.0" # 示例版本
        user_agent = f"Mozilla/5.0 ({platform_identifier}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
        print(f"[Config] Setting User-Agent: {user_agent}")
        options.set_user_agent(user_agent)
        options.headless()
    else:
         print("[Config] Headless mode disabled.")

    # 直接打印要处理的邮箱
    print(f"[Register] Start process for account: {reg_email} with Action: {action_type}")

    # 直接调用核心注册函数 (移除旧参数)
    result = register_cursor_core(reg_email, options)
    # 修改：只在 result 非 None 且包含有效 token 时添加到 results
    results = [result] if result and result.get("token") else []

    if len(results) > 0:
        formatted_date = datetime.now().strftime("%Y-%m-%d")
        token_csv_data = []
        for row in results: # 结果只有一个，但保持循环结构
            # 直接从结果中获取所有需要的信息
            # 确保 balance 和 is_low_balance 转换为字符串
            token_csv_data.append({
                'token': row.get('token'),
                'email': row.get('username'),
                'balance': str(row.get('balance', 0)),
                'is_low_balance': str(row.get('is_low_balance', False))
            })

        # 写入包含额度状态的token文件
        token_file_path = f"./token_{formatted_date}.csv"
        # 检查文件是否已存在，不存在则先写入表头
        file_exists = os.path.exists(token_file_path)
        write_header = not file_exists

        try:
            with open(token_file_path, 'a', newline='', encoding='utf-8') as file: # 添加 encoding='utf-8'
                fieldnames = ['token', 'email', 'balance', 'is_low_balance']
                writer = csv.DictWriter(file, fieldnames=fieldnames)

                if write_header:
                    writer.writeheader() # 写入表头行

                writer.writerows(token_csv_data)
            print(f"[Register] Successfully wrote token to {token_file_path}")
        except IOError as e:
             print(f"[Error] Failed to write token to CSV file {token_file_path}: {e}")

    # 如果没有成功的结果，也返回空列表
    # else:
    #     print(f"[Register] No successful result for {reg_email}")

    return results

def main():
    # 检查必要的环境变量是否已设置
    if not registration_email:
        print("[Error] Missing required environment variable: REGISTRATION_EMAIL")
        sys.exit(1)
    if not action_type:
        print("[Error] Missing required environment variable: ACTION_TYPE")
        sys.exit(1)
    if not all([receiving_imap_server, receiving_imap_port, receiving_username, receiving_password]):
        print("[Error] Missing required environment variables for receiving email config (IMAP)")
        sys.exit(1)

    # 调用修改后的 register_cursor 函数
    account_infos = register_cursor(registration_email) # 只需传递邮箱

    # 过滤掉 None 或没有 token 的结果
    valid_accounts = [row for row in account_infos if row and row.get('token')]
    tokens = [row['token'] for row in valid_accounts]

    print(f"[Register] Process finished. Successfully obtained {len(tokens)} token(s).")

    # 保留 OneAPI 上传逻辑，检查环境变量 ingest_to_oneapi
    if ingest_to_oneapi and len(tokens) > 0:
        # 检查 OneAPI 配置
        if not oneapi_url or not oneapi_token:
            print("[Warning] Ingest to OneAPI is enabled, but CURSOR_ONEAPI_URL or CURSOR_ONEAPI_TOKEN is missing.")
        else:
            print("[OneAPI] Starting to upload tokens to OneAPI...")
            try:
                from tokenManager.oneapi_manager import OneAPIManager

                oneapi = OneAPIManager(oneapi_url, oneapi_token)
                batch_size = min(10, len(tokens)) # 限制每次上传数量
                for i in range(0, len(tokens), batch_size):
                    batch_tokens = tokens[i:i+batch_size]
                    # 确保 oneapi_channel_url 有值，或者提供默认值
                    channel_url = oneapi_channel_url if oneapi_channel_url else "http://localhost:3000" # 提供一个默认值
                    oneapi.batch_add_channel(batch_tokens, channel_url)
                print("[OneAPI] Finished uploading tokens.")
            except ImportError:
                 print("[Error] Failed to import OneAPIManager. Make sure tokenManager is installed or accessible.")
            except Exception as oneapi_err:
                 print(f"[Error] Failed to upload tokens to OneAPI: {oneapi_err}")

if __name__ == "__main__":
    main()
