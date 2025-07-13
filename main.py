import requests
import time
import json
import logging
from datetime import datetime
from typing import Set, Dict, List

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vrchat_auto_block.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VRChatAutoBlock:
    def __init__(self, username: str, password: str):
        """
        初始化VRChat自动拉黑器
        
        Args:
            username: VRChat用户名
            password: VRChat密码
        """
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VRGuardian/1.0 (VRChat Auto-Block Guardian)'
        })
        
        self.base_url = "https://api.vrchat.cloud/api/1"
        self.auth_cookie = None
        self.current_user_id = None
        
        # 存储当前好友列表
        self.friends_cache: Set[str] = set()
        self.friends_data: Dict[str, Dict] = {}
        
        # 配置
        self.poll_interval = 60  # 轮询间隔（秒）
        self.max_retries = 3     # 最大重试次数
        
        # 会话持久化文件
        self.session_file = 'session.json'
        
    def authenticate(self) -> bool:
        """
        进行VRChat API认证，支持2FA和会话复用
        
        Returns:
            bool: 认证是否成功
        """
        try:
            logger.info("开始VRChat API认证...")
            
            # 首先尝试加载保存的会话
            if self.load_session():
                logger.info("使用保存的会话，跳过认证步骤")
                return True
            
            logger.info("开始新的认证流程...")
            
            # 获取配置信息
            config_response = self.session.get(f"{self.base_url}/config")
            if config_response.status_code != 200:
                logger.error("获取配置失败")
                return False
            
            # 进行初始认证
            auth_response = self.session.get(
                f"{self.base_url}/auth/user",
                auth=(self.username, self.password)
            )
            
            if auth_response.status_code == 200:
                user_data = auth_response.json()
                
                # 检查是否需要2FA验证
                if user_data.get('requiresTwoFactorAuth', []):
                    logger.info("检测到需要两步验证")
                    
                    # 获取2FA类型
                    auth_types = user_data.get('requiresTwoFactorAuth', [])
                    logger.info(f"支持的2FA类型: {auth_types}")
                    
                    if 'totp' in auth_types:
                        # TOTP验证（Google Authenticator等）
                        if not self._handle_totp_verification():
                            return False
                    elif 'emailOtp' in auth_types:
                        # 邮箱OTP验证
                        if not self._handle_email_otp_verification():
                            return False
                    else:
                        logger.error(f"不支持的2FA类型: {auth_types}")
                        return False
                
                # 重新获取用户信息
                final_response = self.session.get(
                    f"{self.base_url}/auth/user",
                    auth=(self.username, self.password)
                )
                
                if final_response.status_code == 200:
                    final_user_data = final_response.json()
                    self.current_user_id = final_user_data.get('id')
                    logger.info(f"认证成功！当前用户ID: {self.current_user_id}")
                    
                    # 保存认证会话
                    self.save_session()
                    
                    return True
                else:
                    logger.error("最终认证失败")
                    return False
                    
            else:
                logger.error(f"认证失败，状态码: {auth_response.status_code}")
                logger.error(f"响应内容: {auth_response.text}")
                return False
                
        except Exception as e:
            logger.error(f"认证过程中发生错误: {e}")
            return False
    
    def _handle_totp_verification(self) -> bool:
        """
        处理TOTP两步验证
        
        Returns:
            bool: 验证是否成功
        """
        try:
            # 提示用户输入TOTP代码
            print("\n需要进行两步验证(TOTP)")
            totp_code = input("请输入验证器应用中的6位数字验证码: ").strip()
            
            if not totp_code or len(totp_code) != 6 or not totp_code.isdigit():
                logger.error("TOTP验证码格式不正确")
                return False
            
            # 发送TOTP验证请求
            totp_response = self.session.post(
                f"{self.base_url}/auth/twofactorauth/totp/verify",
                json={'code': totp_code},
                auth=(self.username, self.password)
            )
            
            if totp_response.status_code == 200:
                logger.info("TOTP验证成功")
                return True
            else:
                logger.error(f"TOTP验证失败，状态码: {totp_response.status_code}")
                logger.error(f"响应内容: {totp_response.text}")
                return False
                
        except Exception as e:
            logger.error(f"TOTP验证过程中发生错误: {e}")
            return False
    
    def _handle_email_otp_verification(self) -> bool:
        """
        处理邮箱OTP两步验证
        
        Returns:
            bool: 验证是否成功
        """
        try:
            # 发送邮箱OTP请求
            print("\n需要进行邮箱两步验证")
            email_response = self.session.post(
                f"{self.base_url}/auth/twofactorauth/emailotp/send",
                auth=(self.username, self.password)
            )
            
            if email_response.status_code != 200:
                logger.error(f"发送邮箱验证码失败，状态码: {email_response.status_code}")
                return False
            
            logger.info("邮箱验证码已发送，请检查你的邮箱")
            
            # 提示用户输入邮箱验证码
            email_code = input("请输入邮箱中收到的验证码: ").strip()
            
            if not email_code:
                logger.error("邮箱验证码不能为空")
                return False
            
            # 验证邮箱OTP
            verify_response = self.session.post(
                f"{self.base_url}/auth/twofactorauth/emailotp/verify",
                json={'code': email_code},
                auth=(self.username, self.password)
            )
            
            if verify_response.status_code == 200:
                logger.info("邮箱OTP验证成功")
                return True
            else:
                logger.error(f"邮箱OTP验证失败，状态码: {verify_response.status_code}")
                logger.error(f"响应内容: {verify_response.text}")
                return False
                
        except Exception as e:
            logger.error(f"邮箱OTP验证过程中发生错误: {e}")
            return False
    
    def get_friends_list(self) -> List[Dict]:
        """
        获取当前好友列表（支持分页获取所有好友）
        
        Returns:
            List[Dict]: 好友信息列表
        """
        try:
            all_friends = []
            offset = 0
            n = 100  # 每次请求的数量
            max_attempts = 10  # 最大尝试次数，防止无限循环
            attempt = 0
            
            logger.info("开始获取好友列表...")
            
            while attempt < max_attempts:
                logger.debug(f"请求好友列表: offset={offset}, n={n}")
                
                friends_response = self.make_authenticated_request(
                    'GET', 
                    f"{self.base_url}/auth/user/friends?n={n}&offset={offset}&offline=true"
                )
                
                if friends_response.status_code == 200:
                    friends_batch = friends_response.json()
                    logger.debug(f"本次获取到 {len(friends_batch)} 个好友")
                    
                    if not friends_batch:  # 如果返回空列表，说明已经获取完所有好友
                        logger.info("返回空列表，已获取完所有好友")
                        break
                    
                    all_friends.extend(friends_batch)
                    logger.info(f"累计获取 {len(all_friends)} 个好友...")
                    
                    # 如果返回的好友数量少于请求的数量，说明已经是最后一批
                    if len(friends_batch) < n:
                        logger.info(f"本次获取数量({len(friends_batch)})少于请求数量({n})，已是最后一批")
                        break
                    
                    offset += n
                    attempt += 1
                    time.sleep(1)  # 添加延迟避免请求过快
                    
                else:
                    logger.error(f"获取好友列表失败，状态码: {friends_response.status_code}")
                    if hasattr(friends_response, 'text'):
                        logger.error(f"响应内容: {friends_response.text}")
                    break
            
            if attempt >= max_attempts:
                logger.warning(f"达到最大尝试次数 {max_attempts}，可能还有更多好友未获取")
            
            logger.info(f"总共获取到 {len(all_friends)} 个好友（共尝试 {attempt + 1} 次请求）")
            
            # 验证列表完整性
            if not self.verify_friends_list_integrity(all_friends):
                logger.warning("好友列表可能不完整，建议稍后重试")
            
            return all_friends
                
        except Exception as e:
            logger.error(f"获取好友列表时发生错误: {e}")
            return []
    
    def block_user(self, user_id: str, display_name: str = "Unknown") -> bool:
        """
        拉黑指定用户
        
        Args:
            user_id: 用户ID
            display_name: 用户显示名称
            
        Returns:
            bool: 拉黑是否成功
        """
        try:
            logger.info(f"正在拉黑用户: {display_name} (ID: {user_id})")
            
            # 修正API端点 - 需要包含用户ID
            block_response = self.make_authenticated_request(
                'PUT',
                f"{self.base_url}/auth/user/blocked/{user_id}"
            )
            
            if block_response.status_code == 200:
                logger.info(f"成功拉黑用户: {display_name}")
                return True
            else:
                logger.error(f"拉黑用户失败，状态码: {block_response.status_code}")
                if hasattr(block_response, 'text'):
                    logger.error(f"响应内容: {block_response.text}")
                return False
                
        except Exception as e:
            logger.error(f"拉黑用户时发生错误: {e}")
            return False
    
    def update_friends_cache(self):
        """
        更新好友缓存
        """
        friends_list = self.get_friends_list()
        if not friends_list:
            logger.warning("无法获取好友列表，跳过此次更新")
            return
        
        # 验证好友列表完整性
        if not self.verify_friends_list_integrity(friends_list):
            logger.warning("好友列表不完整，跳过此次删除检测")
            return
        
        new_friends: Set[str] = set()
        new_friends_data: Dict[str, Dict] = {}
        
        logger.info(f"处理 {len(friends_list)} 个好友数据...")
        
        for friend in friends_list:
            user_id = friend.get('id')
            if user_id:
                new_friends.add(user_id)
                new_friends_data[user_id] = {
                    'displayName': friend.get('displayName', 'Unknown'),
                    'bio': friend.get('bio', ''),
                    'status': friend.get('status', 'unknown'),
                    'statusDescription': friend.get('statusDescription', ''),
                    'location': friend.get('location', 'unknown'),
                    'last_activity': friend.get('last_activity', ''),
                    'last_login': friend.get('last_login', ''),
                    'last_platform': friend.get('last_platform', ''),
                    'currentAvatarImageUrl': friend.get('currentAvatarImageUrl', ''),
                    'profilePicOverride': friend.get('profilePicOverride', ''),
                    'tags': friend.get('tags', []),
                    'cached_at': datetime.now().isoformat()
                }
        
        logger.info(f"新好友列表包含 {len(new_friends)} 个用户")
        logger.info(f"缓存中之前有 {len(self.friends_cache)} 个用户")
        
        # 检测被删除的好友 - 只有在缓存不为空时才检测
        if self.friends_cache:  # 防止首次运行时误报
            removed_friends = self.friends_cache - new_friends
            
            if removed_friends:
                logger.warning(f"检测到 {len(removed_friends)} 个用户可能删除了你")
                
                # 使用 isFriend API 进行二次验证
                logger.info("使用 isFriend API 进行二次验证...")
                confirmed_removed = set()
                
                for user_id in removed_friends:
                    # 等待一小段时间避免请求过快
                    time.sleep(1)
                    
                    # 检查用户是否仍然是好友
                    if not self.check_is_friend(user_id):
                        confirmed_removed.add(user_id)
                        logger.debug(f"确认用户 {user_id} 已不是好友")
                    else:
                        logger.debug(f"用户 {user_id} 仍然是好友，可能是API临时问题")
                
                if confirmed_removed:
                    logger.error(f"二次验证确认：{len(confirmed_removed)} 个用户确实删除了你")
                    
                    for removed_user_id in confirmed_removed:
                        removed_user_data = self.friends_data.get(removed_user_id, {})
                        display_name = removed_user_data.get('displayName', 'Unknown')
                        
                        logger.warning(f"用户 {display_name} (ID: {removed_user_id}) 删除了你")
                        
                        # 自动拉黑
                        success = self.block_user(removed_user_id, display_name)
                        if success:
                            logger.info(f"已自动拉黑用户: {display_name}")
                        else:
                            logger.error(f"自动拉黑失败: {display_name}")
                else:
                    logger.info("二次验证：所有用户仍是好友，可能是好友列表获取的临时问题")
            else:
                logger.info("没有检测到好友删除")
        else:
            logger.info("首次运行，建立好友缓存")
        
        # 检测新增好友
        if self.friends_cache:
            new_added_friends = new_friends - self.friends_cache
            if new_added_friends:
                logger.info(f"检测到 {len(new_added_friends)} 个新好友")
                for new_friend_id in new_added_friends:
                    friend_data = new_friends_data.get(new_friend_id, {})
                    display_name = friend_data.get('displayName', 'Unknown')
                    logger.info(f"新好友: {display_name}")
        
        # 更新缓存
        self.friends_cache = new_friends
        self.friends_data = new_friends_data
        
        logger.info(f"好友列表已更新，当前好友数量: {len(new_friends)}")
    
    def save_cache_to_file(self):
        """
        将缓存保存到文件
        """
        try:
            cache_data = {
                'friends_cache': list(self.friends_cache),
                'friends_data': self.friends_data,
                'last_update': datetime.now().isoformat()
            }
            
            with open('friends_cache.json', 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            logger.error(f"保存缓存文件失败: {e}")
    
    def load_cache_from_file(self):
        """
        从文件加载缓存
        """
        try:
            with open('friends_cache.json', 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
                
            self.friends_cache = set(cache_data.get('friends_cache', []))
            self.friends_data = cache_data.get('friends_data', {})
            
            last_update = cache_data.get('last_update')
            if last_update:
                logger.info(f"从缓存文件加载好友数据，上次更新时间: {last_update}")
                logger.info(f"缓存中好友数量: {len(self.friends_cache)}")
            
        except FileNotFoundError:
            logger.info("缓存文件不存在，将创建新的缓存")
        except Exception as e:
            logger.error(f"加载缓存文件失败: {e}")
    
    @staticmethod
    def load_config_from_file(config_path: str = 'config.json') -> Dict:
        """
        从配置文件加载设置
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            Dict: 配置信息
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"成功加载配置文件: {config_path}")
                return config
        except FileNotFoundError:
            logger.info(f"配置文件 {config_path} 不存在")
            return {}
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return {}
    
    def check_auth_status(self) -> bool:
        """
        检查当前认证状态
        
        Returns:
            bool: 认证是否有效
        """
        try:
            response = self.session.get(
                f"{self.base_url}/auth/user"
            )
            
            if response.status_code == 200:
                user_data = response.json()
                # 检查是否需要2FA但没有验证
                if user_data.get('requiresTwoFactorAuth', []):
                    logger.debug("需要重新进行2FA验证")
                    return False
                # 更新用户ID
                self.current_user_id = user_data.get('id')
                return True
            else:
                logger.debug(f"认证状态检查失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            logger.debug(f"检查认证状态时发生错误: {e}")
            return False
    
    def make_authenticated_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        发送经过认证的请求，自动处理重新认证
        
        Args:
            method: HTTP方法
            url: 请求URL
            
        Returns:
            requests.Response: 响应对象
        """
        max_auth_retries = 2
        auth_retry_count = 0
        
        while auth_retry_count < max_auth_retries:
            try:
                # 发送请求
                response = self.session.request(method, url, **kwargs)
                
                # 如果403错误且还有重试次数，尝试重新认证
                if response.status_code == 403 and auth_retry_count < max_auth_retries - 1:
                    logger.warning(f"请求失败403，尝试重新认证 (第{auth_retry_count + 1}次)")

                    if self.authenticate():
                        auth_retry_count += 1
                        continue
                    else:
                        logger.error("重新认证失败")
                        break
                
                return response
                
            except Exception as e:
                logger.error(f"请求过程中发生错误: {e}")
                if auth_retry_count < max_auth_retries - 1:
                    auth_retry_count += 1
                    time.sleep(2)  # 等待2秒后重试
                    continue
                else:
                    # 返回一个模拟的错误响应
                    error_response = requests.Response()
                    error_response.status_code = 500
                    return error_response
        
        # 如果所有重试都失败了
        error_response = requests.Response()
        error_response.status_code = 500
        return error_response
    
    def run(self):
        """
        运行自动拉黑器
        """
        logger.info("VRGuardian 自动拉黑器启动")
        
        # 认证
        if not self.authenticate():
            logger.error("认证失败，运行诊断...")
            self.diagnose_auth_issues()
            logger.error("程序退出")
            return
        
        # 加载缓存
        self.load_cache_from_file()
        
        # 首次更新好友列表
        logger.info("进行首次好友列表更新...")
        self.update_friends_cache()
        self.save_cache_to_file()
        
        logger.info(f"开始监控循环，轮询间隔: {self.poll_interval}秒")
        
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        try:
            while True:
                time.sleep(self.poll_interval)
                
                logger.info("正在检查好友列表变化...")
                
                # 检查好友列表
                friends_list = self.get_friends_list()
                if friends_list is not None and len(friends_list) >= 0:
                    # 成功获取好友列表，重置失败计数
                    consecutive_failures = 0
                    
                    # 更新缓存
                    self.update_friends_cache()
                    self.save_cache_to_file()
                else:
                    # 获取好友列表失败
                    consecutive_failures += 1
                    logger.warning(f"连续失败次数: {consecutive_failures}/{max_consecutive_failures}")
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error("连续失败次数过多，运行诊断...")
                        self.diagnose_auth_issues()
                        
                        # 尝试重新认证
                        logger.info("尝试重新认证...")
                        if self.authenticate():
                            logger.info("重新认证成功，继续监控")
                            consecutive_failures = 0
                        else:
                            logger.error("重新认证失败，程序退出")
                            break
                
        except KeyboardInterrupt:
            logger.info("接收到停止信号，正在退出...")
        except Exception as e:
            logger.error(f"运行过程中发生错误: {e}")
            logger.info("运行诊断...")
            self.diagnose_auth_issues()
        finally:
            logger.info("VRGuardian 自动拉黑器已停止")


    def save_session(self):
        """
        保存当前会话到文件
        """
        try:
            session_data = {
                'cookies': dict(self.session.cookies),
                'headers': dict(self.session.headers),
                'current_user_id': self.current_user_id,
                'username': self.username,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
                
            logger.info("会话已保存到文件")
                
        except Exception as e:
            logger.error(f"保存会话失败: {e}")
    
    def load_session(self) -> bool:
        """
        从文件加载会话
        
        Returns:
            bool: 是否成功加载并验证会话
        """
        try:
            with open(self.session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # 检查会话是否是同一用户的
            if session_data.get('username') != self.username:
                logger.info("会话文件用户名不匹配，需要重新认证")
                return False
            
            # 检查会话时间（可选：如果会话太旧就放弃）
            timestamp_str = session_data.get('timestamp')
            if timestamp_str:
                session_time = datetime.fromisoformat(timestamp_str)
                time_diff = datetime.now() - session_time
                # 如果会话超过7天就放弃（VRChat会话通常有效期较长）
                if time_diff.days > 7:
                    logger.info("会话文件过旧，需要重新认证")
                    return False
            
            # 恢复会话
            self.session.cookies.update(session_data.get('cookies', {}))
            self.session.headers.update(session_data.get('headers', {}))
            self.current_user_id = session_data.get('current_user_id')
            
            logger.info(f"从文件加载会话，时间: {timestamp_str}")
            
            # 验证会话是否仍然有效
            if self.check_auth_status():
                logger.info("会话验证成功，无需重新认证")
                return True
            else:
                logger.info("会话已失效，需要重新认证")
                return False
                
        except FileNotFoundError:
            logger.info("会话文件不存在，需要进行认证")
            return False
        except Exception as e:
            logger.error(f"加载会话失败: {e}")
            return False

    def clear_session(self):
        """
        清除保存的会话文件
        """
        try:
            import os
            if os.path.exists(self.session_file):
                os.remove(self.session_file)
                logger.info("已清除保存的会话文件")
        except Exception as e:
            logger.error(f"清除会话文件失败: {e}")

    def diagnose_auth_issues(self):
        """
        诊断认证问题
        """
        logger.info("=== 认证诊断开始 ===")
        
        try:
            # 检查网络连通性
            response = self.session.get(f"{self.base_url}/config", timeout=10)
            if response.status_code == 200:
                logger.info("✓ 网络连接正常")
            else:
                logger.error(f"✗ 网络连接异常，状态码: {response.status_code}")
        except Exception as e:
            logger.error(f"✗ 网络连接失败: {e}")
        
        # 检查用户凭据格式
        if not self.username or not self.password:
            logger.error("✗ 用户名或密码为空")
        else:
            logger.info("✓ 用户名和密码已设置")
        
        # 检查会话文件
        try:
            import os
            if os.path.exists(self.session_file):
                logger.info(f"✓ 发现会话文件: {self.session_file}")
                # 尝试清除可能损坏的会话文件
                self.clear_session()
                logger.info("已清除可能损坏的会话文件，下次启动将重新认证")
            else:
                logger.info("○ 没有保存的会话文件")
        except Exception as e:
            logger.error(f"✗ 检查会话文件失败: {e}")
        
        logger.info("=== 认证诊断结束 ===")

    def verify_friends_list_integrity(self, friends_list: List[Dict]) -> bool:
        """
        验证好友列表的完整性
        
        Args:
            friends_list: 好友列表
            
        Returns:
            bool: 列表是否完整
        """
        if not friends_list:
            return False
        
        # 检查列表中是否有无效的用户数据
        valid_friends = 0
        for friend in friends_list:
            if friend.get('id') and friend.get('displayName'):
                valid_friends += 1
        
        # 如果有效好友数量太少，可能是API返回不完整
        if len(friends_list) > 0 and valid_friends / len(friends_list) < 0.8:
            logger.warning(f"好友列表可能不完整，有效数据比例: {valid_friends}/{len(friends_list)}")
            return False
        
        return True

    def check_is_friend(self, user_id: str) -> bool:
        """
        检查指定用户是否仍然是好友
        
        Args:
            user_id: 用户ID
            
        Returns:
            bool: 是否仍为好友
        """
        try:
            user_response = self.make_authenticated_request(
                'GET',
                f"{self.base_url}/users/{user_id}"
            )
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                is_friend = user_data.get('isFriend', False)
                logger.debug(f"用户 {user_id} 好友状态: {is_friend}")
                return is_friend
            else:
                logger.warning(f"获取用户 {user_id} 信息失败，状态码: {user_response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"检查用户 {user_id} 好友状态时发生错误: {e}")
            return False

def main():
    
    try:
        # 检查是否使用配置文件
        config = VRChatAutoBlock.load_config_from_file()
        
        if config and config.get('username') and config.get('password'):
            print("检测到配置文件，使用配置文件中的设置")
            print(f"用户名: {config['username']}")
            username = config['username']
            password = config['password']
            poll_interval = config.get('poll_interval', 60)
            print(f"将使用配置的轮询间隔: {poll_interval}秒")
            
            # 询问是否清除保存的会话
            clear_session = input("是否清除保存的会话？(y/N): ").strip().lower()
            if clear_session in ['y', 'yes']:
                import os
                session_file = 'session.json'
                if os.path.exists(session_file):
                    os.remove(session_file)
                    print("已清除保存的会话，将重新进行认证")
                else:
                    print("没有找到保存的会话文件")
        else:
            print("📝 未检测到有效配置文件，请手动输入...")
            # 获取用户凭据
            username = input("请输入你的VRChat用户名: ").strip()
            password = input("请输入你的VRChat密码: ").strip()
            
            if not username or not password:
                print("用户名和密码不能为空！")
                return
            
            # 可选：设置轮询间隔
            try:
                interval_input = input("请输入轮询间隔（秒，默认60）: ").strip()
                poll_interval = int(interval_input) if interval_input else 60
            except ValueError:
                print("轮询间隔必须是数字，使用默认值")
                poll_interval = 60
        
        # 创建并运行自动拉黑
        auto_blocker = VRChatAutoBlock(username, password)
        auto_blocker.poll_interval = poll_interval
        print(f"轮询间隔设置为: {auto_blocker.poll_interval}秒")
        auto_blocker.run()
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except ImportError as e:
        print(f"导入模块失败: {e}")
        print("请确保已安装所需依赖：pip install requests")
    except Exception as e:
        print(f"程序启动失败: {e}")
        logger.error(f"主函数异常: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ 脚本执行失败: {e}")
        import traceback
        traceback.print_exc()
    print("📍 脚本执行完成")
