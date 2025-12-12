import requests
import json
import time
import base64
import hashlib
import random
import string
import os
from datetime import datetime, timedelta, timezone
from eth_account.messages import encode_defunct
from web3 import Web3

class DiscordBot:
    def __init__(self):
        self.token_file = 'token.txt'
        self.channel_id = '1099038274544218234'
        self.message = 'gmicrochains'

    def load_discord_token(self):
        try:
            with open(self.token_file, 'r') as f:
                tokens = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return tokens[0] if tokens else None
        except FileNotFoundError:
            print(f"File {self.token_file} not found!")
            return None

    def send_discord_message(self, message=None):
        token = self.load_discord_token()
        if not token:
            print("No Discord token found!")
            return False

        if not message:
            message = self.message

        url = f"https://discord.com/api/v9/channels/{self.channel_id}/messages"
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }
        payload = {'content': message}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            if response.status_code in [200, 201]:
                print(f"Discord message sent: {message}")
                return True
            else:
                print(f"Failed to send Discord message: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"Error sending Discord message: {e}")
            return False

class LineraMultiAccountBot:
    def __init__(self):
        self.config = {
            'environment_id': '0f2cf892-98a5-43cb-8ebb-3881229a0610',
            'base_dynamic_auth_url': 'https://app.dynamicauth.com/api/v0/sdk',
            'base_linera_url': 'https://linera-api.pulsar.money/api/v1/pulsar',
            'chain': 'EVM',
            'provider': 'browserExtension',
            'task_guid': 'a2c52b5f-e0be-4336-8ba3-85ddf277d3d1'
        }

        self.session = requests.Session()
        self.token_file = 'tokens.json'
        self.accounts_file = 'akun.txt'
        self.discord_bot = DiscordBot()

    def load_accounts(self):
        accounts = []
        try:
            with open(self.accounts_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split('|')
                    if len(parts) >= 2:
                        private_key = parts[0].strip()
                        wallet_address = parts[1].strip()
                        wallet_name = parts[2].strip() if len(parts) > 2 else 'rabby'

                        if not private_key.startswith('0x'):
                            private_key = '0x' + private_key

                        if len(private_key) == 66:
                            accounts.append({
                                'private_key': private_key,
                                'wallet_address': wallet_address,
                                'wallet_name': wallet_name,
                                'line_number': line_num
                            })
                        else:
                            print(f"Invalid private key format on line {line_num}")
                    else:
                        print(f"Invalid format on line {line_num}: {line}")

            print(f"Loaded {len(accounts)} accounts from {self.accounts_file}")
            return accounts

        except FileNotFoundError:
            print(f"File {self.accounts_file} not found!")
            print(f"Please create {self.accounts_file} with format: private_key|wallet_address|wallet_name")
            return []
        except Exception as e:
            print(f"Error loading accounts: {e}")
            return []

    def generate_device_fingerprint(self):
        characters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(characters) for _ in range(32))

    def get_base_headers(self, device_fingerprint, session_public_key):
        return {
            'authority': 'app.dynamicauth.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://portal.linera.net',
            'referer': 'https://portal.linera.net/',
            'sec-ch-ua': '"Chromium";v="142", "Brave";v="142", "Not=A?Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'x-dyn-api-version': 'API/0.0.762',
            'x-dyn-version': 'WalletKit/4.30.1',
            'x-dyn-device-fingerprint': device_fingerprint,
            'x-dyn-is-global-wallet-popup': 'false',
            'x-dyn-session-public-key': session_public_key
        }

    def get_linera_headers(self, dynamic_token):
        return {
            'authority': 'linera-api.pulsar.money',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://portal.linera.net',
            'referer': 'https://portal.linera.net/',
            'sec-ch-ua': '"Chromium";v="142", "Brave";v="142", "Not=A?Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'x-dynamic-token': dynamic_token
        }

    def load_tokens(self):
        try:
            with open(self.token_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except Exception as e:
            print(f"Error loading tokens: {e}")
            return {}

    def save_tokens(self, tokens):
        try:
            with open(self.token_file, 'w') as f:
                json.dump(tokens, f, indent=2)
        except Exception as e:
            print(f"Error saving tokens: {e}")

    def get_valid_token(self, wallet_address):
        tokens = self.load_tokens()
        w3 = Web3()
        try:
            checksum_address = w3.to_checksum_address(wallet_address)
        except:
            checksum_address = wallet_address

        for addr in [wallet_address, checksum_address, wallet_address.lower()]:
            if addr in tokens:
                token_data = tokens[addr]
                expires_at = token_data.get('expires_at')
                if not expires_at:
                    continue
                expiry_time = datetime.fromtimestamp(expires_at)
                if datetime.now() < expiry_time - timedelta(hours=1):
                    return token_data['jwt']
                else:
                    print(f"Token expired or about to expire")

        return None

    def decode_token(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded_bytes = base64.urlsafe_b64decode(payload)
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            print(f"Error decoding token: {e}")
            return None

    def sign_message_with_private_key(self, private_key, message):
        try:
            w3 = Web3()
            account = w3.eth.account.from_key(private_key)
            message_encoded = encode_defunct(text=message)
            signed_message = account.sign_message(message_encoded)
            signature = signed_message.signature.hex()
            if not signature.startswith('0x'):
                signature = '0x' + signature
            return signature
        except Exception as e:
            print(f"Error signing message: {e}")
            return None

    def get_nonce(self, device_fingerprint, session_public_key):
        url = f"{self.config['base_dynamic_auth_url']}/{self.config['environment_id']}/nonce"
        headers = self.get_base_headers(device_fingerprint, session_public_key)
        try:
            print(f"Step 1: Getting nonce...")
            response = self.session.get(url, headers=headers)
            print(f"Nonce request: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                nonce = data.get('nonce')
                print(f"Nonce received: {nonce}")
                return nonce
            else:
                print(f"Failed to get nonce: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error getting nonce: {e}")
            return None

    def connect_wallet(self, wallet_address, wallet_name, device_fingerprint, session_public_key):
        url = f"{self.config['base_dynamic_auth_url']}/{self.config['environment_id']}/connect"
        payload = {
            "address": wallet_address,
            "chain": self.config['chain'],
            "provider": self.config['provider'],
            "walletName": wallet_name,
            "authMode": "connect-and-sign"
        }
        headers = self.get_base_headers(device_fingerprint, session_public_key)
        try:
            print(f"Step 2: Connecting wallet...")
            response = self.session.post(url, json=payload, headers=headers)
            print(f"Connect request: {response.status_code}")
            if response.status_code == 202:
                print(f"Wallet connection initiated")
                return True
            else:
                print(f"Failed to connect wallet: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"Error connecting wallet: {e}")
            return False

    def get_message_to_sign(self, nonce, wallet_address):
        w3 = Web3()
        try:
            checksum_address = w3.to_checksum_address(wallet_address)
        except:
            checksum_address = wallet_address
        issued_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        message = (
            f"portal.linera.net wants you to sign in with your Ethereum account:\n"
            f"{checksum_address}\n"
            f"\n"
            f"Welcome to Linera. Signing is the only way we can truly know that you are the owner of the wallet you are connecting. Signing is a safe, gas-less transaction that does not in any way give Linera permission to perform any transactions with your wallet.\n"
            f"\n"
            f"URI: https://portal.linera.net/quests\n"
            f"Version: 1\n"
            f"Chain ID: 1\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at}\n"
            f"Request ID: {self.config['environment_id']}"
        )
        return message

    def verify_signature(self, wallet_address, wallet_name, message_to_sign, signed_message, device_fingerprint, session_public_key):
        url = f"{self.config['base_dynamic_auth_url']}/{self.config['environment_id']}/verify"
        w3 = Web3()
        try:
            checksum_address = w3.to_checksum_address(wallet_address)
        except:
            checksum_address = wallet_address
        payload = {
            "publicWalletAddress": checksum_address,
            "chain": self.config['chain'],
            "walletProvider": self.config['provider'],
            "walletName": wallet_name,
            "messageToSign": message_to_sign,
            "signedMessage": signed_message,
            "sessionPublicKey": session_public_key,
            "additionalWalletAddresses": [],
            "network": "1"
        }
        headers = self.get_base_headers(device_fingerprint, session_public_key)
        try:
            print(f"Step 4: Verifying signature...")
            response = self.session.post(url, json=payload, headers=headers)
            print(f"Verify request: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"Signature verified successfully!")
                return {
                    'jwt': data.get('jwt'),
                    'minified_jwt': data.get('minifiedJwt'),
                    'expires_at': data.get('expiresAt'),
                    'user': data.get('user', {})
                }
            else:
                print(f"Failed to verify signature: {response.status_code}")
                print(f"Response: {response.text}")
                return None
        except Exception as e:
            print(f"Error verifying signature: {e}")
            return None

    def auto_login(self, account):
        private_key = account['private_key']
        wallet_address = account['wallet_address']
        wallet_name = account['wallet_name']
        print(f"Logging in for {wallet_address}...")
        device_fingerprint = self.generate_device_fingerprint()
        session_public_key = "0203cce4da79fca90bebb01d6776d677228e7fadfd60b4de1e01fd71d57d7cb31d"
        time.sleep(1)
        nonce = self.get_nonce(device_fingerprint, session_public_key)
        if not nonce:
            return None
        time.sleep(1)
        if not self.connect_wallet(wallet_address, wallet_name, device_fingerprint, session_public_key):
            return None
        print(f"Step 3: Signing message...")
        message_to_sign = self.get_message_to_sign(nonce, wallet_address)
        print(f"   Message length: {len(message_to_sign)} chars")
        signed_message = self.sign_message_with_private_key(private_key, message_to_sign)
        if not signed_message:
            return None
        w3 = Web3()
        try:
            account_obj = w3.eth.account.from_key(private_key)
            signer_address = account_obj.address
            print(f"Message signed successfully")
            print(f"   Signer: {signer_address}")
            print(f"   Signature: {signed_message[:20]}...")
        except:
            pass
        time.sleep(1)
        token_data = self.verify_signature(
            wallet_address,
            wallet_name,
            message_to_sign,
            signed_message,
            device_fingerprint,
            session_public_key
        )
        if token_data and token_data.get('jwt'):
            w3 = Web3()
            try:
                checksum_address = w3.to_checksum_address(wallet_address)
            except:
                checksum_address = wallet_address
            tokens = self.load_tokens()
            tokens[checksum_address] = {
                'jwt': token_data['jwt'],
                'expires_at': token_data['expires_at'],
                'last_updated': datetime.now().isoformat(),
                'username': token_data['user'].get('username', ''),
                'wallet_name': wallet_name
            }
            self.save_tokens(tokens)
            print(f"Login successful!")
            print(f"Username: {token_data['user'].get('username', 'N/A')}")
            return token_data['jwt']
        else:
            print(f"Login failed")
            return None

    def get_profile_complete(self, dynamic_token):
        try:
            url = f"{self.config['base_linera_url']}/social-pay/me"
            response = self.session.get(url, headers=self.get_linera_headers(dynamic_token))
            if response.status_code == 200:
                profile = response.json()
                print(f"COMPLETE PROFILE INFO:")
                print(f"   Wallet Address: {profile.get('walletAddress', 'N/A')}")
                print(f"   Created At: {profile.get('createdAt', 'N/A')}")
                print(f"   New User: {profile.get('newUser', 'N/A')}")
                twitter = profile.get('twitterMetadata')
                if twitter:
                    print(f"   Twitter:")
                    print(f"      Name: {twitter.get('name', 'N/A')}")
                    print(f"      Username: @{twitter.get('username', 'N/A')}")
                    print(f"      Followers: {twitter.get('followerCount', 'N/A')}")
                    print(f"      Following: {twitter.get('followedCount', 'N/A')}")
                    print(f"      Bio: {twitter.get('bio', 'N/A')}")
                discord = profile.get('discordMetadata')
                if discord:
                    print(f"   Discord:")
                    print(f"      Username: {discord.get('username', 'N/A')}")
                    print(f"      Global Name: {discord.get('globalName', 'N/A')}")
                    print(f"      Email: {discord.get('email', 'N/A')}")
                    print(f"      Verified: {discord.get('verified', 'N/A')}")
                return profile
            else:
                print(f"Failed to get complete profile: {response.status_code}")
                if response.status_code == 401:
                    print("Token mungkin expired, perlu login ulang")
                return None
        except Exception as e:
            print(f"Error getting complete profile: {e}")
            return None

    def get_challenges_profile(self, dynamic_token):
        try:
            url = f"{self.config['base_linera_url']}/challenges/profile"
            response = self.session.get(url, headers=self.get_linera_headers(dynamic_token))
            if response.status_code == 200:
                profile = response.json()
                username = profile.get('username', 'N/A')
                points = profile.get('points', 0)
                tasks_completed = profile.get('tasksCompleted', 0)
                print(f"CHALLENGES PROFILE:")
                print(f"   Username: {username}")
                print(f"   Points: {points}")
                print(f"   Tasks Completed: {tasks_completed}")
                return profile
            else:
                print(f"Failed to get challenges profile: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error getting challenges profile: {e}")
            return None

    def check_daily_status(self, dynamic_token, wallet_address):
        complete_profile = self.get_profile_complete(dynamic_token)
        challenges_profile = self.get_challenges_profile(dynamic_token)
        if not challenges_profile:
            return None
        tasks = challenges_profile.get('tasks', [])
        for task in tasks:
            if task.get('guid') == self.config['task_guid']:
                completed_today = task.get('completedToday', False)
                if completed_today:
                    print(f"Sudah check-in hari ini!")
                    return True
                else:
                    print(f"Belum check-in hari ini")
                    return False
        print(f"Daily task not found in profile")
        return None

    def do_checkin(self, dynamic_token, wallet_address):
        payload = {
            "taskGuid": self.config['task_guid'],
            "extraArguments": [
                '{"currentStreak":0,"isStreakInDanger":false,"hasCheckedInToday":false}'
            ]
        }
        try:
            url = f"{self.config['base_linera_url']}/challenges/do-task"
            response = self.session.post(
                url,
                headers=self.get_linera_headers(dynamic_token),
                json=payload
            )
            if response.status_code == 201:
                result = response.json()
                points = result.get('points', 0)
                print(f"Check-in Berhasil! +{points} points")
                return True
            elif response.status_code == 400:
                error_msg = response.json().get('message', 'Unknown error')
                if "already" in error_msg.lower() or "completed" in error_msg.lower():
                    print(f"Sudah klaim hari ini")
                    return True
                else:
                    print(f"Check-in failed: {error_msg}")
                    return False
            else:
                print(f"Check-in failed - Status {response.status_code}")
                return False
        except Exception as e:
            print(f"Error during check-in: {e}")
            return False

    def process_account(self, account):
        wallet_address = account['wallet_address']
        wallet_name = account['wallet_name']
        print(f"\n{'='*60}")
        print(f"Processing: {wallet_address} ({wallet_name})")
        print(f"{'='*60}")
        dynamic_token = self.get_valid_token(wallet_address)
        if not dynamic_token:
            print(f"No valid token found, performing auto login...")
            dynamic_token = self.auto_login(account)
        if not dynamic_token:
            print(f"Failed to get valid token")
            return False
        token_info = self.decode_token(dynamic_token)
        if token_info:
            exp_time = datetime.fromtimestamp(token_info.get('exp', 0))
            time_remaining = exp_time - datetime.now()
            hours_remaining = time_remaining.total_seconds() / 3600
            print(f"Token valid for: {hours_remaining:.1f} hours")
        already_checked = self.check_daily_status(dynamic_token, wallet_address)
        if already_checked:
            return True
        elif already_checked is None:
            print(f"Could not verify check-in status")
        print(f"Attempting check-in...")
        time.sleep(2)
        success = self.do_checkin(dynamic_token, wallet_address)
        if success:
            print(f"Check-in completed!")
            return True
        else:
            print(f"Check-in failed!")
            return False

    def countdown_timer(self, seconds):
        print(f"\nNext run in: {seconds} seconds")
        for i in range(seconds, 0, -1):
            hours = i // 3600
            minutes = (i % 3600) // 60
            secs = i % 60
            print(f"\rNext run in: {hours:02d}:{minutes:02d}:{secs:02d}", end="", flush=True)
            time.sleep(1)
        print("\rStarting next run...                          ")

    def run_daily_loop(self):
        print("Linera Auto Login & Check-in Bot with Discord")
        print("Discord notifications enabled")
        print("24-hour loop with countdown")
        print("=" * 60)
        while True:
            try:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"\nStarting daily cycle - {current_time}")
                print("=" * 60)
                print("Sending Discord notification...")
                discord_success = self.discord_bot.send_discord_message()
                if discord_success:
                    print("Discord notification sent successfully")
                else:
                    print("Failed to send Discord notification")
                time.sleep(2)
                accounts = self.load_accounts()
                if not accounts:
                    print("No accounts to process")
                    continue
                print(f"Found {len(accounts)} account(s) to process")
                successful_accounts = 0
                total_accounts = len(accounts)
                for i, account in enumerate(accounts, 1):
                    print(f"\nProcessing account {i}/{total_accounts}")
                    try:
                        if self.process_account(account):
                            successful_accounts += 1
                    except Exception as e:
                        print(f"Unexpected error: {e}")
                        import traceback
                        traceback.print_exc()
                    if i < total_accounts:
                        delay = random.randint(5, 10)
                        print(f"Waiting {delay} seconds before next account...")
                        time.sleep(delay)
                print(f"\n{'='*60}")
                print(f"CYCLE SUMMARY: {successful_accounts}/{total_accounts} accounts successful")
                print(f"{'='*60}")
                next_cycle_seconds = 24 * 3600 + 120
                print(f"\nCycle completed. Next run in 24 hours + 2 minutes...")
                self.countdown_timer(next_cycle_seconds)
            except KeyboardInterrupt:
                print("\nBot stopped by user")
                break
            except Exception as e:
                print(f"Unexpected error in main loop: {e}")
                import traceback
                traceback.print_exc()
                print("Retrying in 5 minutes...")
                self.countdown_timer(300)

def main():
    bot = LineraMultiAccountBot()
    bot.run_daily_loop()

if __name__ == '__main__':
    main()
